import copy
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from randgen import random_snapshot  # noqa: E402
from rulescope import checks, cli, diff, fgtconf, firmware, fleet, model, report, source, ui, usage  # noqa: E402
from rulescope.catalog import INTRODUCED_0_4  # noqa: E402
from rulescope.redact import redact  # noqa: E402
from rulescope.resolve import Resolver  # noqa: E402

SAMPLE = os.path.join(HERE, "sample.conf")


def load_sample():
    with open(SAMPLE, encoding="utf-8") as fh:
        return fh.read()


def by_check(result):
    out = {}
    for f in result["findings"]:
        out.setdefault(f["check"], set()).add(f["policyid"] if f["policyid"] is not None else f["object"])
    return out


def sev_of(result, check, target):
    for f in result["findings"]:
        if f["check"] == check and (f["policyid"] == target or f["object"] == target):
            return f["severity"]
    return None


class ParserTests(unittest.TestCase):
    def test_multiline_and_escapes(self):
        root = fgtconf.parse(load_sample())
        msg = root.subs["system replacemsg mail email-block"].get("buffer")
        self.assertIn('"dangerous"', msg)
        self.assertNotIn("\n", msg)  # line breaks inside values are flattened: config text is untrusted
        self.assertIn("10", root.sub("firewall policy").entries)

    def test_header(self):
        self.assertEqual(fgtconf.header_info(load_sample()), {"model": "FGT60F", "version": "v7.4.3", "build": "2573"})

    def test_multi_vdom(self):
        text = """config vdom
edit root
next
edit dmz
next
end
config global
config system global
    set hostname "MV"
end
config system interface
    edit "port1"
        set vdom "dmz"
        set role wan
        set allowaccess ping
    next
end
end
config vdom
edit dmz
config firewall policy
    edit 7
        set srcintf "port1"
        set dstintf "port2"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
    next
end
next
end
"""
        snap = model.from_config(text, vdom="dmz")
        self.assertTrue(snap["device"]["multi_vdom"])
        self.assertEqual(snap["device"]["hostname"], "MV")
        self.assertEqual([p["policyid"] for p in snap["policies"]], [7])
        with self.assertRaises(ValueError):
            model.from_config(text, vdom="nope")

    def test_new_sections(self):
        snap = model.from_config(load_sample())
        self.assertEqual(snap["vips"]["VIP_RDP"]["mappedport"], "3389")
        self.assertEqual(snap["sslvpn"]["source_interface"], ["wan1"])
        self.assertEqual(snap["ipsec_p1"]["branch-vpn"]["dhgrp"], ["2"])
        self.assertEqual(snap["ipsec_p1"]["branch-vpn"]["ike_version"], "1")
        self.assertEqual(snap["ipsec_p2"]["branch-p2"]["pfs"], "disable")
        self.assertEqual(snap["local_in"][0]["action"], "deny")
        self.assertEqual(snap["default_routes"], [{"device": "", "sdwan_zone": ["virtual-wan-link"], "sdwan": False}])
        self.assertLess(snap["schedules"]["onetime"]["promo-2024"]["end_epoch"], time.time())
        dumped = json.dumps(snap)
        for secret in ("ENC SH2", "PRIVATE KEY", "c2VjcmV0cHNr"):
            self.assertNotIn(secret, dumped)


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.snap = model.from_config(load_sample())
        self.r = Resolver(self.snap)

    def test_group_of_halves_equals_subnet(self):
        self.assertTrue(self.r.address("LAN_HALVES").covers(self.r.address("LAN_NET")))
        self.assertTrue(self.r.address("LAN_NET").covers(self.r.address("LAN_HALVES")))
        self.assertFalse(self.r.address("LAN_HALF_A").covers(self.r.address("LAN_NET")))

    def test_opaque_objects(self):
        self.assertTrue(self.r.address("all").covers(self.r.address("Update_Site")))
        self.assertFalse(self.r.address("LAN_NET").covers(self.r.address("Update_Site")))
        self.assertFalse(self.r.address("all").covers(self.r.address("VIP_WEB")))

    def test_services(self):
        s = self.r.services
        self.assertTrue(s(["WEB_RANGE"]).covers(s(["WEB_PORTS"])))
        self.assertFalse(s(["HTTPS"]).covers(s(["WEB_PORTS"])))
        self.assertTrue(s(["ALL_ICMP"]).covers(s(["PING"])))
        self.assertFalse(s(["PING"]).covers(s(["ALL_ICMP"])))
        self.assertTrue(s(["ALL"]).covers(s(["MYSQL", "PING"])))
        self.assertFalse(s(["MYSQL"]).covers(s(["ALL"])))
        self.assertTrue(s(["WEB_RANGE"]).allows_port("tcp", 443, 443))
        self.assertFalse(s(["WEB_RANGE"]).allows_port("udp", 443, 443))

    def test_source_port_restriction(self):
        self.snap["services"]["SRC_LIMITED"] = model._service("SRC_LIMITED", {"tcp-portrange": "443:1024-2000"})
        self.snap["services"]["SPLIT"] = model._service("SPLIT", {"tcp-portrange": "1-500 501-1000"})
        r = Resolver(self.snap)
        self.assertTrue(r.services(["HTTPS"]).covers(r.services(["SRC_LIMITED"])))
        self.assertFalse(r.services(["SRC_LIMITED"]).covers(r.services(["HTTPS"])))
        self.assertFalse(r.services(["SPLIT"]).covers(r.services(["WEB_RANGE"])))
        self.assertTrue(r.services(["SPLIT"]).covers(r.services(["HTTPS"])))


class IndexEquivalenceTests(unittest.TestCase):
    def test_index_matches_bruteforce(self):
        found = 0
        for seed in range(15):
            snap = random_snapshot(300, seed)
            r = Resolver(snap)
            m = [checks._build_match(p, r) for p in snap["policies"] if p["status"] == "enable"]
            fast = checks.first_cover(m)
            self.assertEqual(fast, checks.first_cover_bruteforce(m), f"seed {seed}")
            found += sum(x is not None for x in fast)
        self.assertGreater(found, 50)


class AnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snap = model.from_config(load_sample())
        cls.res = checks.analyze(cls.snap)
        cls.f = by_check(cls.res)

    def test_rulebase(self):
        f = self.f
        self.assertEqual(f["REDUNDANT"], {11, 40, 51, 60})
        self.assertEqual(f["SHADOW_CONFLICT"], {12})
        self.assertEqual(f["SHADOW_DEAD"], {22})
        self.assertEqual(f["OUTBOUND_UNRESTRICTED"], {10})
        self.assertNotIn("ANY_ANY", f)
        self.assertNotIn("SERVICE_ALL", f)  # #33 is reported as EXPOSED_ALL_PORTS instead
        self.assertEqual(f["NO_LOG"], {20})
        self.assertEqual(f["DISABLED"], {41})
        self.assertEqual(f["NO_NAME"], {41})
        self.assertEqual(f["NO_UTM_WAN"], {10, 40, 60})
        self.assertEqual(f["EXPIRED_SCHEDULE"], {60})
        self.assertNotIn("UNUSED", f)

    def test_exposure(self):
        f, res = self.f, self.res
        self.assertEqual(set(res["wan_interfaces"]), {"wan1", "wan2"})
        self.assertEqual(f["EXPOSED_RISKY"], {32})
        self.assertEqual(sev_of(res, "EXPOSED_RISKY", 32), "high")
        self.assertEqual(f["EXPOSED_ALL_PORTS"], {33})
        self.assertEqual(sev_of(res, "EXPOSED_ALL_PORTS", 33), "medium")  # geo-restricted
        self.assertEqual(f["EXPOSED_NO_IPS"], {31, 32, 33})
        self.assertEqual(sev_of(res, "EXPOSED_NO_IPS", 33), "low")
        self.assertEqual(f["ADMIN_WAN"], {"wan1", "wan2"})
        self.assertEqual(sev_of(res, "ADMIN_WAN", "wan1"), "high")
        self.assertEqual(sev_of(res, "ADMIN_WAN", "wan2"), "low")  # blocked by local-in
        rdp = [x for x in res["exposure"] if x.get("policyid") == 32][0]
        self.assertEqual(rdp["risky"], ["RDP"])
        self.assertEqual(rdp["external"], "198.51.100.11:33890")
        kinds = {x["kind"] for x in res["exposure"]}
        self.assertEqual(kinds, {"Rule", "Management", "SSL-VPN", "IPsec"})
        self.assertNotIn(30, f.get("EXPOSED_NO_IPS", set()))  # has IPS

    def test_vpn_and_admin(self):
        f, res = self.f, self.res
        self.assertEqual(f["SSLVPN_EXPOSED"], {"vpn ssl settings"})
        self.assertEqual(f["SSLVPN_WEAK_TLS"], {"vpn ssl settings"})
        self.assertEqual(f["VPN_WEAK_CRYPTO"], {"branch-vpn", "branch-p2"})
        self.assertEqual(sev_of(res, "VPN_WEAK_CRYPTO", "branch-vpn"), "medium")
        self.assertEqual(sev_of(res, "VPN_WEAK_CRYPTO", "branch-p2"), "low")
        self.assertEqual(f["VPN_AGGRESSIVE_PSK"], {"branch-vpn"})
        self.assertEqual(f["VPN_NO_PFS"], {"branch-p2"})
        self.assertEqual(f["UNUSED_OBJECT"], {"Unused_Group", "TCP_8443"})
        self.assertEqual(f["ADMIN_TELNET"], {"internal"})
        self.assertEqual(f["ADMIN_NO_TRUSTHOST"], {"admin"})
        self.assertEqual(f["APIUSER_NO_TRUSTHOST"], {"old-integration"})
        self.assertIn("WEAK_CRYPTO", f)

    def test_score_and_summary(self):
        res = self.res
        self.assertLessEqual(res["score"], checks.HIGH_CAP)
        self.assertEqual(set(res["areas"]), {"exposure", "rules", "device", "monitoring", "vpn", "objects"})
        self.assertEqual(res["cleanup"], {"policies": 6, "total": 15, "percent": 40, "objects": 2})
        self.assertEqual(res["top_actions"][0]["severity"], "high")
        rdp = [x for x in res["findings"] if x["check"] == "EXPOSED_RISKY"][0]
        self.assertIn("PCI DSS 4.0 1.4.2", rdp["compliance"])
        self.assertEqual(rdp["uuid"], "11111111-0000-0000-0000-000000000032")
        clean = checks.score([], {"enabled": 10, "objects_total": 10})
        self.assertEqual((clean["score"], clean["grade"]), (100, "A"))
        one_high = checks.score([{"check": "ANY_ANY", "severity": "high"}], {"enabled": 10, "objects_total": 10})
        self.assertLessEqual(one_high["score"], 69)

    def test_outputs(self):
        html = report.html_report(self.res, self.snap, client="Lab", auditor="Pavel")
        for s in ("Executive summary", "Priority actions", "Internet exposure", "Compliance view", "ISO 27001:2022",
                  "data-theme-toggle", "prefers-color-scheme: dark", 'data-fsev="high"', 'id="check-SHADOW_CONFLICT"',
                  "Deny rule never applies", "198.51.100.11:33890"):
            self.assertIn(s, html)
        cli_txt = report.remediation_cli(self.res)
        self.assertIn("# config firewall policy\n#     move 12 before 10", cli_txt)
        self.assertIn("#         set proposal aes256-sha256", cli_txt)
        self.assertIn("    set ssl-min-proto-ver tls1-2", cli_txt)
        self.assertEqual(cli_txt.count('edit "internal"'), 1)  # telnet + http fixed in one block
        csv_txt = report.findings_csv(self.res)
        self.assertTrue(csv_txt.startswith("﻿severity,check,title"))
        self.assertIn("EXPOSED_RISKY", csv_txt)

    def test_v1_snapshot_upgrade(self):
        old = json.loads(json.dumps(self.snap))
        old["schema"] = 1
        old["vips"] = list(old["vips"])
        for k in ("sslvpn", "ipsec_p1", "ipsec_p2", "local_in", "default_routes", "schedules", "change_log"):
            old.pop(k)
        up = model.upgrade(old)
        self.assertEqual(up["schema"], model.SCHEMA)
        res = checks.analyze(up)
        self.assertIn("SHADOW_CONFLICT", by_check(res))


class UsageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.snap = model.from_config(load_sample())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _file(self, name, text):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p

    def test_csv_import(self):
        p = self._file("hits.csv", "Policy ID;Hits;Last Seen\n10;5000;2026-10-30 10:00\n30;12;2025-01-01\n50;7;2026-10-31\n")
        u = usage.load(p)
        self.assertEqual(u["10"]["hit_count"], 5000)
        known, unknown = usage.apply(self.snap, u, p, usage.to_epoch("2026-08-01"))
        # logtraffic=all policies missing from the file become zero-hit; others stay unknown
        self.assertEqual(self.snap["hits"]["21"]["hit_count"], 0)
        self.assertEqual(self.snap["hits"]["32"]["hit_count"], 0)
        self.assertNotIn("11", self.snap["hits"])
        res = checks.analyze(self.snap)
        f = by_check(res)
        self.assertIn(32, f["UNUSED"])
        self.assertIn(21, f["UNUSED_DENY"])
        self.assertIn(30, f["STALE"])
        self.assertTrue(any("Usage imported" in n for n in res["notes"]))

    def test_fortigate_json_and_opensearch(self):
        p1 = self._file("fgt.json", json.dumps({"results": [{"policyid": 10, "hit_count": 3, "last_used": 1761900000},
                                                            {"policyid": 10, "hit_count": 4, "last_used": 1761900500}]}))
        self.assertEqual(usage.load(p1)["10"], {"hit_count": 7, "bytes": 0, "last_used": 1761900500, "first_used": 0})
        agg = {"aggregations": {"by_policy": {"buckets": [
            {"key": "32", "doc_count": 99, "last_seen": {"value": 1761900000000.0, "value_as_string": "2025-10-31T08:40:00.000Z"}},
            {"key": 10, "doc_count": 5}]}}}
        u = usage.load(self._file("os.json", json.dumps(agg)))
        self.assertEqual(u["32"]["hit_count"], 99)
        self.assertEqual(u["32"]["last_used"], 1761900000)
        self.assertEqual(usage.to_epoch(1761900000000000000), 1761900000)


class BaselineAndRedactTests(unittest.TestCase):
    def test_baseline(self):
        before = model.from_config(load_sample())
        after = copy.deepcopy(before)
        after["policies"] = [p for p in after["policies"] if p["policyid"] not in (12, 32)]
        after["global"]["strong-crypto"] = "enable"
        res = checks.analyze(after, baseline=before)
        comp = res["comparison"]
        resolved = {(x["check"], x["policyid"] or x["object"]) for x in comp["resolved"]}
        self.assertIn(("SHADOW_CONFLICT", 12), resolved)
        self.assertIn(("EXPOSED_RISKY", 32), resolved)
        self.assertIn(("WEAK_CRYPTO", "system global"), resolved)
        self.assertEqual(comp["new"], [])
        self.assertIn("Progress since", report.html_report(res, after))
        # a findings JSON works as baseline too
        res2 = checks.analyze(after, baseline=json.loads(json.dumps(checks.analyze(before))))
        self.assertEqual(len(res2["comparison"]["resolved"]), len(comp["resolved"]))

    def test_redaction(self):
        snap = model.from_config(load_sample())
        red, mapping = redact(snap)
        a, b = checks.analyze(snap), checks.analyze(red)
        key = lambda r: sorted((f["check"], f["severity"], f["policyid"] or 0) for f in r["findings"])  # noqa: E731
        self.assertEqual(key(a), key(b))
        self.assertEqual(a["score"], b["score"])
        html = report.html_report(b, red, redacted=True) + report.remediation_cli(b) + json.dumps(b)
        for leak in ("LAN_NET", "Web_Server", "FGT-LAB", "rdp-to-fileserver", "198.51.100.11", "old-integration",
                     "pavel", "VIP_RDP", "branch-vpn", "203.0.113.10", "LAN_ZONE", "promo-2024", "block-bad-host",
                     "DC01", "audit-ro", "user nms", "'nms'"):
            self.assertNotIn(leak, html, leak)
        self.assertIn("pseudonymized", html)
        self.assertEqual(mapping["addresses"]["LAN_NET"][:4], "ADDR")


class DiffTests(unittest.TestCase):
    def test_diff_attribution_and_alerts(self):
        old = model.from_config(load_sample())
        old["global"]["strong-crypto"] = "enable"
        new = copy.deepcopy(old)
        new["collected_at"] = "2099-01-01T00:00:00+00:00"
        pols = new["policies"]
        pols[0]["service"] = ["HTTPS"]                              # modify 10
        moved = next(p for p in pols if p["policyid"] == 22)
        pols.remove(moved)
        pols.insert(0, moved)                                        # move 22 to the top
        pols.append(dict(pols[1], policyid=99, uuid="new-uuid", name="added", srcintf=["wan2"],
                         dstintf=["internal"], action="accept", logtraffic="disable"))
        del new["addresses"]["Old_Printer"]
        new["interfaces"]["wan2"]["allowaccess"] = ["ping", "https", "ssh"]
        new["admins"]["bob"] = {"name": "bob", "accprofile": "super_admin", "trusthosts": []}
        new["global"]["strong-crypto"] = "disable"
        t = model.iso_epoch("2098-12-31T12:00:00+00:00")
        new["change_log"] = [
            {"time": t, "user": "pavel", "ui": "GUI(192.168.1.50)", "action": "Edit", "cfgpath": "firewall.policy",
             "cfgobj": "10", "cfgattr": "service[ALL->HTTPS]", "msg": ""},
            {"time": t, "user": "pavel", "ui": "ssh(192.168.1.50)", "action": "Add", "cfgpath": "system.admin",
             "cfgobj": "bob", "cfgattr": "", "msg": ""},
        ]
        d = diff.diff_snapshots(old, new)
        self.assertEqual([p["policyid"] for p in d["policies"]["added"]], [99])
        self.assertEqual([m["policy"]["policyid"] for m in d["policies"]["modified"]], [10])
        self.assertEqual([p["policyid"] for p in d["policies"]["moved"]], [22])
        changes = {(o["type"], o["name"], o["change"]) for o in d["objects"]}
        self.assertIn(("Address", "Old_Printer", "removed"), changes)
        self.assertIn(("Admin", "bob", "added"), changes)
        self.assertIn(("Interface", "wan2", "modified"), changes)
        self.assertTrue(d["attribution"]["policy:10"][0].startswith("pavel via GUI(192.168.1.50)"))
        self.assertIn("Admin:bob", d["attribution"])
        alerts = " | ".join(d["alerts"])
        for s in ("Management access added on internet-facing interface wan2: ssh", "New admin account: bob",
                  "New inbound rule from the internet: #99", "New accept rule without logging: #99",
                  "strong-crypto was disabled"):
            self.assertIn(s, alerts)
        text = diff.render_text(d)
        self.assertIn("service: ALL -> HTTPS", text)
        self.assertIn("by pavel via GUI", text)
        self.assertIn("Changed by", diff.render_html(d))


class FleetTests(unittest.TestCase):
    def test_fleet_run(self):
        tmp = tempfile.mkdtemp()
        try:
            b_conf = os.path.join(tmp, "b.conf")
            shutil.copy(SAMPLE, b_conf)
            inv = os.path.join(tmp, "fleet.ini")
            with open(inv, "w") as fh:
                fh.write(f"[DEFAULT]\ninsecure = yes\n\n[lab-a]\nconfig = {SAMPLE}\nlabel = Lab A\ngroup = Lab\n\n"
                         f"[lab-b]\nconfig = {b_conf}\n\n[broken]\nconfig = {os.path.join(tmp, 'missing.conf')}\n")
            devs = fleet.load_inventory(inv)
            self.assertEqual([d["name"] for d in devs], ["lab-a", "lab-b", "broken"])
            out, snaps = os.path.join(tmp, "site"), os.path.join(tmp, "snaps")
            s1 = fleet.run(devs, out, snaps, workers=3)
            with open(b_conf, encoding="utf-8") as fh:
                text = fh.read()
            text = text.replace("set allowaccess ping https\n", "set allowaccess ping https ssh\n", 1)
            with open(b_conf, "w", encoding="utf-8") as fh:
                fh.write(text)
            s2 = fleet.run(devs, out, snaps, workers=3)
            rows = {r["name"]: r for r in s2["devices"]}
            self.assertEqual(rows["broken"]["status"], "error")
            self.assertEqual(rows["lab-a"]["status"], "ok")
            self.assertEqual(rows["lab-a"]["changes"], 0)
            self.assertGreater(rows["lab-b"]["changes"], 0)
            self.assertTrue(any("wan2" in a for a in rows["lab-b"]["alerts"]))
            first = {r["name"]: r for r in s1["devices"]}
            self.assertEqual(rows["lab-a"]["trend"], [first["lab-a"]["score"]] * 2)
            for p in ("index.html", "fleet.json", "lab-a/report.html", "lab-b/changes.html", "lab-b/findings.csv"):
                self.assertTrue(os.path.exists(os.path.join(out, p)), p)
            with open(os.path.join(out, "index.html"), encoding="utf-8") as fh:
                idx = fh.read()
            self.assertIn("Firewall fleet overview", idx)
            self.assertIn("Management access added", idx)
        finally:
            shutil.rmtree(tmp)


class WanDetectionTests(unittest.TestCase):
    """Regression: internal VLAN carrying the default route to an upstream internal network (reported bug, policy #859)."""

    def _snap(self, role):
        snap = model.from_config(load_sample())
        snap["interfaces"]["QinQ-V10"] = model._interface("QinQ-V10", {"role": role, "type": "vlan"})
        snap["interfaces"]["port13"] = model._interface("port13", {"role": "lan"})
        snap["zones"]["v13-DATA"] = ["port13"]
        snap["default_routes"].append({"device": "QinQ-V10", "sdwan_zone": [], "sdwan": False})
        snap["addresses"]["cHC-ApexAV"] = model._address("cHC-ApexAV", {"subnet": "10.13.0.5 255.255.255.255"})
        snap["services"]["TM-Ports"] = model._service("TM-Ports", {"tcp-portrange": "135 139 445"})
        snap["policies"].append(model._policy(859, {"srcintf": ["QinQ-V10"], "dstintf": ["v13-DATA"], "srcaddr": ["all"],
            "dstaddr": ["cHC-ApexAV"], "service": ["TM-Ports"], "action": "accept", "status": "enable",
            "schedule": "always", "logtraffic": "all"}))
        return snap

    def test_lan_role_beats_default_route(self):
        res = checks.analyze(self._snap("lan"))
        self.assertNotIn("QinQ-V10", res["wan_interfaces"])
        self.assertNotIn(859, by_check(res).get("EXPOSED_RISKY", set()))
        self.assertEqual(res["wan_reasons"]["wan1"], ["role wan", "SD-WAN member (virtual-wan-link)",
                                                       "default route via SD-WAN zone virtual-wan-link",
                                                       "VIP external interface"])

    def test_undefined_role_shows_reason_and_can_be_excluded(self):
        snap = self._snap("undefined")
        res = checks.analyze(snap)
        self.assertEqual(res["wan_reasons"]["QinQ-V10"], ["default route"])
        self.assertIn(859, by_check(res)["EXPOSED_RISKY"])
        self.assertIn("QinQ-V10 (default route)", report.console_summary(res))
        cli.apply_wan(snap, None, "QinQ-V10")
        res = checks.analyze(snap)
        self.assertNotIn(859, by_check(res).get("EXPOSED_RISKY", set()))
        self.assertIn("wan1", res["wan_interfaces"])

    def test_manual_list_and_zone_names(self):
        snap = self._snap("undefined")
        cli.apply_wan(snap, "wan2", None)
        res = checks.analyze(snap)
        self.assertEqual(res["wan_reasons"], {"wan2": ["set manually"]})
        self.assertNotIn("EXPOSED_RISKY", by_check(res))   # RDP VIP is on wan1
        snap2 = self._snap("undefined")
        cli.apply_wan(snap2, None, "virtual-wan-link")     # zone name expands to wan1, wan2
        self.assertEqual(set(checks.analyze(snap2)["wan_interfaces"]), {"QinQ-V10"})


class InventoryTests(unittest.TestCase):
    def test_example_inventory(self):
        devs = fleet.load_inventory(os.path.join(os.path.dirname(HERE), "examples", "fleet.ini.example"))
        by = {d["name"]: d for d in devs}
        self.assertEqual(set(by), {"HQ-FW", "Branch-North", "Customer-X-offline"})
        self.assertFalse(by["HQ-FW"]["insecure"])                      # certificate checks stay on by default
        self.assertEqual(by["HQ-FW"]["pin_sha256"], "PASTE_FINGERPRINT_FROM_rulescope_cert")
        self.assertEqual(by["Branch-North"]["host"], "192.0.2.21:8443")              # inline '; comment' stripped
        self.assertEqual(by["Branch-North"]["token_env"], "BRANCH_TOKEN")
        self.assertEqual(by["Customer-X-offline"]["usage_since"], "2026-08-01")
        self.assertEqual(by["HQ-FW"]["not_wan"], "port10, QinQ-V10")
        self.assertEqual(source.split_host_port("192.0.2.21:8443", 443), ("192.0.2.21", 8443))

    def test_multi_vdom_expansion(self):
        tmp = tempfile.mkdtemp()
        try:
            p = os.path.join(tmp, "f.ini")
            with open(p, "w") as fh:
                fh.write("[FW]\nhost = 192.0.2.1\nvdom = root, DMZ\n")
            self.assertEqual([d["name"] for d in fleet.load_inventory(p)], ["FW_root", "FW_DMZ"])
        finally:
            shutil.rmtree(tmp)


class CliTests(unittest.TestCase):
    def test_audit_analyze_diff(self):
        tmp = tempfile.mkdtemp()
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                rc = cli.main(["audit", "--config", SAMPLE, "--html", os.path.join(tmp, "r.html"), "--csv",
                               os.path.join(tmp, "f.csv"), "--save-snapshot", os.path.join(tmp, "s"), "--fail-on", "high"])
                self.assertEqual(rc, 2)
                snap_path = source.list_snapshots(os.path.join(tmp, "s", "FGT-LAB"))[0]
                rc = cli.main(["analyze", snap_path, "--redact", "--html", os.path.join(tmp, "red.html")])
                self.assertEqual(rc, 0)
                cli.main(["audit", "--config", SAMPLE, "--save-snapshot", os.path.join(tmp, "s")])
                rc = cli.main(["diff", "--dir", os.path.join(tmp, "s", "FGT-LAB")])
                self.assertEqual(rc, 0)  # identical configs
            self.assertIn("Score", out.getvalue())
            self.assertTrue(os.path.exists(os.path.join(tmp, "red.html")))
        finally:
            shutil.rmtree(tmp)


# ---------------------------------------------------------------- v0.4: best practice, firmware, palettes

class HardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snap = model.from_config(load_sample())
        cls.res = checks.analyze(cls.snap)
        cls.f = by_check(cls.res)

    def test_settings_read_from_backup(self):
        st = self.snap["settings"]
        self.assertEqual(self.snap["settings_source"], "config")
        self.assertEqual(st["ntp"]["ntpsync"], "disable")
        self.assertEqual(st["auto_install"], {"auto-install-config": "enable", "auto-install-image": "enable"})
        self.assertEqual(st["zones"], {"LAN_ZONE": "allow"})
        self.assertEqual(st["snmp_communities"][0]["any_host"], True)
        self.assertNotIn("lab-community-string", json.dumps(self.snap))   # SNMP community = password, never stored
        self.assertNotIn("SH2ldap", json.dumps(self.snap))
        self.assertEqual(self.snap["admins"]["pavel"]["two_factor"], "fortitoken")
        self.assertEqual(self.snap["global"]["admin-https-ssl-versions"], "tlsv1-1 tlsv1-2 tlsv1-3")

    def test_device_checks(self):
        f, res = self.f, self.res
        self.assertEqual(f["ADMIN_NO_MFA"], {"admin"})
        self.assertEqual(f["APIUSER_SUPER_ADMIN"], {"old-integration"})
        self.assertEqual(f["ADMIN_WEAK_TLS"], {"system global"})
        self.assertEqual(f["LDAP_INSECURE"], {"DC01"})
        self.assertEqual(f["SNMP_V2C"], {"SNMP community 1"})
        self.assertEqual(sev_of(res, "SNMP_V2C", "SNMP community 1"), "medium")    # any host, snmp on internal
        self.assertEqual(f["SNMP_V3_NOPRIV"], {"SNMP user nms"})
        for c in ("NTP_DISABLED", "USB_AUTO_INSTALL", "NO_PASSWORD_POLICY", "STATIC_KEY_CIPHERS", "ADMIN_LOCKOUT_WEAK",
                  "NO_PRIVATE_DATA_ENCRYPTION", "HOSTNAME_ON_LOGIN", "NO_LOGIN_BANNER", "ADMIN_DEFAULT_PORTS"):
            self.assertIn(c, f, c)
        self.assertNotIn("HA_NO_MONITOR", f)                                   # standalone
        self.assertNotIn("MANY_SUPER_ADMINS", f)

    def test_logging_profiles_rules(self):
        f = self.f
        self.assertEqual(f["NO_CENTRAL_LOG"], {"log settings"})
        self.assertEqual(f["PROFILE_GAPS"], {11})
        gap = [x for x in self.res["findings"] if x["check"] == "PROFILE_GAPS"][0]
        self.assertEqual(gap["missing"], ["antivirus", "application control"])
        self.assertEqual(f["IPS_NO_BOTNET"], {"default"})
        self.assertNotIn("DNS_NO_BOTNET", f)                                   # block-botnet enable
        self.assertEqual(f["ZONE_INTRAZONE_ALLOW"], {"LAN_ZONE"})
        self.assertEqual(f["NO_ISDB_DENY"], {"firewall policy"})
        self.assertEqual(f["SSLVPN_FACTORY_CERT"], {"vpn ssl settings"})
        self.assertNotIn("SSLVPN_TUNNEL_MODE", f)                              # no policy uses ssl.root

    def test_isdb_deny_rule_above_inbound_rules_passes(self):
        snap = copy.deepcopy(self.snap)
        snap["policies"].insert(0, model._policy(5, {"srcintf": ["wan1", "wan2"], "dstintf": ["any"], "action": "deny",
            "status": "enable", "schedule": "always", "internet-service-src": "enable",
            "internet-service-src-name": ["Tor-Exit.Node", "Malicious-Malicious.Server"], "dstaddr": ["all"],
            "service": ["ALL"], "logtraffic": "all", "name": "deny-bad"}))
        res = checks.analyze(snap)
        self.assertNotIn("NO_ISDB_DENY", by_check(res))
        bp = {i["id"]: i for i in res["practices"]["items"]}
        self.assertEqual(bp["BP22"]["status"], "pass")

    def test_logging_variants(self):
        snap = copy.deepcopy(self.snap)
        snap["settings"]["log_targets"]["syslogd"]["status"] = "enable"
        snap["settings"]["log_targets"]["fortianalyzer"].update(status="enable", **{"enc-algorithm": "low"})
        snap["settings"]["eventfilter"]["event"] = "disable"
        res = checks.analyze(snap)
        f = by_check(res)
        self.assertNotIn("NO_CENTRAL_LOG", f)
        self.assertEqual(f["LOG_UNENCRYPTED"], {"log fortianalyzer setting", "log syslogd setting"})
        self.assertEqual(sev_of(res, "LOG_UNENCRYPTED", "log syslogd setting"), "info")
        self.assertIn("EVENT_LOG_OFF", f)
        bp = {i["id"]: i["status"] for i in res["practices"]["items"]}
        self.assertEqual((bp["BP32"], bp["BP33"]), ("fail", "partial"))

    def test_ha_and_tunnel_mode(self):
        snap = copy.deepcopy(self.snap)
        snap["settings"]["ha"].update(mode="a-p", monitor="", **{"ha-mgmt-status": "disable"})
        snap["policies"].append(model._policy(70, {"srcintf": ["ssl.root"], "dstintf": ["internal"], "srcaddr": ["all"],
            "dstaddr": ["LAN_NET"], "service": ["HTTPS"], "action": "accept", "status": "enable", "schedule": "always",
            "logtraffic": "all", "groups": ["VPN-Users"]}))
        res = checks.analyze(snap)
        f = by_check(res)
        self.assertIn("HA_NO_MONITOR", f)
        self.assertIn("HA_NO_MGMT", f)
        self.assertEqual(f["SSLVPN_TUNNEL_MODE"], {"vpn ssl settings"})        # 7.4.3 < 7.6.3, portal offers tunnel
        snap["device"]["version"] = "v7.6.4"
        self.assertNotIn("SSLVPN_TUNNEL_MODE", by_check(checks.analyze(snap)))

    def test_practices(self):
        bp = self.res["practices"]
        self.assertEqual(bp["total"], 37)
        st = {i["id"]: i["status"] for i in bp["items"]}
        self.assertEqual(st["BP02"], "fail")              # telnet + http
        self.assertEqual(st["BP06"], "fail")              # admin TLS 1.1
        self.assertEqual(st["BP07"], "pass")              # admintimeout 5
        self.assertEqual(st["BP13"], "fail")              # SNMP v2c
        self.assertEqual(st["BP17"], "fail")              # admin without MFA
        self.assertEqual(st["BP26"], "partial")           # IPS without botnet, DNS filter blocks C&C
        self.assertEqual(st["BP34"], "manual")            # backup has no change log
        self.assertEqual(st["BP35"], "partial")           # supported, advisories not checked
        self.assertEqual(st["BP37"], "na")                # standalone
        self.assertEqual(sum(bp["counts"].values()), 37)
        bp02 = next(i for i in bp["items"] if i["id"] == "BP02")
        self.assertEqual(bp02["checks"], ["ADMIN_HTTP", "ADMIN_TELNET"])
        csv_txt = report.practices_csv(self.res)
        self.assertIn("BP17,Accounts,MFA for administrators", csv_txt)

    def test_quick_wins_are_safe_single_settings(self):
        qw = self.res["quick_wins"]
        ids = {q["check"] for q in qw}
        self.assertIn("WEAK_CRYPTO", ids)
        self.assertNotIn("IPS_NO_BOTNET", ids)            # changes traffic: commented, not a quick win
        self.assertNotIn("NO_LOGIN_BANNER", ids)          # info only
        cli_txt = report.remediation_cli(self.res, only=ids, safe_only=True, title="quick wins")
        self.assertIn("# rulescope quick wins script", cli_txt)
        self.assertIn("    set strong-crypto enable", cli_txt)
        self.assertNotIn("move 12 before 10", cli_txt)
        self.assertTrue(all(f["effort"] in ("quick", "change", "project") for f in self.res["findings"]))

    def test_schema2_snapshot_skips_unknown_settings(self):
        old = json.loads(json.dumps(self.snap))
        old["schema"] = 2
        for k in ("settings", "settings_source", "profiles", "accprofiles", "licenses"):
            old.pop(k)
        for k in ("admin-lockout-duration", "ssl-static-key-ciphers", "pre-login-banner", "admin-https-ssl-versions"):
            old["global"].pop(k)
        for a in old["admins"].values():
            a.pop("two_factor")
        up = model.upgrade(old)
        res = checks.analyze(up)
        f = by_check(res)
        for c in ("NTP_DISABLED", "USB_AUTO_INSTALL", "ADMIN_NO_MFA", "ADMIN_LOCKOUT_WEAK", "ADMIN_WEAK_TLS", "SNMP_V2C"):
            self.assertNotIn(c, f, c)
        st = {i["id"]: i["status"] for i in res["practices"]["items"]}
        self.assertEqual((st["BP10"], st["BP15"], st["BP17"]), ("unknown", "unknown", "unknown"))
        # comparing against it does not report the never-evaluated checks as new
        comp = checks.analyze(self.snap, baseline=up)["comparison"]
        self.assertFalse({x["check"] for x in comp["new"]} & {"NTP_DISABLED", "USB_AUTO_INSTALL", "ADMIN_NO_MFA"})

    def test_old_findings_json_as_baseline(self):
        old = json.loads(json.dumps(self.res))
        old.pop("evaluated")
        old["findings"] = [f for f in old["findings"] if f["check"] not in INTRODUCED_0_4]  # what 0.3 produced
        comp = checks.analyze(self.snap, baseline=old)["comparison"]
        self.assertEqual(comp["new"], [])
        self.assertEqual(comp["resolved"], [])

    def test_diff_hardening_alerts(self):
        old = model.from_config(load_sample())
        new = copy.deepcopy(old)
        new["collected_at"] = "2099-01-01T00:00:00+00:00"
        old["settings"]["eventfilter"]["event"] = "enable"
        new["settings"]["eventfilter"]["event"] = "disable"
        new["settings"]["auto_install"]["auto-install-image"] = "enable"
        old["settings"]["auto_install"]["auto-install-image"] = "disable"
        new["admins"]["pavel"]["two_factor"] = "disable"
        alerts = " | ".join(diff.diff_snapshots(old, new)["alerts"])
        for s in ("Event logging was disabled", "USB firmware auto-install was enabled",
                  "Two-factor authentication removed from admin pavel"):
            self.assertIn(s, alerts)
        # a v0.3 snapshot (no settings) diffed against v0.4 produces no settings noise
        legacy = json.loads(json.dumps(old))
        legacy["schema"] = 2
        legacy.pop("settings")
        for a in legacy["admins"].values():
            a.pop("two_factor")
        for k in ("admin-lockout-duration", "ssl-static-key-ciphers"):
            legacy["global"].pop(k)
        d = diff.diff_snapshots(legacy, old)
        self.assertTrue(d["empty"], d["objects"])


class FirmwareTests(unittest.TestCase):
    def test_lifecycle(self):
        self.assertEqual(firmware.lifecycle("v7.2.10", "2026-11-05")["status"], "eos")
        self.assertEqual(firmware.lifecycle("7.4.3", "2026-11-05")["status"], "supported")
        self.assertEqual(firmware.lifecycle("7.4.3", "2027-06-01")["status"], "eoes")
        self.assertEqual(firmware.lifecycle("7.6.1", "2028-03-01")["status"], "eoes_soon")
        self.assertEqual(firmware.lifecycle("7.6.1", "2029-12-01")["status"], "eoes")
        self.assertEqual(firmware.lifecycle("9.9.9", "2026-11-05")["status"], "unknown")
        self.assertEqual(firmware.lifecycle("", "2026-11-05")["status"], "unknown")
        snap = model.from_config(load_sample().replace("FGT60F-7.4.3-FW-build2573", "FGT60F-7.2.10-FW-build1706"))
        res = checks.analyze(snap)
        self.assertEqual(by_check(res)["FIRMWARE_EOS"], {"FortiOS 7.2.10"})
        self.assertIn("reached end of support", " ".join(report.executive_summary(res, "Lab")))

    def test_lifecycle_file_override(self):
        tmp = tempfile.mkdtemp()
        try:
            p = os.path.join(tmp, "lc.json")
            with open(p, "w") as fh:
                json.dump({"7.4": ["2023-05-11", "2025-01-01", "2026-01-01"]}, fh)
            table = firmware.load_lifecycle(p)
            self.assertEqual(firmware.lifecycle("7.4.3", "2026-11-05", table)["status"], "eos")
            self.assertEqual(table["7.6"], firmware.LIFECYCLE["7.6"])
        finally:
            shutil.rmtree(tmp)

    def test_nvd_lookup_cache_and_findings(self):
        NvdHandler.calls = []
        srv = HTTPServer(("127.0.0.1", 0), NvdHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        tmp = tempfile.mkdtemp()
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}/rest/json/cves/2.0"
            client = firmware.AdvisoryClient(mode="online", cache_dir=tmp, api_key="test-key", url=url)
            adv = client.lookup("v7.4.3")
            self.assertIsNone(adv["error"])
            self.assertEqual([c["id"] for c in adv["cves"]], ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"])
            self.assertEqual(len(NvdHandler.calls), 2)                    # two pages
            self.assertIn("cpeName=cpe%3A2.3%3Ao%3Afortinet%3Afortios%3A7.4.3", NvdHandler.calls[0])
            self.assertIn("&isVulnerable&", NvdHandler.calls[0])
            self.assertEqual(NvdHandler.keys, {"test-key"})
            kev = adv["cves"][0]
            self.assertTrue(kev["kev"])
            self.assertEqual(kev["fgir"], "FG-IR-99-001")
            self.assertTrue(os.path.exists(os.path.join(tmp, "fortios-7.4.3.json")))
            # cache mode: no network
            cached = firmware.AdvisoryClient(mode="cache", cache_dir=tmp, url="http://127.0.0.1:9/x").lookup("7.4.3")
            self.assertTrue(cached["from_cache"])
            self.assertEqual(len(cached["cves"]), 3)
            snap = model.from_config(load_sample())
            res = checks.analyze(snap, advisories=cached)
            f = by_check(res)
            self.assertEqual(f["FIRMWARE_KEV"], {"CVE-2099-0001"})
            self.assertEqual(f["FIRMWARE_CVE"], {"CVE-2099-0002"})            # 5.3 is counted, not a finding
            self.assertEqual(sev_of(res, "FIRMWARE_CVE", "CVE-2099-0002"), "high")
            bp = {i["id"]: i["status"] for i in res["practices"]["items"]}
            self.assertEqual(bp["BP35"], "fail")
            html = report.html_report(res, snap)
            self.assertIn("CVE-2099-0001", html)
            self.assertIn("Exploited", html)
            # NVD unreachable in online mode: falls back to the cache with a note
            offline = firmware.AdvisoryClient(mode="online", cache_dir=tmp, max_age_hours=0, url="http://127.0.0.1:9/x",
                                              timeout=2).lookup("7.4.3")
            self.assertIn("using cached results", offline["error"])
            self.assertEqual(len(offline["cves"]), 3)
            none = firmware.AdvisoryClient(mode="cache", cache_dir=os.path.join(tmp, "empty")).lookup("7.4.3")
            self.assertIn("no cached advisory data", none["error"])
        finally:
            srv.shutdown()
            shutil.rmtree(tmp)

    def test_firmware_cli(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(["firmware", "7.2.10", "7.4.3", "--advisories", "off"]), 0)
        self.assertIn("FortiOS 7.2.10: branch 7.2, status eos", out.getvalue())
        self.assertIn("FortiOS 7.4.3: branch 7.4, status supported", out.getvalue())


def _cve(i, score, kev=False):
    c = {"id": f"CVE-2099-000{i}", "published": "2099-01-0{i}T10:00:00.000",
         "descriptions": [{"lang": "en", "value": f"Test vulnerability {i}. More text."}],
         "metrics": {"cvssMetricV31": [{"source": "psirt@fortinet.com", "type": "Secondary",
                                        "cvssData": {"baseScore": score, "baseSeverity": "CRITICAL" if score >= 9 else "HIGH"}}]},
         "references": [{"url": f"https://fortiguard.example/psirt/FG-IR-99-00{i}"}]}
    if kev:
        c.update(cisaExploitAdd="2099-01-05", cisaVulnerabilityName="Fortinet FortiOS Test Vulnerability")
    return {"cve": c}


class NvdHandler(BaseHTTPRequestHandler):
    calls, keys = [], set()

    def do_GET(self):
        NvdHandler.calls.append(self.path)
        NvdHandler.keys.add(self.headers.get("apiKey"))
        items = [_cve(1, 9.8, kev=True), _cve(2, 9.1), _cve(3, 5.3)]
        start = int(self.path.split("startIndex=")[1].split("&")[0]) if "startIndex=" in self.path else 0
        page = items[start:start + 2]
        body = json.dumps({"resultsPerPage": len(page), "startIndex": start, "totalResults": len(items),
                           "format": "NVD_CVE", "version": "2.0", "vulnerabilities": page}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class PaletteTests(unittest.TestCase):
    def test_palettes_and_print(self):
        css = ui.CSS
        for p in ("forest", "ocean", "graphite", "contrast"):
            self.assertIn(f':root[data-palette="{p}"]{{', css)
            self.assertIn(f':root[data-palette="{p}"][data-theme="dark"]{{', css)
            self.assertIn(f'<option value="{p}">', ui.CONTROLS)
        # dark tokens are screen-only, so printing always uses the light variant
        self.assertIn("@media screen and (prefers-color-scheme: dark)", css)
        self.assertNotIn("@media (prefers-color-scheme: dark)", css)
        snap = model.from_config(load_sample())
        res = checks.analyze(snap)
        html = report.html_report(res, snap, palette="ocean")
        self.assertTrue(html.startswith('<!doctype html><html lang="en" data-palette="ocean">'))
        self.assertIn("rulescope-palette", html)
        self.assertIn("data-palette-select", html)
        for s in ('id="practices"', 'id="firmware"', 'id="quickwins"', "Best-practice baseline", "Quick wins",
                  "CIS FortiGate 7.0.x v1.4.0", 'class="eff quick"'):
            self.assertIn(s, html)
        self.assertTrue(report.html_report(res, snap, palette="nope").startswith(
            '<!doctype html><html lang="en" data-palette="harbor">'))
        dash = fleet.dashboard({"generated": "now", "devices": [], "lifecycle": []}, "forest")
        self.assertIn('data-palette="forest"', dash)


# ---------------------------------------------------------------- 0.4.1: hostile input

HOSTILE_NAME = "x\nend\nexecute factoryreset\nconfig firewall address"


def hostile_config():
    """The sample config with crafted names, comments and hostname, as a malicious client could send."""
    cfg = load_sample()
    esc_name = HOSTILE_NAME.replace('"', '\\"')
    cfg = cfg.replace("config firewall address\n", f'config firewall address\n    edit "{esc_name}"\n'
                      '        set subnet 10.9.9.9 255.255.255.255\n    next\n'
                      '    edit "=HYPERLINK(""http://evil.example"",""x"")"\n'
                      '        set subnet 10.9.9.8 255.255.255.255\n    next\n', 1)
    cfg = cfg.replace('set hostname "FGT-LAB"', 'set hostname "..\x1b[2J\x1b]0;pwned\x07"')
    i = cfg.index("    edit 11\n", cfg.index("config firewall policy"))
    j = cfg.index("    next\n", i)
    return cfg[:j] + '        set comments "old\nexecute shutdown\nconfig system global"\n' + cfg[j:]


class HostileInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snap = model.from_config(hostile_config())
        cls.res = checks.analyze(cls.snap)

    def test_no_control_characters_survive_parsing(self):
        dump = json.dumps(self.snap, ensure_ascii=False)
        for ch in ("\\n", "\\u001b", "\\u0007"):
            self.assertNotIn(ch, dump)
        self.assertIn("x end execute factoryreset config firewall address", self.snap["addresses"])

    def test_remediation_script_cannot_be_injected(self):
        cli_txt = report.remediation_cli(self.res)
        for ln in cli_txt.splitlines():
            if ln.strip() and not ln.lstrip().startswith("#"):
                self.assertRegex(ln, r"^\s*(config|edit|set|unset|append|next|end|move|delete)(\s|$)", ln)
        self.assertNotRegex(cli_txt, r"(?m)^\s*execute")
        self.assertIn('delete "x end execute factoryreset config firewall address"', cli_txt)
        self.assertIn("old execute shutdown config system global", cli_txt)   # comment kept on one line
        # the last line of defense blocks anything that is not a generated statement
        guarded = report.guard_script("config firewall policy\n    edit 1\nexecute factoryreset\nend\n")
        self.assertIn("# BLOCKED, unexpected statement: execute factoryreset", guarded)
        self.assertTrue(guarded.startswith("# WARNING: 1 unexpected line"))

    def test_csv_formula_and_terminal(self):
        csv_txt = report.findings_csv(self.res)
        self.assertIn("'=HYPERLINK", csv_txt)
        self.assertNotRegex(csv_txt, r"(^|,)=HYPERLINK")
        self.assertNotIn("\x1b", report.console_summary(self.res))
        self.assertNotIn("\x1b", report.practices_csv(self.res))

    def test_api_data_and_loaded_files_are_cleaned(self):
        snap = model.from_api({"status": {"results": {"hostname": "fw\nevil", "version": "v7.4.3"}},
                               "policy": {"results": [{"policyid": 1, "name": "a\nexecute x", "srcintf": [{"name": "p1"}],
                                                       "dstintf": [{"name": "p2"}], "srcaddr": [{"name": "all"}],
                                                       "dstaddr": [{"name": "all"}], "service": [{"name": "ALL"}],
                                                       "action": "accept", "status": "enable"}]}})
        self.assertEqual(snap["device"]["hostname"], "fw evil")
        self.assertEqual(snap["policies"][0]["name"], "a execute x")
        tmp = tempfile.mkdtemp()
        try:
            p = os.path.join(tmp, "s.json")
            raw = json.loads(json.dumps(model.from_config(load_sample())))
            raw["device"]["hostname"] = "bad\nname\x1b"
            with open(p, "w") as fh:
                json.dump(raw, fh)
            self.assertEqual(source.load_snapshot(p)["device"]["hostname"], "bad name?")
        finally:
            shutil.rmtree(tmp)

    def test_paths_stay_inside_and_files_are_private(self):
        for bad in ("..", ".", "../../etc", "...x", "/abs/path", ""):
            n = source.safe_name(bad)
            self.assertFalse(n.startswith("."), bad)
            self.assertNotIn("/", n)
        tmp = tempfile.mkdtemp()
        try:
            base = os.path.join(tmp, "snaps")
            path = source.save_snapshot(self.snap, base)       # hostname starts with ".."
            self.assertTrue(os.path.realpath(path).startswith(os.path.realpath(base) + os.sep))
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            out = os.path.join(tmp, "r.html")
            with redirect_stdout(io.StringIO()):
                cli.main(["audit", "--config", os.path.join(HERE, "sample.conf"), "--html", out,
                          "--cli", os.path.join(tmp, "fix.txt"), "--advisories", "off"])
            for f in ("r.html", "fix.txt"):
                self.assertEqual(os.stat(os.path.join(tmp, f)).st_mode & 0o007, 0, f)
        finally:
            shutil.rmtree(tmp)

    def test_change_log_secrets_masked(self):
        from rulescope.api import normalize_event
        e = normalize_event({"cfgattr": "auth-pwd[abc]priv-pwd[def]passphrase[wifi123]name[x]", "msg": "psksecret[zz]"})
        self.assertNotIn("abc", e["cfgattr"])
        self.assertNotIn("def", e["cfgattr"])
        self.assertNotIn("wifi123", e["cfgattr"])
        self.assertIn("name[x]", e["cfgattr"])

    def test_report_links_https_only(self):
        from rulescope.safety import safe_url
        self.assertEqual(safe_url("javascript:alert(1)"), "")
        self.assertEqual(safe_url("https://fortiguard.com/psirt/FG-IR-24-015"), "https://fortiguard.com/psirt/FG-IR-24-015")
        c = firmware.sanitize_cve({"id": "CVE-2099-0001", "url": "javascript:alert(1)", "title": "t\nx", "cvss": "9.8"})
        self.assertEqual(c["url"], "https://nvd.nist.gov/vuln/detail/CVE-2099-0001")
        self.assertEqual((c["title"], c["cvss"]), ("t x", 9.8))
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, "fortios-7.4.3.json"), "w") as fh:
                json.dump({"fetched": "2099-01-01T00:00:00+00:00", "cves": [
                    {"id": "CVE-2099-0005\"><script>", "url": "javascript:alert(1)", "kev": True, "cvss": 9.9}]}, fh)
            adv = firmware.AdvisoryClient(mode="cache", cache_dir=tmp).lookup("7.4.3")
            html = report.html_report(checks.analyze(self.snap, advisories=adv), self.snap)
            self.assertNotIn("javascript:", html)
            self.assertNotIn("<script>alert", html)
        finally:
            shutil.rmtree(tmp)

    def test_syslog_one_line_per_alert(self):
        import socket
        from rulescope import notify
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(2)
        try:
            notify.syslog(f"127.0.0.1:{rx.getsockname()[1]}", "fw\nx", ["Policy a\n<132>1 forged line"])
            msg = rx.recv(4096).decode()
            self.assertNotIn("\n", msg)
            self.assertIn("forged line", msg)
        finally:
            rx.close()

    def test_webhook_url_from_file_or_env(self):
        tmp = tempfile.mkdtemp()
        try:
            p = os.path.join(tmp, "hook")
            with open(p, "w") as fh:
                fh.write("https://hooks.example/abc\n")
            import argparse
            self.assertEqual(cli._webhook(argparse.Namespace(webhook_file=p, webhook=None)), "https://hooks.example/abc")
            os.environ["RULESCOPE_WEBHOOK"] = "https://hooks.example/env"
            try:
                self.assertEqual(cli._webhook(argparse.Namespace(webhook_file=None, webhook=None)), "https://hooks.example/env")
            finally:
                del os.environ["RULESCOPE_WEBHOOK"]
        finally:
            shutil.rmtree(tmp)

    def test_nvd_lookup_once_per_version_under_concurrency(self):
        NvdHandler.calls = []
        srv = HTTPServer(("127.0.0.1", 0), NvdHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        tmp = tempfile.mkdtemp()
        try:
            client = firmware.AdvisoryClient(mode="online", cache_dir=tmp, api_key="k",
                                             url=f"http://127.0.0.1:{srv.server_address[1]}/rest/json/cves/2.0")
            results = []
            ts = [threading.Thread(target=lambda: results.append(client.lookup("7.4.3"))) for _ in range(6)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
            self.assertEqual(len(NvdHandler.calls), 2)          # one lookup (two pages), not six
            self.assertTrue(all(len(r["cves"]) == 3 for r in results))
            self.assertEqual([f for f in os.listdir(tmp) if f.endswith(".tmp")], [])
        finally:
            srv.shutdown()
            shutil.rmtree(tmp)


@unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
class PinningTests(unittest.TestCase):
    def test_pin_accepts_only_that_certificate(self):
        import ssl
        import subprocess
        from rulescope.api import CertificatePinError, FortiGateAPI, cert_fingerprint
        tmp = tempfile.mkdtemp()
        try:
            key, crt = os.path.join(tmp, "k.pem"), os.path.join(tmp, "c.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                            "-days", "2", "-subj", "/CN=fgt-test"], check=True, capture_output=True)
            seen = []

            class H(BaseHTTPRequestHandler):
                def do_GET(self):
                    seen.append(self.headers.get("Authorization"))
                    body = b'{"results": {"hostname": "fgt"}}'
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *a):
                    pass
            srv = HTTPServer(("127.0.0.1", 0), H)
            srv.handle_error = lambda *a: None  # the refused client closes the connection on purpose
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(crt, key)
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            port = srv.server_address[1]
            try:
                fp = cert_fingerprint("127.0.0.1", port)
                ok = FortiGateAPI("127.0.0.1", "tok", port=port, pin_sha256=":".join(fp[i:i + 2] for i in range(0, 64, 2)))
                self.assertEqual(ok.get("monitor/system/status", vdom_scoped=False)["results"]["hostname"], "fgt")
                self.assertEqual(seen, ["Bearer tok"])
                bad = FortiGateAPI("127.0.0.1", "secret", port=port, pin_sha256="0" * 64)
                with self.assertRaises(CertificatePinError):
                    bad.get("monitor/system/status", vdom_scoped=False)
                self.assertEqual(seen, ["Bearer tok"])          # the token was never sent to the wrong certificate
                strict = FortiGateAPI("127.0.0.1", "secret", port=port)  # default: CA verification, self-signed fails
                with self.assertRaises(ConnectionError):
                    strict.get("monitor/system/status", vdom_scoped=False)
            finally:
                srv.shutdown()
        finally:
            shutil.rmtree(tmp)


# ---------------------------------------------------------------- fake FortiGate REST API

def fake_api_payloads():
    now = int(time.time())
    snap = model.from_config(load_sample())
    refs = snap["references"]

    def lst(names):
        return [{"name": n, "q_origin_key": n} for n in names]

    def meta(d):
        return dict(d, q_ref=refs.get(d["name"], 0), q_static=False)

    policies = []
    for p in snap["policies"]:
        api_p = dict(p)
        for f in model.POLICY_LIST_FIELDS:
            api_p[f] = lst(p[f])
        policies.append(api_p)
    return {
        "monitor/system/status": {"results": {"hostname": "FGT-LAB", "model_name": "FortiGate 60F"},
                                  "serial": "FGT60FTK00000000", "version": "v7.4.3", "build": 2573},
        "cmdb/system/global": {"results": {"hostname": "FGT-LAB", "strong-crypto": "enable", "admintimeout": 480}},
        "cmdb/firewall/policy": {"results": policies},
        "cmdb/firewall/address": {"results": [meta(a) for a in snap["addresses"].values()]},
        "cmdb/firewall/addrgrp": {"results": [meta(dict(g, member=lst(g["member"]))) for g in snap["addrgrps"].values()]},
        "cmdb/firewall.service/custom": {"results": [meta(dict(s, **{"tcp-portrange": " ".join(s["tcp-portrange"])}))
                                                     for s in snap["services"].values()]},
        "cmdb/firewall.service/group": {"results": [meta(dict(g, member=lst(g["member"]))) for g in snap["servicegrps"].values()]},
        "cmdb/firewall/vip": {"results": [meta(dict(v, mappedip=[{"range": m} for m in v["mappedip"]]))
                                          for v in snap["vips"].values()]},
        "cmdb/firewall/vipgrp": {"results": []},
        "cmdb/system/zone": {"results": [{"name": "LAN_ZONE", "interface": [{"interface-name": "internal"}]}]},
        "cmdb/system/sdwan": {"results": {"zone": [{"name": "virtual-wan-link"}],
                                          "members": [{"interface": "wan1", "zone": "virtual-wan-link"},
                                                      {"interface": "wan2", "zone": "virtual-wan-link"}]}},
        "cmdb/system/interface": {"results": [dict(i, allowaccess=" ".join(i["allowaccess"]))
                                              for i in snap["interfaces"].values()]},
        "cmdb/firewall.schedule/onetime": {"results": [{"name": "promo-2024", "start": "00:00 2024/01/01",
                                                        "end": "00:00 2024/12/31"}]},
        "cmdb/vpn.ssl/settings": {"results": {"status": "enable", "port": 10443, "source-interface": [{"name": "wan1"}],
                                              "source-address": [{"name": "all"}], "ssl-min-proto-ver": "tls1-1"}},
        "cmdb/vpn.ipsec/phase1-interface": {"results": [{"name": "branch-vpn", "interface": "wan1", "type": "static",
            "ike-version": "1", "mode": "aggressive", "authmethod": "psk", "proposal": "3des-md5 aes128-sha1",
            "dhgrp": "2", "remote-gw": "203.0.113.10", "psksecret": "ENC c2VjcmV0cHNr"}]},
        "cmdb/vpn.ipsec/phase2-interface": {"results": [{"name": "branch-p2", "phase1name": "branch-vpn",
                                                         "proposal": "aes128-sha1", "pfs": "disable"}]},
        "cmdb/firewall/local-in-policy": {"results": [{"policyid": 1, "intf": [{"name": "wan2"}], "srcaddr": lst(["all"]),
            "dstaddr": lst(["all"]), "service": lst(["ALL"]), "action": "deny", "status": "enable", "schedule": "always"}]},
        "cmdb/router/static": {"results": [{"seq-num": 1, "dst": "0.0.0.0 0.0.0.0", "status": "enable",
                                            "sdwan-zone": [{"name": "virtual-wan-link"}]}]},
        "monitor/firewall/policy": {"results": [
            {"policyid": 10, "hit_count": 52000, "bytes": 9_000_000, "last_used": now - 3600, "first_used": now - 86400 * 30},
            {"policyid": 20, "hit_count": 0, "bytes": 0, "last_used": 0, "first_used": 0},
            {"policyid": 21, "hit_count": 0, "bytes": 0, "last_used": 0, "first_used": 0},
            {"policyid": 30, "hit_count": 12, "bytes": 1000, "last_used": now - 86400 * 200, "first_used": now - 86400 * 300},
            {"policyid": 31, "hit_count": 4, "bytes": 100, "last_used": now - 7200, "first_used": now - 86400 * 10},
            {"policyid": 31, "hit_count": 3, "bytes": 100, "last_used": now - 600, "first_used": now - 86400 * 20},
            {"policyid": 32, "hit_count": 5, "bytes": 100, "last_used": now - 600, "first_used": now - 86400 * 2},
        ]},
        "log/memory/event/system": {"results": [
            {"eventtime": (now - 300) * 10**9, "logdesc": "Object attribute configured", "user": "pavel",
             "ui": "GUI(192.168.1.50)", "action": "Edit", "cfgpath": "firewall.policy", "cfgobj": "32",
             "cfgattr": "srcaddr[LAN_NET->all]", "msg": "Edit firewall.policy 32"},
            {"date": "2026-11-01", "time": "10:00:00", "tz": "+0200", "user": "pavel", "ui": "ssh(192.168.1.50)",
             "action": "Add", "cfgpath": "system.admin", "cfgobj": "bob", "cfgattr": "password[ENC SH2abc]accprofile[super_admin]"},
            {"logdesc": "Admin login successful", "user": "pavel"},
        ]},
        "cmdb/system/password-policy": {"results": {"status": "enable", "apply-to": "admin-password", "minimum-length": 12}},
        "cmdb/system.snmp/sysinfo": {"results": {"status": "enable"}},
        "cmdb/system.snmp/community": {"results": [{"id": 1, "name": "api-secret-community", "status": "enable",
                                                    "query-v1-status": "disable", "query-v2c-status": "enable",
                                                    "hosts": [{"id": 1, "ip": "10.0.0.5 255.255.255.255"}]}]},
        "cmdb/system.snmp/user": {"results": []},
        "cmdb/log/eventfilter": {"results": {"event": "disable", "system": "enable"}},
        "monitor/license/status": {"results": {"antivirus": {"type": "licensed", "status": "expired", "expires": now - 86400},
                                               "ips": {"type": "licensed", "status": "licensed", "expires": now + 10 * 86400},
                                               "forticare": {"status": "registered"}}},
        # admin / api-user / disk logs / backup intentionally forbidden (403) like a read-only token without sysgrp
    }


class Handler(BaseHTTPRequestHandler):
    payloads = {}
    seen = []

    def _send(self):
        path = self.path.split("?")[0].replace("/api/v2/", "")
        Handler.seen.append(path)
        if self.headers.get("Authorization") != "Bearer good-token":
            self.send_response(401)
            self.end_headers()
            return
        body = self.payloads.get(path)
        if body is None:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'{"status":"error","http_status":403}')
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    do_GET = _send
    do_POST = _send

    def log_message(self, *a):
        pass


class ApiPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Handler.payloads = fake_api_payloads()
        cls.srv = HTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def api(self, token="good-token"):
        from rulescope.api import FortiGateAPI
        api = FortiGateAPI("127.0.0.1", token, port=self.port)
        api.base = f"http://127.0.0.1:{self.port}"  # plain HTTP for the test server
        return api

    def test_bad_token(self):
        from rulescope.api import ApiError
        with self.assertRaises(ApiError) as cm:
            self.api("wrong").collect_raw()
        self.assertEqual(cm.exception.status, 401)

    def test_collect_and_analyze(self):
        Handler.seen = []
        raw = self.api().collect_raw()
        self.assertNotIn("monitor/system/config/backup", Handler.seen)  # q_ref made the backup unnecessary
        self.assertIn("log/disk/event/system", Handler.seen)            # tried disk, fell back to memory
        snap = model.from_api(raw)
        self.assertEqual(snap["references_source"], "q_ref")
        self.assertEqual(snap["device"]["serial"], "FGT60FTK00000000")
        self.assertEqual(len(snap["policies"]), 15)
        self.assertEqual(snap["hits"]["31"]["hit_count"], 7)
        self.assertIsNone(snap["admins"])
        self.assertEqual(len(snap["change_log"]), 2)
        self.assertIn("password[***]", json.dumps(snap["change_log"]))
        self.assertNotIn("SH2abc", json.dumps(snap))
        self.assertNotIn("c2VjcmV0cHNr", json.dumps(snap))
        res = checks.analyze(snap, stale_days=90)
        f = by_check(res)
        self.assertEqual(f["SHADOW_CONFLICT"], {12})
        self.assertEqual(f["REDUNDANT"], {11, 40, 51, 60})
        self.assertEqual(f["UNUSED"], {20})
        self.assertEqual(f["UNUSED_DENY"], {21})
        self.assertEqual(f["STALE"], {30})
        self.assertEqual(f["EXPOSED_RISKY"], {32})
        self.assertEqual(f["UNUSED_OBJECT"], {"Unused_Group", "TCP_8443"})
        self.assertEqual(f["VPN_AGGRESSIVE_PSK"], {"branch-vpn"})
        self.assertEqual(f["SSLVPN_WEAK_TLS"], {"vpn ssl settings"})
        self.assertEqual(f["EXPIRED_SCHEDULE"], {60})
        self.assertIn("LONG_ADMIN_TIMEOUT", f)
        self.assertEqual(f["ADMIN_WAN"], {"wan1", "wan2"})
        self.assertEqual(sev_of(res, "ADMIN_WAN", "wan1"), "high")       # admins unknown -> assume worst
        rdp = [x for x in res["exposure"] if x.get("policyid") == 32][0]
        self.assertEqual(rdp["hits"], 5)
        self.assertIn("Recent configuration changes", report.html_report(res, snap))
        # hardening settings over the API: readable ones are checked, the rest are 'not assessed'
        self.assertNotIn("api-secret-community", json.dumps(snap))
        self.assertEqual(snap["settings_source"], "api")
        self.assertNotIn("NO_PASSWORD_POLICY", f)
        self.assertEqual(sev_of(res, "SNMP_V2C", "SNMP community 1"), "low")     # restricted to one host
        self.assertIn("EVENT_LOG_OFF", f)
        self.assertEqual(f["LICENSE_EXPIRED"], {"Antivirus", "IPS"})
        self.assertEqual(sev_of(res, "LICENSE_EXPIRED", "Antivirus"), "medium")
        self.assertEqual(sev_of(res, "LICENSE_EXPIRED", "IPS"), "low")
        self.assertNotIn("NTP_DISABLED", f)
        st = {i["id"]: i["status"] for i in res["practices"]["items"]}
        self.assertEqual((st["BP10"], st["BP16"], st["BP34"], st["BP36"]), ("unknown", "pass", "pass", "fail"))
        self.assertTrue(any("Token could not read" in n for n in res["notes"]))
        # system global unreadable: default admin ports still apply, global-based checks are not assessed
        raw["global"] = None
        snap2 = model.from_api(raw)
        res2 = checks.analyze(snap2)
        self.assertIn("wan1:443", {x["external"] for x in res2["exposure"] if x["kind"] == "Management"})
        self.assertNotIn("WEAK_CRYPTO", by_check(res2))
        self.assertIn("SNMP_V2C", by_check(res2))
        st2 = {i["id"]: i["status"] for i in res2["practices"]["items"]}
        self.assertEqual((st2["BP07"], st2["BP09"]), ("unknown", "unknown"))


class ReviewFixTests(unittest.TestCase):
    def test_log_poll_waits_when_progress_is_zero(self):
        from rulescope import api
        self.assertEqual(api._progress({"completed": 0}), 0.0)
        self.assertEqual(api._progress({"completed": "40"}), 40.0)
        self.assertEqual(api._progress({}), 100.0)

        calls = []

        class Fake(api.FortiGateAPI):
            def _request(self, method, path, params=None, body=None, raw=False):
                calls.append(params.get("session_id"))
                if "session_id" not in params:
                    return {"session_id": 7, "completed": 0, "results": []}
                return {"session_id": 7, "completed": 100,
                        "results": [{"cfgpath": "firewall.policy", "eventtime": 1700000000}]}

        orig = api.time.sleep
        api.time.sleep = lambda s: None
        try:
            events, src = Fake("192.0.2.1", "t").config_events()
        finally:
            api.time.sleep = orig
        self.assertEqual((len(events), src), (1, "disk"))
        self.assertEqual(calls, [None, "7"])

    def test_secret_masking_covers_old_and_new_values(self):
        from rulescope.api import _sanitize
        out = _sanitize("psksecret[ENC aaa]->[ENC bbb] comments[x]->[y]", 400)
        self.assertNotIn("aaa", out)
        self.assertNotIn("bbb", out)
        self.assertIn("comments[x]->[y]", out)
        self.assertNotIn("s3cr3t", _sanitize("passwd[old->s3cr3t]", 400))

    def test_ipv6_hosts(self):
        from rulescope.api import FortiGateAPI
        self.assertEqual(source.split_host_port("[2001:db8::1]:8443", 443), ("2001:db8::1", 8443))
        self.assertEqual(source.split_host_port("[2001:db8::1]", 443), ("2001:db8::1", 443))
        self.assertEqual(source.split_host_port("2001:db8::1", 443), ("2001:db8::1", 443))
        self.assertEqual(FortiGateAPI("2001:db8::1", "t", port=8443).base, "https://[2001:db8::1]:8443")
        self.assertEqual(FortiGateAPI("192.0.2.1", "t").base, "https://192.0.2.1:443")

    def test_private_files_are_never_world_readable(self):
        tmp = tempfile.mkdtemp()
        old = os.umask(0o022)
        try:
            p = os.path.join(tmp, "map.json")
            with open(p, "w") as fh:
                fh.write("old")
            os.chmod(p, 0o644)
            source.write_private(p, "secret")
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
            with open(p) as fh:
                self.assertEqual(fh.read(), "secret")
            path = source.save_snapshot({"device": {"hostname": "fw"}}, tmp)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        finally:
            os.umask(old)
            shutil.rmtree(tmp)

    def test_snapshot_names_are_utc(self):
        import datetime as _dt
        tmp = tempfile.mkdtemp()
        try:
            path = source.save_snapshot({"device": {"hostname": "fw"}}, tmp)
            age = time.time() - source._stamp_epoch(path)
            self.assertLess(abs(age), 5)
            now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d")
            self.assertTrue(os.path.basename(path).startswith(now))
        finally:
            shutil.rmtree(tmp)

    def test_redacted_ips_stay_plain_and_unique(self):
        from rulescope.redact import _IPs
        ips = _IPs("203.0.113.", "198.18.")
        out = [ips(f"10.0.{i // 250}.{i % 250}") for i in range(600)]
        self.assertEqual(len(set(out)), 600)
        self.assertTrue(all("/" not in o for o in out))
        self.assertEqual((out[0], out[253], out[254], out[507]), ("203.0.113.1", "203.0.113.254", "198.18.0.1",
                                                                  "198.18.0.254"))
        self.assertEqual(out[508], "198.18.1.1")

    def test_exposure_policyid_is_escaped(self):
        # policy IDs are integers after parsing; the escape is defence in depth for any non-numeric ID
        evil = '9"><script>alert(1)</script>'
        snap = model.from_config(load_sample())
        res = checks.analyze(snap)
        row = next(x for x in res["exposure"] if x.get("policyid") is not None)
        row["policyid"] = evil
        res["exposure"] = [row]
        html = report.html_report(res, snap)
        self.assertNotIn("<script>alert(1)", html)
        self.assertIn("#9&quot;&gt;&lt;script&gt;alert(1)", html)

    def test_syslog_is_one_line_and_supports_ipv6(self):
        import socket
        from rulescope import notify
        for fam, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            try:
                srv = socket.socket(fam, socket.SOCK_DGRAM)
                srv.bind((host, 0))
            except OSError:
                continue  # no IPv6 on this machine
            srv.settimeout(5)
            port = srv.getsockname()[1]
            target = f"[{host}]:{port}" if fam == socket.AF_INET6 else f"{host}:{port}"
            notify.syslog(target, "fw\n1", ['rule "a"\r\nfake line'])
            msg = srv.recv(4096).decode()
            srv.close()
            self.assertNotIn("\n", msg)
            self.assertNotIn("\r", msg)
            self.assertIn("alert=\"rule 'a'  fake line\"", msg)


if __name__ == "__main__":
    unittest.main()
