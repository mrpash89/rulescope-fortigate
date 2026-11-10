"""Pseudonymize a snapshot so reports can be shared (sales samples, support, second opinions).

Every custom name (objects, interfaces, zones, users, schedules, profiles, rules), the
hostname, serial and published IPs are replaced consistently. Factory-default names and
generic port names (port1, wan1, ...) are kept so findings stay readable. Redaction runs
before analysis, so the findings are identical to an unredacted run; address values stay
in memory for the coverage math but are never printed.
"""
from __future__ import annotations

import copy
import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from . import defaults
from .hardening import isdb_source_is_known_bad

_PHYS = re.compile(r"^(port\d+|wan\d*|lan\d*|internal\d*|dmz\d*|mgmt\d*|ha\d*|x\d+|[ab]|fortilink|"
                   r"npu\d+_vlink\d+|s\d+|vw\d+|modem|loopback\d*|ssl\.root|any)$", re.I)
_DEFAULT_PROFILES = {"default", "certificate-inspection", "deep-inspection", "no-inspection", "custom-deep-inspection",
                     "g-default", "wifi-default", "monitor-all", "sniffer-profile", "high_security", "protect_client",
                     "protect_http_server", "protect_email_server", "all_default", "all_default_pass",
                     "default_no_exe", "block-high-risk"}


class _NS:
    def __init__(self, prefixes: Dict[str, str], default: str, keep: Set[str],
                 mapping: Optional[Dict[str, str]] = None):
        self.prefixes, self.default, self.keep = prefixes, default, keep
        self.map: Dict[str, str] = dict(mapping or {})
        self.count: Counter = Counter()
        for alias in self.map.values():
            prefix, _, number = alias.rpartition("-")
            self.count[prefix] = max(self.count[prefix], int(number))

    def __call__(self, name: Optional[str]) -> Optional[str]:
        if not name:
            return name
        m = self.map.get(name)
        if m is None and name in self.keep:
            return name
        if m is None:
            pre = self.prefixes.get(name, self.default)
            self.count[pre] += 1
            m = self.map[name] = f"{pre}-{self.count[pre]:02d}"
        return m

    def many(self, names: Iterable[str]) -> List[str]:
        return [self(n) for n in names]


class _IPs:
    """Stand-in addresses: the first 254 from `base` (a /24 prefix such as "203.0.113."), the rest from
    `overflow` (a /16 prefix such as "198.18."), so every pseudonym is a distinct plain host address."""

    def __init__(self, base: str, overflow: str, mapping: Optional[Dict[str, str]] = None):
        self.base, self.overflow = base, overflow
        self.map = dict(mapping or {})
        self.n = len(self.map)

    def __call__(self, ip: str) -> str:
        if not ip:
            return ip
        if ip not in self.map:
            self.n += 1
            if self.n <= 254:
                self.map[ip] = f"{self.base}{self.n}"
            else:
                m = self.n - 255
                if m >= 256 * 254:
                    raise ValueError("more distinct addresses than the redaction ranges can hold")
                self.map[ip] = f"{self.overflow}{m // 254}.{m % 254 + 1}"
        return self.map[ip]


def redact(snap: Dict[str, Any], mapping: Optional[Dict[str, Dict[str, str]]] = None
           ) -> Tuple[Dict[str, Any], Dict[str, Dict[str, str]]]:
    """Redact a snapshot, optionally extending a prior snapshot's pseudonym mapping."""
    prior = mapping or {}
    s = copy.deepcopy(snap)
    A = _NS({**{n: "ADDR" for n in s["addresses"]}, **{n: "ADDRGRP" for n in s["addrgrps"]},
             **{n: "VIP" for n in s["vips"]}, **{n: "VIPGRP" for n in s["vipgrps"]}}, "OBJ",
            defaults.DEFAULT_ADDRESSES | defaults.DEFAULT_ADDRGRPS | {"all", "none"}, prior.get("addresses"))
    S = _NS({**{n: "SVC" for n in s["services"]}, **{n: "SVCGRP" for n in s["servicegrps"]}}, "SVC",
            defaults.DEFAULT_SERVICES | defaults.DEFAULT_SERVICEGRPS, prior.get("services"))
    ifkeep = {n for n in s["interfaces"] if _PHYS.match(n)} | {"any", "ssl.root", "virtual-wan-link"}
    I = _NS({**{n: "ZONE" for n in s["zones"]}, **{n: "SDWAN" for n in s["sdwan_zones"]},
             **{n: "VPN" for n in s.get("ipsec_p1", {})},
             **{n: "VPN" for n, i in s["interfaces"].items() if i.get("type") == "tunnel"}}, "IF", ifkeep,
            prior.get("interfaces"))
    U = _NS({**{n: "ADMIN" for n in (s.get("admins") or {})}, **{n: "API" for n in (s.get("api_users") or {})}},
            "USERGRP", {"admin"}, prior.get("users"))
    T = _NS({}, "SCHED", {"always", "none"}, prior.get("schedules"))
    P = _NS({}, "PROFILE", _DEFAULT_PROFILES, prior.get("profiles"))
    P2 = _NS({}, "P2", set(), prior.get("phase2"))
    POOL = _NS({}, "POOL", set(), prior.get("pools"))
    VDOM = _NS({}, "VDOM", {"root"}, prior.get("vdoms"))
    ISDB = _NS({}, "ISDB", set(), prior.get("internet_services"))
    # documentation ranges first, then the benchmarking range 198.18.0.0/15 (one /16 each)
    EXT = _IPs("203.0.113.", "198.18.", prior.get("external_ips"))
    MAPPED = _IPs("10.255.0.", "10.254.", prior.get("mapped_ips"))
    PEER = _IPs("198.51.100.", "198.19.", prior.get("vpn_peers"))

    s["device"]["hostname"] = "FIREWALL"
    s["device"]["serial"] = ""
    s["device"]["vdom"] = VDOM(s["device"].get("vdom"))
    usage_source = s.get("usage_source") or ""
    if usage_source.startswith("import:"):
        s["usage_source"] = "import:redacted"
    # A snapshot can contain notes from several imports, not just its latest usage source.
    s["notes"] = ["Usage imported from redacted: " + note.rsplit(": ", 1)[-1]
                  if note.startswith("Usage imported from ") else note for note in s.get("notes", [])]
    for p in s["policies"]:
        p["_redacted_isdb_bad_source"] = isdb_source_is_known_bad(p)
        p["srcintf"], p["dstintf"] = I.many(p["srcintf"]), I.many(p["dstintf"])
        for f in ("srcaddr", "dstaddr", "srcaddr6", "dstaddr6"):
            p[f] = A.many(p[f])
        p["service"] = S.many(p["service"])
        for direction in ("internet-service", "internet-service-src"):
            for kind in ("group", "custom", "custom-group"):
                field = direction + "-" + kind
                p[field] = ISDB.many(p.get(field, []))
        for f in ("users", "groups", "fsso-groups"):
            p[f] = U.many(p[f])
        p["poolname"] = POOL.many(p["poolname"])
        p["schedule"] = T(p["schedule"])
        if p["name"]:
            p["name"] = f"rule-{p['policyid']}"
        p["comments"] = ""
        for f in ("ssl-ssh-profile", "av-profile", "webfilter-profile", "dnsfilter-profile", "ips-sensor",
                  "application-list", "emailfilter-profile", "file-filter-profile", "profile-group"):
            p[f] = P(p.get(f))

    s["addresses"] = {A(n): dict(v, name=A(n), comment="", fqdn="redacted.invalid" if v.get("fqdn") else "")
                      for n, v in s["addresses"].items()}
    s["addrgrps"] = {A(n): dict(v, name=A(n), comment="", member=A.many(v["member"]),
                                **{"exclude-member": A.many(v.get("exclude-member", []))}) for n, v in s["addrgrps"].items()}
    s["services"] = {S(n): dict(v, name=S(n), comment="", fqdn="redacted.invalid" if v.get("fqdn") else "")
                     for n, v in s["services"].items()}
    s["servicegrps"] = {S(n): dict(v, name=S(n), comment="", member=S.many(v["member"])) for n, v in s["servicegrps"].items()}
    s["vips"] = {A(n): dict(v, name=A(n), comment="", extip=EXT(v.get("extip", "")), extintf=I(v.get("extintf")),
                            mappedip=[MAPPED(m) for m in v.get("mappedip", [])]) for n, v in s["vips"].items()}
    s["vipgrps"] = {A(n): A.many(m) for n, m in s["vipgrps"].items()}
    s["zones"] = {I(n): I.many(m) for n, m in s["zones"].items()}
    s["sdwan_zones"] = {I(n): I.many(m) for n, m in s["sdwan_zones"].items()}
    s["interfaces"] = {I(n): dict(v, name=I(n), alias="", ip="0.0.0.0 0.0.0.0", vdom=VDOM(v.get("vdom")))
                       for n, v in s["interfaces"].items()}
    sch = s.get("schedules") or {"onetime": {}, "groups": {}}
    s["schedules"] = {"onetime": {T(n): dict(v, name=T(n)) for n, v in sch.get("onetime", {}).items()},
                      "groups": {T(n): T.many(m) for n, m in sch.get("groups", {}).items()}}
    if s.get("sslvpn"):
        s["sslvpn"] = dict(s["sslvpn"], source_interface=I.many(s["sslvpn"]["source_interface"]),
                           source_address=A.many(s["sslvpn"]["source_address"]))
    s["ipsec_p1"] = {I(n): dict(v, name=I(n), interface=I(v.get("interface")), remote_gw=PEER(v.get("remote_gw", "")))
                     for n, v in s.get("ipsec_p1", {}).items()}
    s["ipsec_p2"] = {P2(n): dict(v, name=P2(n), phase1name=I(v.get("phase1name"))) for n, v in s.get("ipsec_p2", {}).items()}
    s["local_in"] = [dict(li, intf=I.many(li["intf"]), srcaddr=A.many(li["srcaddr"]), dstaddr=A.many(li["dstaddr"]),
                          service=S.many(li["service"])) for li in s.get("local_in", [])]
    s["default_routes"] = [dict(r, device=I(r.get("device")), sdwan_zone=I.many(r.get("sdwan_zone", [])))
                           for r in s.get("default_routes", [])]
    if s.get("admins") is not None:
        s["admins"] = {U(n): dict(v, name=U(n), trusthosts=["redacted"] * len(v["trusthosts"])) for n, v in s["admins"].items()}
    if s.get("api_users") is not None:
        s["api_users"] = {U(n): dict(v, name=U(n), trusthosts=["redacted"] * len(v["trusthosts"]))
                          for n, v in s["api_users"].items()}
    if s.get("references") is not None:
        objs = set(snap["addresses"]) | set(snap["addrgrps"]) | set(snap["vips"]) | set(snap["vipgrps"])
        s["references"] = {(A(k) if k in objs else S(k)): v for k, v in s["references"].items()}
    CERT = _NS({}, "CERT", {"", "Fortinet_Factory", "Fortinet_Factory_Backup", "self-sign", "Fortinet_SSL",
                            "Fortinet_GUI_Server"}, prior.get("certificates"))
    ACC = _NS({}, "ACCPROFILE", {"super_admin", "super_admin_readonly", "prof_admin", "", None},
              prior.get("admin_profiles"))
    MISC = _NS({}, "NAME", {"full-access", "tunnel-access", "web-access"}, prior.get("other_names"))
    for coll in ("admins", "api_users"):
        for v in (s.get(coll) or {}).values():
            v["accprofile"] = ACC(v.get("accprofile"))
    if s.get("accprofiles") is not None:
        s["accprofiles"] = {ACC(n): v for n, v in s["accprofiles"].items()}
    if s.get("sslvpn") and "servercert" in s["sslvpn"]:
        s["sslvpn"]["servercert"] = CERT(s["sslvpn"]["servercert"])
    g = s.get("global") or {}
    if g.get("admin-server-cert"):
        g["admin-server-cert"] = CERT(g["admin-server-cert"])
    st = s.get("settings") or {}
    if st.get("ldap") is not None:
        st["ldap"] = {MISC(n): v for n, v in st["ldap"].items()}
    if st.get("snmp_users") is not None:
        st["snmp_users"] = [dict(u, name=MISC(u.get("name"))) for u in st["snmp_users"]]
    if st.get("zones") is not None:
        st["zones"] = {I(n): v for n, v in st["zones"].items()}
    if st.get("ssl_portals") is not None:
        st["ssl_portals"] = {MISC(n): v for n, v in st["ssl_portals"].items()}
    if st.get("ha"):
        st["ha"] = dict(st["ha"], monitor=" ".join(I.many((st["ha"].get("monitor") or "").split())),
                        mgmt_interfaces=I.many(st["ha"].get("mgmt_interfaces") or []))
    if st.get("dns"):
        st["dns"] = dict(st["dns"], primary="redacted" if st["dns"].get("primary") else "",
                         secondary="redacted" if st["dns"].get("secondary") else "")
    prof = s.get("profiles")
    if prof:
        s["profiles"] = {
            "ips": None if prof.get("ips") is None else {P(n): v for n, v in prof["ips"].items()},
            "dnsfilter": None if prof.get("dnsfilter") is None else {P(n): v for n, v in prof["dnsfilter"].items()},
            "groups": None if prof.get("groups") is None else {P(n): {k: P(x) for k, x in v.items()} for n, v in prof["groups"].items()},
        }
    s["change_log"] = None
    if s.get("wan_override"):
        s["wan_override"] = I.many(s["wan_override"])
    s["wan_exclude"] = I.many(s.get("wan_exclude") or [])
    mapping = {"addresses": A.map, "services": S.map, "interfaces": I.map, "users": U.map, "schedules": T.map,
               "profiles": P.map, "phase2": P2.map, "pools": POOL.map, "external_ips": EXT.map,
               "mapped_ips": MAPPED.map, "vpn_peers": PEER.map, "certificates": CERT.map, "admin_profiles": ACC.map,
               "other_names": MISC.map, "vdoms": VDOM.map, "internet_services": ISDB.map,
               "hostname": {**prior.get("hostname", {}), snap["device"].get("hostname", ""): "FIREWALL"}}
    return s, mapping
