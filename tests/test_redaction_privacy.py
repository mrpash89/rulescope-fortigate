import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rulescope import checks, cli, model, report, usage
from rulescope.redact import redact


SAMPLE = Path(__file__).with_name("sample.conf")


class RedactionPrivacyTests(unittest.TestCase):
    def snapshot(self):
        snap = model.from_config(SAMPLE.read_text())
        snap["device"]["vdom"] = "SYNTHETIC_CUSTOM_VDOM"
        for iface in snap["interfaces"].values():
            iface["vdom"] = "SYNTHETIC_CUSTOM_VDOM"
        for name in ("SYNTHETIC_OBJECT_A", "SYNTHETIC_OBJECT_B"):
            snap["addresses"][name] = model._address(name, {"subnet": "192.0.2.10 255.255.255.255"})
        for p in snap["policies"]:
            for direction in ("internet-service", "internet-service-src"):
                p[direction] = "enable"
                p[direction + "-name"] = ["Microsoft-Office365"]
                p[direction + "-id"] = ["12345"]
                for kind in ("group", "custom", "custom-group"):
                    p[direction + "-" + kind] = ["SYNTHETIC_ISDB_" + kind]
        usage.apply(snap, {}, "SYNTHETIC_USAGE.csv")
        return snap

    def test_identifiers_removed_from_every_report_format(self):
        snap = self.snapshot()
        original = copy.deepcopy(snap)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "snapshot.json"
            source.write_text(json.dumps(snap))
            mapping = root / "mapping.json"
            output = io.StringIO()
            args = ["analyze", str(source), "--advisories", "off", "--redact", "--redact-map", str(mapping)]
            paths = []
            for option, suffix in (("--html", "html"), ("--json", "json"), ("--csv", "csv"),
                                   ("--practices-csv", "practices.csv"), ("--cli", "txt")):
                path = root / ("report." + suffix)
                args.extend([option, str(path)])
                paths.append(path)
            with contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(args), 0)
            text = output.getvalue() + "".join(path.read_text() for path in paths)
            self.assertNotIn("SYNTHETIC_", text)
            self.assertIn("Microsoft-Office365", text)
            self.assertIn("SYNTHETIC_CUSTOM_VDOM", mapping.read_text())
            if os.name != "nt":  # Windows has no POSIX permission bits; files inherit the folder's ACL
                self.assertEqual(os.stat(mapping).st_mode & 0o777, 0o600)
        red, _ = redact(snap)
        self.assertNotIn("SYNTHETIC_CUSTOM_VDOM", json.dumps(red))
        self.assertNotIn("SYNTHETIC_ISDB", json.dumps(red))
        self.assertEqual(snap, original)
        self.assertEqual(checks.analyze(snap)["score"], checks.analyze(red)["score"])
        self.assertEqual(red["policies"][0]["internet-service-src-id"], ["12345"])
        self.assertIn("unknown", " ".join(red["notes"]))

    def test_findings_baseline_rejected_before_any_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snap = self.snapshot()
            source, baseline = root / "snapshot.json", root / "baseline.json"
            source.write_text(json.dumps(snap))
            baseline.write_text(json.dumps(checks.analyze(snap)))
            args = ["analyze", str(source), "--redact", "--baseline", str(baseline), "--advisories", "off"]
            for option in ("--json", "--html", "--csv", "--practices-csv", "--cli", "--redact-map"):
                args.extend([option, str(root / option[2:])])
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(SystemExit, "snapshot baseline"):
                cli.main(args)
            self.assertEqual(set(root.iterdir()), {source, baseline})

    def test_redact_save_snapshot_rejected_before_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(cli, "_snapshot_from_args", side_effect=AssertionError("must not collect")):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    cli.main(["audit", "--config", str(SAMPLE), "--redact", "--save-snapshot", tmp])
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_reordered_snapshot_baseline_preserves_identity(self):
        before = self.snapshot()
        after = copy.deepcopy(before)
        for key in ("addresses", "services", "interfaces", "admins", "vips"):
            after[key] = dict(reversed(list(after[key].items())))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, baseline, output = (root / name for name in ("snapshot.json", "baseline.json", "report.json"))
            source.write_text(json.dumps(after))
            baseline.write_text(json.dumps(before))
            with contextlib.redirect_stdout(io.StringIO()):
                cli.main(["analyze", str(source), "--redact", "--baseline", str(baseline),
                          "--advisories", "off", "--json", str(output)])
            result = json.loads(output.read_text())
            self.assertEqual(result["comparison"]["new"], [])
            self.assertEqual(result["comparison"]["resolved"], [])
            self.assertNotIn("SYNTHETIC_", output.read_text())

    def test_shared_mapping_keeps_new_and_removed_names_distinct(self):
        before = self.snapshot()
        after = copy.deepcopy(before)
        del after["addresses"]["SYNTHETIC_OBJECT_A"]
        after["addresses"]["SYNTHETIC_OBJECT_C"] = model._address(
            "SYNTHETIC_OBJECT_C", {"subnet": "192.0.2.11 255.255.255.255"})
        red_after, mapping = redact(after)
        red_before, mapping = redact(before, mapping)
        result = checks.analyze(red_after, baseline=red_before)
        self.assertIn(mapping["addresses"]["SYNTHETIC_OBJECT_A"],
                      [f["object"] for f in result["comparison"]["resolved"]])
        self.assertIn(mapping["addresses"]["SYNTHETIC_OBJECT_C"],
                      [f["object"] for f in result["comparison"]["new"]])
        for name in set(before["vips"]) & set(after["vips"]):
            key = mapping["addresses"][name]
            self.assertEqual(red_before["vips"][key]["extip"], red_after["vips"][key]["extip"])

    def test_unredacted_findings_baseline_remains_supported(self):
        snap = self.snapshot()
        result = checks.analyze(snap, baseline=checks.analyze(snap))
        self.assertEqual(result["comparison"]["new"], [])
        self.assertEqual(result["comparison"]["resolved"], [])
        self.assertIn("SYNTHETIC_CUSTOM_VDOM", report.html_report(result, snap))

    def test_previous_usage_import_filenames_are_also_removed(self):
        snap = self.snapshot()
        usage.apply(snap, {}, "SYNTHETIC_SECOND: usage.csv")
        red, _ = redact(snap)
        text = json.dumps(checks.analyze(red))
        self.assertNotIn("SYNTHETIC_USAGE.csv", text)
        self.assertNotIn("SYNTHETIC_SECOND", text)
        self.assertEqual(sum("Usage imported from redacted:" in n for n in red["notes"]), 2)
        self.assertIn("unknown", " ".join(red["notes"]))

    def test_custom_isdb_classification_survives_aliasing(self):
        for kind in ("group", "custom", "custom-group"):
            for value in ("SYNTHETIC-malicious-sources", "SYNTHETIC-scanner-list", "SYNTHETIC-Tor-nodes",
                          "SYNTHETIC-botnet-list", "SYNTHETIC-ordinary-list"):
                with self.subTest(kind=kind, value=value):
                    snap = model.from_config(SAMPLE.read_text())
                    snap["policies"].insert(0, model._policy(5, {
                        "srcintf": ["wan1", "wan2"], "dstintf": ["any"], "action": "deny",
                        "status": "enable", "schedule": "always", "internet-service-src": "enable",
                        "internet-service-src-" + kind: [value], "dstaddr": ["all"],
                        "service": ["ALL"], "logtraffic": "all", "name": "synthetic-deny"}))
                    before = checks.analyze(snap)
                    red, _ = redact(snap)
                    after = checks.analyze(red)
                    key = lambda r: [(f["check"], f["policyid"], f["severity"]) for f in r["findings"]]
                    self.assertEqual(key(before), key(after))
                    self.assertEqual(before["score"], after["score"])
                    self.assertNotIn(value, json.dumps(after))


if __name__ == "__main__":
    unittest.main()
