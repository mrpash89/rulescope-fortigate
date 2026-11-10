import copy
import json
import os
import tempfile
import unittest
from html import escape

from rulescope import checks, model, report, source


class SnapshotPolicyIDTests(unittest.TestCase):
    def snapshot(self, schema=model.SCHEMA, status="enable"):
        snap = model.empty_snapshot("config")
        snap["schema"] = schema
        snap["policies"] = [model._policy(7, {"status": status, "logtraffic": "all"})]
        snap["local_in"] = [model._local_in(9, {})]
        snap["hits"] = {"7": {"hit_count": 1234, "bytes": 0, "last_used": 0, "first_used": 0}}
        return snap

    def load(self, snap):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "snapshot.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(snap, fh)
            return source.load_snapshot(path)

    def test_invalid_ids_are_rejected_in_all_supported_schemas(self):
        for schema in range(1, model.SCHEMA + 1):
            for collection in ("policies", "local_in"):
                for value in (True, False, 7.5, 7.0, "7", "invalid", None, [], {}):
                    with self.subTest(schema=schema, collection=collection, value=value):
                        snap = self.snapshot(schema)
                        snap[collection][0]["policyid"] = value
                        with self.assertRaisesRegex(ValueError, rf"{collection}\[0\]\.policyid.*integer"):
                            self.load(snap)

    def test_disabled_single_policy_payload_is_rejected_before_reporting(self):
        for schema in range(1, model.SCHEMA + 1):
            with self.subTest(schema=schema):
                snap = self.snapshot(schema, status="disable")
                snap["policies"][0]["policyid"] = '7"><script>alert(1)</script>'
                with self.assertRaisesRegex(ValueError, r"policies\[0\]\.policyid.*integer"):
                    loaded = self.load(snap)
                    report.html_report(checks.analyze(loaded), loaded)

    def test_valid_ids_and_hit_keys_survive_load_analysis_and_report(self):
        for schema in range(1, model.SCHEMA + 1):
            for status in ("enable", "disable"):
                with self.subTest(schema=schema, status=status):
                    snap = self.snapshot(schema, status)
                    loaded = self.load(snap)
                    self.assertEqual(loaded["schema"], model.SCHEMA)
                    self.assertEqual(loaded["policies"][0]["policyid"], 7)
                    self.assertEqual(loaded["local_in"], snap["local_in"])
                    self.assertIs(type(loaded["policies"][0]["policyid"]), int)
                    self.assertEqual(loaded["hits"], snap["hits"])
                    html = report.html_report(checks.analyze(loaded), loaded)
                    self.assertIn('id="inv-7"', html)
                    self.assertIn('<td class="num">7</td>', html)
                    self.assertIn('<td class="num">1,234</td>', html)

    def test_legacy_missing_collections_and_vips_still_upgrade(self):
        for schema in (1, 2):
            with self.subTest(schema=schema):
                snap = self.snapshot(schema)
                del snap["local_in"]
                del snap["settings"]
                snap["vips"] = ["synthetic-vip"]
                loaded = self.load(snap)
                self.assertEqual(loaded["local_in"], [])
                self.assertEqual(loaded["settings"], {})
                self.assertIn("synthetic-vip", loaded["vips"])
                report.html_report(checks.analyze(loaded), loaded)

    def test_inventory_escapes_id_when_snapshot_loading_is_bypassed(self):
        snap = self.snapshot(status="disable")
        result = checks.analyze(snap)
        for value in ('7"><script>alert(1)</script>', "7' onmouseover='alert(1)"):
            with self.subTest(value=value):
                direct = copy.deepcopy(snap)
                direct["policies"][0]["policyid"] = value
                html = report.html_report(result, direct)
                self.assertIn(f'id="inv-{escape(value)}"', html)
                self.assertIn(f'<td class="num">{escape(value)}</td>', html)
                self.assertNotIn(value, html)


if __name__ == "__main__":
    unittest.main()
