"""Synthetic regression cases for unsupported policy matching (upstream issue #5)."""
import copy
import unittest

from rulescope import checks, diff, model, report
from rulescope.resolve import Resolver

COVERAGE = {"REDUNDANT", "SHADOW_CONFLICT", "SHADOW_DEAD"}
MATCH_CHECKS = COVERAGE | {"ANY_ANY", "OUTBOUND_UNRESTRICTED", "SERVICE_ALL"}
CRITERIA = {
    "ztna-status": "enable", "ztna-ems-tag": "SYNTHETIC_TAG",
    "ztna-ems-tag-secondary": "SECONDARY_TAG", "ztna-geo-tag": "SYNTHETIC_GEO",
    "internet-service6": "enable", "internet-service6-src": "enable",
    "internet-service6-name": "SYNTHETIC_SERVICE", "internet-service6-group": "SYNTHETIC_GROUP",
    "internet-service6-custom": "SYNTHETIC_CUSTOM", "internet-service6-custom-group": "SYNTHETIC_CUSTOM_GROUP",
    "internet-service6-id": "123", "internet-service6-src-name": "SYNTHETIC_SERVICE",
    "internet-service6-src-group": "SYNTHETIC_GROUP", "internet-service6-src-custom": "SYNTHETIC_CUSTOM",
    "internet-service6-src-custom-group": "SYNTHETIC_CUSTOM_GROUP", "internet-service6-src-id": "123",
    "src-vendor-mac": "1234",
}


def config(extra="", restricted=1, actions=("accept", "accept")):
    policies = []
    for pid, action in enumerate(actions, 1):
        policies.append(f'''edit {pid}
set srcintf "port1"
set dstintf "port2"
set srcaddr "all"
set dstaddr "all"
set service "ALL"
set schedule "always"
set action {action}
set logtraffic disable
{extra if pid == restricted else ""}
next''')
    return "config firewall policy\n" + "\n".join(policies) + "\nend\n"


def coverage(result):
    return [f for f in result["findings"] if f["check"] in COVERAGE]


class PolicyCoverageTests(unittest.TestCase):
    def test_unrestricted_control(self):
        snap = model.from_config(config())
        self.assertEqual(snap["schema"], 4)
        self.assertEqual(snap["policies"][0]["unsupported_match"], [])
        result = checks.analyze(snap)
        self.assertEqual([(f["check"], f["policyid"]) for f in coverage(result)], [("REDUNDANT", 2)])
        self.assertTrue(result["policy_coverage_complete"])
        self.assertEqual(result["cleanup"]["policies"], 1)

    def test_unsupported_criteria_on_either_policy(self):
        for field, value in CRITERIA.items():
            for restricted in (1, 2):
                for actions in (("accept", "accept"), ("accept", "deny"), ("deny", "accept")):
                    with self.subTest(field=field, restricted=restricted, actions=actions):
                        snap = model.from_config(config(f'set {field} "{value}"', restricted, actions))
                        self.assertEqual(snap["policies"][restricted - 1]["unsupported_match"], [field])
                        result = checks.analyze(snap)
                        self.assertEqual(coverage(result), [])
                        self.assertFalse(result["policy_coverage_complete"])
                        self.assertFalse(set(result["evaluated"]) & MATCH_CHECKS)
                        self.assertEqual(result["cleanup"]["policies"], 0)
                        self.assertNotIn("set status disable", report.remediation_cli(result))
                        self.assertIn(field, " ".join(result["notes"]))

    def test_disabled_and_empty_defaults(self):
        extra = "\n".join(f"set {field} " + ("disable" if value == "enable" else '""')
                          for field, value in CRITERIA.items())
        snap = model.from_config(config(extra))
        self.assertEqual(snap["policies"][0]["unsupported_match"], [])
        self.assertEqual(len(coverage(checks.analyze(snap))), 1)

    def test_api_uses_shared_normalisation_without_raw_values(self):
        for field, value in CRITERIA.items():
            with self.subTest(field=field):
                key = "id" if field.endswith("-id") or field == "src-vendor-mac" else "name"
                raw = {"policyid": 1, field: value if value == "enable" else [{key: value}]}
                snap = model.from_api({"policy": {"results": [raw]}})
                p = snap["policies"][0]
                self.assertEqual(p["unsupported_match"], [field])
                self.assertNotIn(field, p)
                if value != "enable":
                    self.assertNotIn(value, str(p))

    def test_legacy_upgrades_mark_unknown_even_with_new_metadata(self):
        for schema in (1, 2, 3):
            with self.subTest(schema=schema):
                snap = model.from_config(config())
                snap["schema"] = schema
                snap = model.upgrade(snap)
                self.assertTrue(all(p["unsupported_match"] is None for p in snap["policies"]))
                result = checks.analyze(snap)
                self.assertEqual(coverage(result), [])
                self.assertEqual(result["cleanup"]["policies"], 0)
                self.assertTrue(any(f["check"] == "NO_LOG" for f in result["findings"]))
                self.assertIn("unknown", " ".join(result["notes"]).lower())

    def test_known_pairs_still_checked_when_another_policy_is_unsupported(self):
        snap = model.from_config(config())
        snap["policies"].append(model._policy(3, {"ztna-status": "enable", **snap["policies"][0]}))
        result = checks.analyze(snap)
        self.assertEqual([(f["check"], f["policyid"]) for f in coverage(result)], [("REDUNDANT", 2)])
        self.assertFalse(result["policy_coverage_complete"])

    def test_comparison_omits_unevaluated_coverage_in_both_directions(self):
        complete = checks.analyze(model.from_config(config()))
        incomplete = checks.analyze(model.from_config(config('set ztna-status enable')))
        for now, before in ((complete, incomplete), (incomplete, complete)):
            comp = checks.compare(now, before)
            self.assertFalse(MATCH_CHECKS & {f["check"] for f in comp["new"] + comp["resolved"]})

    def test_old_findings_json_lacks_completeness_even_with_evaluated(self):
        current = checks.analyze(model.from_config(config()))
        for evaluated in (True, False):
            old = copy.deepcopy(current)
            old.pop("policy_coverage_complete")
            old["findings"] = [f for f in old["findings"] if f["check"] not in MATCH_CHECKS]
            if not evaluated:
                old.pop("evaluated")
            for now, before in ((current, old), (old, current)):
                comp = checks.compare(now, before)
                self.assertEqual(comp["new"], [])
                self.assertEqual(comp["resolved"], [])

    def test_empty_evaluated_does_not_fall_back_to_all_checks(self):
        current = checks.analyze(model.from_config(config()))
        before = copy.deepcopy(current)
        before["findings"] = []
        current["evaluated"] = []
        self.assertEqual(checks.compare(current, before)["new"], [])

    def test_schema2_diff_ignores_newly_collected_metadata(self):
        current = model.from_config(config('set ztna-status enable'))
        old = copy.deepcopy(current)
        old["schema"] = 2
        for p in old["policies"]:
            p.pop("unsupported_match", None)
        self.assertTrue(diff.diff_snapshots(old, current)["empty"])

    def test_current_diff_retains_changes_in_unsupported_criteria(self):
        old = model.from_config(config())
        current = model.from_config(config('set ztna-status enable'))
        d = diff.diff_snapshots(old, current)
        self.assertEqual(d["policies"]["modified"][0]["changes"],
                         [("unsupported_match", [], ["ztna-status"])])

    def test_best_practices_do_not_claim_skipped_matches_passed(self):
        snap = model.from_config(config('set ztna-status enable'))
        snap["policies"] = snap["policies"][:1]
        snap["hits"] = {"1": {"hit_count": 1, "last_used": model.iso_epoch(snap["collected_at"])}}
        result = checks.analyze(snap)
        statuses = {p["id"]: p["status"] for p in result["practices"]["items"]}
        self.assertEqual(statuses["BP19"], "unknown")
        self.assertEqual(statuses["BP20"], "unknown")

    def test_disabled_unsupported_policy_does_not_block_enabled_coverage(self):
        snap = model.from_config(config())
        snap["policies"].append(model._policy(3, {"ztna-status": "enable", "status": "disable"}))
        self.assertTrue(checks.analyze(snap)["policy_coverage_complete"])

    def test_index_matches_bruteforce_with_unsupported_and_unknown(self):
        snap = model.from_config(config())
        for pid, criterion in enumerate(CRITERIA, 3):
            snap["policies"].append(model._policy(pid, {**snap["policies"][0], criterion: CRITERIA[criterion]}))
        unknown = copy.deepcopy(snap["policies"][0])
        unknown["unsupported_match"] = None
        snap["policies"].append(unknown)
        matches = [checks._build_match(p, Resolver(snap)) for p in snap["policies"]]
        expected = [None, 0] + [None] * (len(matches) - 2)
        self.assertEqual(checks.first_cover(matches), expected)
        self.assertEqual(checks.first_cover_bruteforce(matches), expected)
