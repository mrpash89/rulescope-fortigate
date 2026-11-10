"""Synthetic regression cases for the shared FortiOS script export."""
import copy
import re
import unittest
import unicodedata
from html import unescape

from rulescope import checks, fgtconf, model, report
from rulescope.catalog import finding, q


GLOBAL = ["config system global", "    set strong-crypto enable", "end"]
VDOM = ["config firewall policy", "    edit 7", "        set logtraffic all", "    next", "end"]
CONTROLS = tuple(map(chr, range(32))) + tuple(map(chr, range(127, 160))) + (
    "\u2028", "\u2029", "\u202e", "\ufeff",
)


def result(*findings):
    return {
        "device": {"hostname": "Lab", "model": "FGT60F", "version": "v7.4.3",
                   "vdom": "root", "multi_vdom": False},
        "collected_at": "2026-01-01T00:00:00Z", "findings": list(findings),
    }


def active(script):
    return [line for line in script.splitlines() if line.strip() and not line.startswith("#")]


class RemediationSafetyTests(unittest.TestCase):
    def test_metadata_and_detail_physical_lines_remain_comments(self):
        payload = "name\r\nexecute date\rget system status\nend\u0085next\u2028config global\u2029end"
        for field in ("hostname", "model", "version", "vdom", "collected_at", "title", "detail"):
            with self.subTest(field=field):
                res = result(finding("WEAK_CRYPTO", detail="Normal detail", cli=GLOBAL, cli_scope="global"))
                title = "remediation"
                if field == "title":
                    title = payload
                elif field == "detail":
                    res["findings"][0]["detail"] = payload
                elif field == "collected_at":
                    res[field] = payload
                else:
                    res["device"][field] = payload
                script = report.remediation_cli(res, title=title)
                self.assertEqual(active(script), GLOBAL)
                self.assertIn("execute date", script)
                self.assertNotIn("\r", script)

    def test_comment_controls_are_printable(self):
        res = result(finding("WEAK_CRYPTO", detail="a" + "".join(CONTROLS) + "b", cli=GLOBAL))
        res["device"]["hostname"] = res["findings"][0]["detail"]
        script = report.remediation_cli(res)
        self.assertEqual(active(script), GLOBAL)
        self.assertFalse(any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp")
                             for c in script if c != "\n"))

    def test_command_controls_withhold_whole_safe_and_disabled_blocks(self):
        failures = []
        for control in CONTROLS:
            for safe in (True, False):
                bad = ["config firewall address", '    edit "bad' + control + 'name"',
                       "        set comment should-be-withheld", "    next", "end"]
                res = result(finding("UNUSED_OBJECT", detail="Bad object", cli=bad, cli_safe=safe),
                             finding("WEAK_CRYPTO", cli=GLOBAL, cli_scope="global"))
                script = report.remediation_cli(res)
                if (active(script) != GLOBAL or "should-be-withheld" in script
                        or "config firewall address" in script or "withheld" not in script.lower()):
                    failures.append((repr(control), safe))
                res["device"]["multi_vdom"] = True
                script = report.remediation_cli(res, safe_only=safe)
                if (active(script) != ["config global"] + GLOBAL + ["end"]
                        or "config vdom" in script or "should-be-withheld" in script):
                    failures.append((repr(control), safe, "multi_vdom"))
        self.assertEqual(failures, [])

    def test_valid_quoted_vdom_and_object_names_round_trip(self):
        for name in ('branch office', 'branch "quoted"', r"branch\path", "Tāmaki-אבג"):
            with self.subTest(name=name):
                commands = ["config firewall address", f"    edit {q(name)}",
                            '        set comment "ordinary"', "    next", "end"]
                res = result(finding("UNUSED_OBJECT", detail=name, cli=commands),
                             finding("WEAK_CRYPTO", cli=GLOBAL, cli_scope="global"))
                res["device"].update(vdom=name, multi_vdom=True)
                script = report.remediation_cli(res)
                self.assertIn("config vdom\nedit " + q(name) + "\n", script)
                parsed = fgtconf.parse(script)
                self.assertEqual(parsed.sub("global").sub("system global").get("strong-crypto"), "enable")
                self.assertEqual(parsed.sub("vdom").entries[name].sub("firewall address").entries[name].get("comment"),
                                 "ordinary")

    def test_invalid_vdom_withholds_scoped_commands_and_keeps_global(self):
        failures = []
        for name in (None, "", "   ") + tuple("root" + c + "other" for c in CONTROLS):
            res = result(finding("NO_LOG", cli=VDOM),
                         finding("WEAK_CRYPTO", cli=GLOBAL, cli_scope="global"))
            res["device"].update(vdom=name, multi_vdom=True)
            script = report.remediation_cli(res)
            if (active(script) != ["config global"] + GLOBAL + ["end"]
                    or "set logtraffic" in script or "withheld" not in script.lower()):
                failures.append(repr(name))
        self.assertEqual(failures, [])

    def test_ordinary_disabled_blocks_and_filters_are_preserved(self):
        res = result(finding("NO_LOG", detail="Policy 7", cli=VDOM, cli_safe=False),
                     finding("WEAK_CRYPTO", cli=GLOBAL, cli_scope="global"))
        script = report.remediation_cli(res)
        self.assertIn("\n".join("# " + line for line in VDOM), script)
        self.assertEqual(active(script), GLOBAL)
        quick = report.remediation_cli(res, only={"NO_LOG"}, safe_only=True, title="quick wins")
        self.assertEqual(active(quick), [])
        self.assertIn("# No remediation commands generated.", quick)

    def test_multiline_parser_values_survive_but_commands_are_withheld(self):
        name = "wan\nexecute date"
        text = ('config system global\nset hostname "Lab\nget system status"\nend\n'
                'config system interface\nedit ' + q(name) + '\nset allowaccess ping http\nnext\nend\n')
        snap = model.from_config(text)
        self.assertEqual(snap["device"]["hostname"], "Lab\nget system status")
        self.assertIn(name, snap["interfaces"])
        script = report.remediation_cli(checks.analyze(snap))
        self.assertNotIn("get system status", active(script))
        self.assertNotIn("config system interface", script)
        self.assertNotIn("set allowaccess", script)
        self.assertIn("withheld", script.lower())

    def test_html_and_quick_win_scripts_share_protection(self):
        snap = model.from_config('config system global\nset strong-crypto disable\nend\n')
        res = checks.analyze(snap)
        bad = finding("NO_LOG", policyid=7, detail="Policy\nexecute date",
                      cli=["config firewall policy", "    edit 7\nend", "        set logtraffic all", "end"])
        res["findings"].append(bad)
        res["quick_wins"] = checks.quick_wins(res["findings"])
        before = copy.deepcopy(res)
        for name, multi in (("root", False), ("root\rnext", True)):
            with self.subTest(name=name):
                res["device"].update(vdom=name, multi_vdom=multi)
                html = report.html_report(res, snap)
                scripts = [unescape(s) for s in re.findall(r"<pre>(.*?)</pre>", html, re.DOTALL)]
                self.assertGreaterEqual(len(scripts), 2)
                for script in scripts:
                    self.assertIn("set strong-crypto enable", script)
                    self.assertNotIn("config firewall policy", script)
                    self.assertNotIn("set logtraffic", script)
                    self.assertNotIn("execute date", active(script))
                    self.assertIn("withheld", script.lower())
        res["device"] = before["device"]
        self.assertEqual(res, before)


if __name__ == "__main__":
    unittest.main()
