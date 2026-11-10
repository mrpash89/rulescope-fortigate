"""Randomized tests: hostile text in a config must never leave rulescope as something that acts.

The hostile-input tests in test_rulescope.py cover the attacks we thought of. These tests cover the
ones we did not: every round builds a config from random hostile fragments (line breaks of every
kind, control and direction characters, FortiOS statements, spreadsheet formulas, markup, path
tricks, broken quoting) and checks the properties that must hold for any input:

* reading a config never crashes, and no control character survives it
* every active line of a remediation script is a statement rulescope generates
* no CSV cell can run as a spreadsheet formula
* terminal output carries no control characters
* text from the config never becomes an HTML tag or attribute
* snapshots stay inside the folder they are saved to

Standard library only and deterministic: the same seed always produces the same inputs.

    python3 -m unittest tests.test_fuzz                      # the fixed seed used in CI
    RULESCOPE_FUZZ_ROUNDS=5000 python3 -m unittest tests.test_fuzz
    RULESCOPE_FUZZ_SEED=1234 python3 -m unittest tests.test_fuzz    # reproduce a reported failure
"""
import csv
import io
import os
import random
import re
import sys
import tempfile
import unicodedata
import unittest
from html.parser import HTMLParser

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from rulescope import checks, diff, fgtconf, model, report, source  # noqa: E402

SEED = os.environ.get("RULESCOPE_FUZZ_SEED", "rulescope")
ROUNDS = int(os.environ.get("RULESCOPE_FUZZ_ROUNDS", "100"))

ALLOWED = re.compile(r"^\s*(?:config|edit|set|unset|append|next|end|move|delete)(?:\s|$)")
FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "|", "%")

LINE_BREAKS = ["\n", "\r\n", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
CONTROLS = ["\x00", "\x07", "\x08", "\x1b[2J", "\x1b]0;fuzz\x07", "\x7f", "\x9b31m", "\u200e", "\u200f",
            "\u202a", "\u202e", "\u2066", "\u2069", "\ufeff", "\u00ad", "\u200b", "\u061c"]
STATEMENTS = ["end", "next", "execute factoryreset", "execute reboot", "config system global",
              "config firewall policy", "set admin-sport 1", "diagnose sys kill 11 1", "purge",
              "exec backup config tftp x 198.51.100.1", "delete 1", "edit 0", "set status disable",
              "config vdom", "edit root", "get system status", "unset password", "#", "# end"]
FORMULAS = ["=HYPERLINK(\"http://fuzz.example\",\"x\")", "+cmd|' /C calc'!A0", "-2+3", "@SUM(1+1)",
            "\t=1+1", "\r=1+1", "|x", "%x", "=1+1"]
MARKUP = ["<fuzz-tag>", "</td></tr></table><fuzz-tag>", "\" onfuzz=\"1", "' onfuzz='1", "<fuzz-tag onfuzz=1>",
          "</script><fuzz-tag>", "</pre><fuzz-tag>", "javascript:fuzz()", "&lt;fuzz-tag&gt;", "<!--", "-->",
          "</style><fuzz-tag>", "`onfuzz=1`"]
PATHS = ["..", ".", "../..", "../../etc/passwd", "/etc/passwd", "..\\..\\windows", "C:\\x", "~", "a/b",
         "con", "nul", ".hidden", "...", " ", ""]
QUOTING = ["\"", "\\", "\\\"", "\\\\", "\"\"", "'", "\\n", "\" end \"", "\\\n"]
PLAIN = ["all", "ALL", "any", "port1", "wan1", "root", "always", "x", "a b", "Ünïcødé", "אבג", "名前", "0", "-1",
         "65536", "0.0.0.0 0.0.0.0", "10.0.0.0 255.0.0.0", "A" * 300, "enable", "disable", "accept", "deny"]
POOLS = [LINE_BREAKS, CONTROLS, STATEMENTS, FORMULAS, MARKUP, PATHS, QUOTING, PLAIN]


def payload(rnd):
    """A hostile string: one to six fragments from random pools."""
    return "".join(rnd.choice(rnd.choice(POOLS)) for _ in range(rnd.randint(1, 6)))


def quoted(rnd, text):
    """Usually a correctly quoted FortiOS value; sometimes left raw so the quoting itself is broken."""
    if rnd.random() < 0.15:
        return '"' + text + '"'
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


_QUOTED = re.compile(r'"(?:[^"\\\n]|\\.)*"')


def hostile_config(rnd, sample):
    """The sample config with random quoted values replaced, hostile objects added and lines damaged."""
    rate = rnd.choice([0.02, 0.1, 0.4])
    text = _QUOTED.sub(lambda m: quoted(rnd, payload(rnd)) if rnd.random() < rate else m.group(0), sample)
    extra = ["config firewall address"]
    for _ in range(rnd.randint(0, 4)):
        extra += [f"    edit {quoted(rnd, payload(rnd))}", "        set subnet 10.9.9.9 255.255.255.255",
                  f"        set comment {quoted(rnd, payload(rnd))}", "    next"]
    extra += ["end", "config system global", f"    set hostname {quoted(rnd, payload(rnd))}", "end",
              "config firewall policy"]
    for _ in range(rnd.randint(0, 3)):
        extra += [f"    edit {rnd.choice(['9001', '9002', payload(rnd).split() and '9003', quoted(rnd, payload(rnd))])}",
                  f"        set name {quoted(rnd, payload(rnd))}", '        set srcintf "any"', '        set dstintf "any"',
                  f"        set srcaddr {quoted(rnd, payload(rnd))}", '        set dstaddr "all"',
                  "        set action accept", '        set schedule "always"', '        set service "ALL"',
                  f"        set comments {quoted(rnd, payload(rnd))}", "    next"]
    extra += ["end"]
    lines = (text + "\n" + "\n".join(extra) + "\n").split("\n")
    for _ in range(rnd.choice([0, 0, 1, 3])):  # damage the structure: drop, repeat or replace a line
        i = rnd.randrange(len(lines))
        lines[i:i + 1] = rnd.choice([[], [lines[i], lines[i]], [payload(rnd)], [rnd.choice(STATEMENTS)]])
    return "\n".join(lines)


def garbage(rnd):
    """Text with no structure at all: fragments and random characters."""
    parts = []
    for _ in range(rnd.randint(0, 60)):
        if rnd.random() < 0.7:
            parts.append(rnd.choice(rnd.choice(POOLS)))
        else:
            parts.append("".join(chr(rnd.choice([rnd.randrange(0, 0x100), rnd.randrange(0, 0x3000),
                                                  rnd.randrange(0, 0x110000)])) for _ in range(rnd.randint(1, 8)))
                         .encode("utf-8", "replace").decode("utf-8"))
        parts.append(rnd.choice([" ", " ", "\n", "", "\"", "\t"]))
    return "".join(parts)


def unsafe_chars(text, allow="\n"):
    """Control, format and separator characters that must not reach a script or a terminal."""
    return sorted({repr(c) for c in text if c not in allow and unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp")})


def strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from strings(k)
            yield from strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from strings(v)


class _Tags(HTMLParser):
    """Collects every tag and attribute name the browser would see."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.attrs, self.links = set(), set(), []

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag)
        for name, value in attrs:
            self.attrs.add(name)
            if name in ("href", "src", "action"):
                self.links.append(value or "")


class FuzzTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(HERE, "sample.conf"), encoding="utf-8") as fh:
            cls.sample = fh.read()

    def each_round(self, name, check, count=None):
        """Run check(rnd) for every round. A failure names the seed and round needed to reproduce it."""
        for i in range(count or ROUNDS):
            try:
                check(random.Random(f"{SEED}/{name}/{i}"))
            except Exception as e:
                raise AssertionError(f"{name} round {i} with RULESCOPE_FUZZ_SEED={SEED}: "
                                     f"{type(e).__name__}: {e}") from e

    # ------------------------------------------------------------------ reading

    def test_parser_accepts_anything(self):
        def check(rnd):
            text = garbage(rnd)
            self.assertIsInstance(fgtconf.parse(text), fgtconf.Block)
            snap = model.from_config(text)
            self.assertEqual([s for s in strings(snap) if unsafe_chars(s, allow="")], [],
                             "invisible characters survived parsing")
            checks.analyze(snap)

        self.each_round("parser", check, ROUNDS * 4)

    def test_hostile_configs_through_every_output(self):
        def check(rnd):
            snap = model.from_config(hostile_config(rnd, self.sample))
            self.assertEqual([s for s in strings(snap) if unsafe_chars(s, allow="")], [],
                             "invisible characters survived parsing")
            res = checks.analyze(snap)

            for script in (report.remediation_cli(res), report.remediation_cli(res, safe_only=True, title="quick wins")):
                self.assertEqual(unsafe_chars(script), [], "invisible characters in the remediation script")
                for ln in script.split("\n"):
                    if ln.strip() and not ln.lstrip().startswith("#"):
                        self.assertRegex(ln, ALLOWED, "active script line is not a generated statement")

            for name, text in (("findings", report.findings_csv(res)), ("practices", report.practices_csv(res))):
                for row in csv.reader(io.StringIO(text.lstrip("\ufeff"))):
                    for cell in row:
                        self.assertFalse(cell.startswith(FORMULA_START),
                                         f"{name} CSV cell can run as a formula: {cell[:60]!r}")
                        self.assertEqual(unsafe_chars(cell, allow=""), [], f"invisible characters in {name} CSV")

            self.assertEqual(unsafe_chars(report.console_summary(res)), [], "invisible characters in terminal output")

            page = _Tags()
            page.feed(report.html_report(res, snap))
            self.assertNotIn("fuzz-tag", page.tags, "config text became an HTML tag")
            self.assertNotIn("onfuzz", page.attrs, "config text became an HTML attribute")
            for link in page.links:
                self.assertRegex(link, r"^(https://|#|$)", "a link in the report is not https or internal")

        self.each_round("pipeline", check)

    def test_change_reports_of_hostile_snapshots(self):
        def check(rnd):
            old = model.from_config(hostile_config(rnd, self.sample))
            new = model.from_config(hostile_config(rnd, self.sample))
            d = diff.diff_snapshots(old, new)
            self.assertEqual(unsafe_chars(diff.render_text(d)), [], "invisible characters in the change report")
            for alert in d["alerts"]:
                self.assertEqual(unsafe_chars(alert, allow=""), [], "invisible characters in an alert")
            page = _Tags()
            page.feed(diff.render_html(d))
            self.assertNotIn("fuzz-tag", page.tags, "config text became an HTML tag")
            self.assertNotIn("onfuzz", page.attrs, "config text became an HTML attribute")

        self.each_round("diff", check, max(ROUNDS // 3, 10))

    # ------------------------------------------------------------------ writing

    def test_guard_blocks_every_foreign_line(self):
        def check(rnd):
            lines = [rnd.choice(["    " * rnd.randint(0, 3) + rnd.choice(STATEMENTS), payload(rnd), "# " + payload(rnd),
                                 "config firewall policy", "    edit 1", "        set status disable", "    next", "end"])
                     for _ in range(rnd.randint(1, 12))]
            out = report.guard_script("\n".join(lines) + "\n")
            self.assertEqual(unsafe_chars(out), [], "invisible characters in a guarded script")
            for ln in out.split("\n"):
                if ln.strip() and not ln.lstrip().startswith("#"):
                    self.assertRegex(ln, ALLOWED, "guard let a foreign statement through")

        self.each_round("guard", check, ROUNDS * 4)

    def test_snapshots_stay_inside_their_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.realpath(os.path.join(tmp, "snaps"))

            def check(rnd):
                name = payload(rnd)
                safe = source.safe_name(name)
                self.assertRegex(safe, r"^[A-Za-z0-9_-]([A-Za-z0-9._-]*[A-Za-z0-9_-])?$")
                self.assertLessEqual(len(safe), 101)
                self.assertNotRegex(safe, r"(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)")
                snap = model.empty_snapshot("config")
                snap["device"]["hostname"] = name
                for explicit in (None, payload(rnd)):
                    path = os.path.realpath(source.save_snapshot(snap, base, explicit))
                    self.assertTrue(path.startswith(base + os.sep), f"snapshot written outside its folder: {path}")
                    self.assertEqual(os.path.dirname(os.path.dirname(path)), base)

            self.each_round("paths", check)

    # ------------------------------------------------------------------ the source itself

    def test_source_has_no_invisible_characters(self):
        """Direction marks or zero-width characters in source make code read differently than it runs."""
        root = os.path.dirname(HERE)
        for folder in ("rulescope", "tests", "deploy", "examples", "website", ".github"):
            for dirpath, _, files in os.walk(os.path.join(root, folder)):
                for name in files:
                    if not name.endswith((".py", ".yml", ".service", ".timer", ".conf", ".example", ".ini", ".toml", ".html",
                                          "Caddyfile")):
                        continue
                    path = os.path.join(dirpath, name)
                    with open(path, encoding="utf-8") as fh:
                        found = unsafe_chars(fh.read(), allow="\n\t")
                    self.assertEqual(found, [], f"invisible characters in {os.path.relpath(path, root)}")


if __name__ == "__main__":
    unittest.main()
