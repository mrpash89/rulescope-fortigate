"""The demo website builds from the current code, with every placeholder of the landing page filled."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from html.parser import HTMLParser

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "website"))

import build  # noqa: E402


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.local, self.rows = [], 0

    def handle_starttag(self, tag, attrs):
        href = dict(attrs).get("href") or ""
        if tag == "a" and href and not href.startswith(("http", "#", "./")):
            self.local.append(href.split("#")[0])
        if tag == "tr":
            self.rows += 1


class WebsiteTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "the site is published through a symbolic link; it is built on Linux")
    def test_site_builds_and_every_local_link_resolves(self):
        with tempfile.TemporaryDirectory() as out:
            for _ in range(2):   # a second build replaces the first without leaving the site empty
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(build.main(["--out", out, "--site-url", "https://demo.example.com/"]), 0)
            site = os.path.join(out, "current")
            self.assertTrue(os.path.islink(site))
            with open(os.path.join(site, "index.html"), encoding="utf-8") as fh:
                page = fh.read()
            self.assertNotIn("{{", page)
            self.assertIn('href="https://demo.example.com/"', page)       # no doubled slash
            links = _Links()
            links.feed(page)
            self.assertGreater(links.rows, 10)                              # the sample rule base is in the page
            self.assertGreater(len(links.local), 5)
            for href in links.local:
                target = os.path.join(site, href)
                if href.endswith("/"):
                    target = os.path.join(target, "index.html")
                self.assertTrue(os.path.isfile(target), f"landing page links to a missing file: {href}")
            # every sample page asks not to be indexed; the landing page may be
            self.assertNotIn(build.NOINDEX, page)
            pages = 0
            for dirpath, _, files in os.walk(os.path.join(site, "demo")):
                for name in files:
                    if name.endswith(".html"):
                        pages += 1
                        with open(os.path.join(dirpath, name), encoding="utf-8") as fh:
                            self.assertIn("<head>" + build.NOINDEX, fh.read(), name)
            self.assertGreater(pages, 5)
            with open(os.path.join(site, "robots.txt"), encoding="utf-8") as fh:
                self.assertNotIn("Disallow", fh.read())   # crawlers must be able to see the noindex
            for dirpath, dirs, files in os.walk(os.path.realpath(site)):
                for name in dirs + files:
                    self.assertFalse(os.path.islink(os.path.join(dirpath, name)), name)
            self.assertEqual([n for n in os.listdir(out) if n.startswith(".build-")], [])

    @unittest.skipIf(os.name == "nt", "symbolic links need extra rights on Windows")
    def test_a_symbolic_link_in_the_build_is_refused(self):
        real = build.make_demo.main

        def with_link(out, advisor=None):
            real(out, advisor=advisor)
            os.symlink("/etc/hostname", os.path.join(out, "site", "HQ", "leak.txt"))

        build.make_demo.main = with_link
        try:
            with tempfile.TemporaryDirectory() as out, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "symbolic link"):
                    build.main(["--out", out, "--site-url", "https://demo.example.com"])
                self.assertFalse(os.path.lexists(os.path.join(out, "current")))     # nothing was published
        finally:
            build.make_demo.main = real

    def test_unfilled_placeholder_fails_the_build(self):
        with self.assertRaises(ValueError):
            build.render("<p>{{version}} {{typo}}</p>", {"version": "1"})

    def test_placeholders_inside_values_are_not_expanded(self):
        self.assertEqual(build.render("{{a}} {{b}}", {"a": "{{b}}", "b": "x"}), "{{b}} x")


if __name__ == "__main__":
    unittest.main()
