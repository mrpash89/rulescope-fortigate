"""Build the public demo website: the landing page plus live sample output from synthetic configs.

    python3 website/build.py --out /srv/rulescope-demo --site-url https://demo.example.com

Layout of --out:

    releases/20261110-031500/     one complete build
        index.html                landing page (website/index.html with real numbers filled in)
        demo/                     fleet dashboard and reports, from examples/make_demo.py
        img/                      preview image for shared links
        robots.txt, .well-known/security.txt
    current -> releases/...       what the web server serves; switched only after a build succeeded

A failed build leaves `current` as it was. Standard library only. No visitor input is involved:
the site is static files.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import glob
import json
import os
import re
import shutil
import sys
import tempfile
from html import escape
from typing import Any, Dict, List

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "examples"))

import make_demo  # noqa: E402
from rulescope import __version__, firmware  # noqa: E402

REPO_URL = "https://github.com/mrpash89/rulescope-fortigate"
SEVERITIES = ("high", "medium", "low", "info")
REQUIRED = ("index.html", "robots.txt", "demo/index.html", "demo/HQ/report.html", "demo/HQ/fix.txt",
            "demo/HQ/findings.csv", "demo/HQ/practices.csv", "demo/HQ/findings.json",
            "demo/Branch-South/changes.html", "img/report-overview.png")


def _load(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _join(names: List[str]) -> str:
    return ", ".join(n for n in names if n) or "any"


def policy_rows(result: Dict[str, Any], snap: Dict[str, Any]) -> str:
    """The rule base of one firewall as table rows, each rule with what the audit found on it."""
    found: Dict[Any, List[Dict[str, Any]]] = {}
    for f in result["findings"]:
        if f.get("policyid") is not None:
            found.setdefault(f["policyid"], []).append(f)
    rows = []
    for p in snap["policies"]:
        fs = sorted(found.get(p["policyid"], []), key=lambda f: SEVERITIES.index(f["severity"]))
        off = p["status"] != "enable"
        cls = "off" if off else ("high" if fs and fs[0]["severity"] == "high" else "")
        tr_class = f' class="{cls}"' if cls else ""
        name = escape(p["name"] or "(no name)")
        cells = "".join(
            f'<div><span class="sev {escape(f["severity"])}">{escape(f["severity"].capitalize())}</span>'
            f'<span>{escape(f["title"])}</span></div>' for f in fs
        ) or '<div><span class="none">Nothing</span></div>'
        dst = _join(p["dstaddr"]) if p["dstaddr"] else "internet service"
        rows.append(
            f'          <tr{tr_class}><td class="num">{escape(str(p["policyid"]))}</td>'
            f'<td class="name"><a href="demo/HQ/report.html#inv-{escape(str(p["policyid"]))}">{name}</a></td>'
            f'<td class="intf mono">{escape(_join(p["srcintf"]))} to {escape(_join(p["dstintf"]))}</td>'
            f'<td class="addr mono">{escape(_join(p["srcaddr"]))} to {escape(dst)}</td>'
            f'<td class="svc mono">{escape(_join(p["service"]) if p["service"] else "internet service")}</td>'
            f'<td class="{"deny" if p["action"] == "deny" else "accept"}">{escape(p["action"])}'
            f'{" (disabled)" if off else ""}</td>'
            f'<td class="found">{cells}</td></tr>')
    return "\n".join(rows)


def render(template: str, values: Dict[str, str]) -> str:
    """Fill {{name}} placeholders in one pass, so text inside a value is never expanded again."""
    def fill(m: "re.Match[str]") -> str:
        if m.group(1) not in values:
            raise ValueError(f"landing page has an unfilled placeholder: {m.group(0)}")
        return values[m.group(1)]

    return re.sub(r"\{\{(\w+)\}\}", fill, template)


NOINDEX = '<meta name="robots" content="noindex">'


def mark_noindex(folder: str) -> None:
    """The samples describe weaknesses of fictional firewalls. In search results they would read like
    a real exposed report, so every sample page asks not to be indexed (the web server also sends
    X-Robots-Tag for the files that are not HTML)."""
    for dirpath, _, files in os.walk(folder):
        for name in files:
            if not name.endswith(".html"):
                continue
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8") as fh:
                page = fh.read()
            head = page.find("<head>")
            if head < 0:
                raise RuntimeError(f"{path} has no <head>: cannot mark it noindex")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(page[:head + 6] + NOINDEX + page[head + 6:])


def build(release: str, work: str, site_url: str, advisor: Any = None) -> None:
    make_demo.main(work, advisor=advisor)
    # symlinks=True: a link is copied as a link (and refused below), never as the content of its target
    shutil.copytree(os.path.join(work, "site"), os.path.join(release, "demo"), symlinks=True)
    mark_noindex(os.path.join(release, "demo"))

    hq = _load(os.path.join(release, "demo", "HQ", "findings.json"))
    hq_snap = _load(sorted(glob.glob(os.path.join(work, "snapshots", "HQ", "*.json")))[-1])
    fleet_summary = _load(os.path.join(release, "demo", "fleet.json"))
    south = next(d for d in fleet_summary["devices"] if d["name"] == "Branch-South")
    alerts = "".join(f"<li>{escape(a)}</li>" for a in south["alerts"]) or "<li>No risky change in this build.</li>"
    now = _dt.datetime.now(_dt.timezone.utc)

    with open(os.path.join(HERE, "index.html"), encoding="utf-8") as fh:
        page = render(fh.read(), {
            "site_url": escape(site_url.rstrip("/")), "repo_url": REPO_URL, "version": escape(__version__),
            "built": now.strftime("%Y-%m-%d %H:%M"),
            "hq_hostname": escape(hq["device"]["hostname"]), "hq_model": escape(hq["device"]["model"]),
            "hq_rules": str(len(hq_snap["policies"])), "hq_score": str(int(hq["score"])),
            "hq_high": str(int(hq["severity_counts"]["high"])), "hq_rows": policy_rows(hq, hq_snap),
            "practices_total": str(int(hq["practices"]["total"])),
            "south_hostname": escape(south["hostname"]),
            "south_alerts": f'          <ul class="alerts">{alerts}</ul>',
        })
    with open(os.path.join(release, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(page)

    os.makedirs(os.path.join(release, "img"))  # the preview image for links shared in chat and social apps
    shutil.copy(os.path.join(ROOT, "docs", "images", "report-overview.png"), os.path.join(release, "img"))
    with open(os.path.join(release, "robots.txt"), "w", encoding="utf-8") as fh:
        # Crawling is allowed everywhere. The samples carry "noindex" instead: a Disallow here would
        # stop crawlers from ever seeing it, and linked pages could then still be listed.
        fh.write("User-agent: *\nAllow: /\n")
    os.makedirs(os.path.join(release, ".well-known"))
    with open(os.path.join(release, ".well-known", "security.txt"), "w", encoding="utf-8") as fh:
        fh.write(f"Contact: {REPO_URL}/security/advisories/new\n"
                 f"Policy: {REPO_URL}/blob/main/SECURITY.md\n"
                 f"Expires: {(now + _dt.timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
                 f"Canonical: {site_url.rstrip('/')}/.well-known/security.txt\n")

    for name in REQUIRED:
        path = os.path.join(release, name)
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            raise RuntimeError(f"build is incomplete: {name} is missing or empty")
    # RuleScope writes reports without access for other users. This site is public by design.
    for dirpath, dirs, files in os.walk(release):
        os.chmod(dirpath, 0o755)
        for name in dirs + files:
            path = os.path.join(dirpath, name)
            if os.path.islink(path):  # the web server follows links: one could publish a file outside the site
                raise RuntimeError(f"build contains a symbolic link: {os.path.relpath(path, release)}")
        for name in files:
            os.chmod(os.path.join(dirpath, name), 0o644)


def publish(out: str, release: str) -> None:
    """Point `current` at the new release in one atomic step."""
    link = os.path.join(out, "current")
    tmp = link + ".new"
    if os.path.lexists(tmp):
        os.remove(tmp)
    os.symlink(os.path.relpath(release, out), tmp)
    os.replace(tmp, link)


def prune(out: str, keep: int) -> None:
    current = os.path.realpath(os.path.join(out, "current"))
    for old in sorted(glob.glob(os.path.join(out, "releases", "*")))[:-keep]:
        if os.path.realpath(old) != current:
            shutil.rmtree(old, ignore_errors=True)


def main(argv: Any = None) -> int:
    ap = argparse.ArgumentParser(description="Build the RuleScope demo website (static files).")
    ap.add_argument("--out", required=True, help="Folder that holds releases/ and the 'current' link")
    ap.add_argument("--site-url", required=True, help="Public address of the site, e.g. https://demo.example.com")
    ap.add_argument("--advisories", choices=("off", "cache", "online"), default="off",
                    help="Known CVEs for the demo's FortiOS versions from the NIST NVD (default: off)")
    ap.add_argument("--cache-dir", help="NVD cache folder (with --advisories cache/online)")
    ap.add_argument("--keep", type=int, default=3, help="Releases to keep (default 3)")
    args = ap.parse_args(argv)

    advisor = None
    if args.advisories != "off":
        advisor = firmware.AdvisoryClient(mode=args.advisories, cache_dir=args.cache_dir,
                                          api_key=os.environ.get("NVD_API_KEY"))
    out = os.path.abspath(args.out)
    os.makedirs(os.path.join(out, "releases"), exist_ok=True)
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    release = os.path.join(out, "releases", stamp)
    n = 1
    while os.path.exists(release):  # two builds in the same second
        n += 1
        release = os.path.join(out, "releases", f"{stamp}-{n}")
    staging = tempfile.mkdtemp(prefix=".build-", dir=out)
    try:
        build(os.path.join(staging, "site"), os.path.join(staging, "work"), args.site_url, advisor)
        os.chmod(staging, 0o755)
        os.replace(os.path.join(staging, "site"), release)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    publish(out, release)
    prune(out, max(args.keep, 1))
    print(f"published {release} (RuleScope {__version__})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
