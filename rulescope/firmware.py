"""Firmware lifecycle and known-vulnerability lookup.

Lifecycle: Fortinet publishes a GA, End of Engineering Support (EoES) and End of Support (EoS)
date for every FortiOS branch. The table below is shipped with rulescope and can be replaced
with --lifecycle-file when Fortinet changes dates (it extended 7.4 and 7.6 by a year in 2026).

Vulnerabilities: looked up in the NIST National Vulnerability Database (NVD API 2.0) by the
device's exact CPE, so only CVEs whose affected-version ranges include this build are returned,
together with CISA's Known Exploited Vulnerabilities (KEV) flag. Results are cached on disk,
so fleets and air-gapped installs can reuse one download (copy the cache folder across).
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .catalog import finding
from .safety import clean_tree, safe_url

LIFECYCLE_SOURCE = "https://support.fortinet.com/Information/ProductLifeCycle.aspx"
LIFECYCLE_CHECKED = "2026-11-05"
# branch: (GA, End of Engineering Support, End of Support)
LIFECYCLE: Dict[str, Tuple[str, str, str]] = {
    "6.0": ("2018-03-29", "2021-03-29", "2022-09-29"),
    "6.2": ("2019-03-28", "2022-03-28", "2023-09-28"),
    "6.4": ("2020-03-31", "2023-03-31", "2024-09-30"),
    "7.0": ("2021-03-30", "2024-03-30", "2025-09-30"),
    "7.2": ("2022-03-31", "2025-03-31", "2026-09-30"),
    "7.4": ("2023-05-11", "2027-05-11", "2028-11-11"),  # extended by one year (Fortinet CSB-260330-1)
    "7.6": ("2024-07-25", "2028-07-25", "2030-01-25"),  # extended by one year (Fortinet CSB-260330-1)
    "8.0": ("2026-04-21", "2029-04-21", "2030-10-21"),
}
EOES_SOON_DAYS = 180

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SOURCE = "NIST National Vulnerability Database"
_FGIR = re.compile(r"FG-IR-\d{2}-\d{2,4}", re.I)
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}")


def parse_version(v: Optional[str]) -> Optional[str]:
    """'v7.4.3', '7.4.3 build2573' -> '7.4.3'."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", v or "")
    return f"{int(m.group(1))}.{int(m.group(2))}.{int(m.group(3))}" if m else None


def load_lifecycle(path: Optional[str]) -> Dict[str, Tuple[str, str, str]]:
    """JSON {"7.4": ["2023-05-11", "2027-05-11", "2028-11-11"], ...} merged over the built-in table."""
    table = dict(LIFECYCLE)
    if path:
        with open(path, encoding="utf-8") as fh:
            for k, v in json.load(fh).items():
                if isinstance(v, (list, tuple)) and len(v) == 3:
                    table[str(k)] = (str(v[0]), str(v[1]), str(v[2]))
                elif isinstance(v, dict):
                    table[str(k)] = (str(v["ga"]), str(v["eoes"]), str(v["eos"]))
    return table


def _days(a: str, b: str) -> int:
    return (_dt.date.fromisoformat(b) - _dt.date.fromisoformat(a)).days


def lifecycle(version: Optional[str], today: str,
              table: Optional[Dict[str, Tuple[str, str, str]]] = None) -> Dict[str, Any]:
    table = table or LIFECYCLE
    v = parse_version(version)
    out: Dict[str, Any] = {"version": v, "branch": None, "ga": None, "eoes": None, "eos": None, "status": "unknown",
                           "days_to_eos": None, "days_to_eoes": None, "source": LIFECYCLE_SOURCE,
                           "checked": LIFECYCLE_CHECKED}
    if not v:
        return out
    branch = ".".join(v.split(".")[:2])
    out["branch"] = branch
    if branch not in table:
        return out
    ga, eoes, eos = table[branch]
    out.update({"ga": ga, "eoes": eoes, "eos": eos, "days_to_eos": _days(today, eos), "days_to_eoes": _days(today, eoes)})
    out["status"] = ("eos" if today > eos else "eoes" if today > eoes else
                     "eoes_soon" if out["days_to_eoes"] <= EOES_SOON_DAYS else "supported")
    return out


def lifecycle_table(today: str, table: Optional[Dict[str, Tuple[str, str, str]]] = None) -> List[Dict[str, Any]]:
    rows = []
    for br, (ga, eoes, eos) in sorted((table or LIFECYCLE).items(), key=lambda kv: tuple(map(int, kv[0].split(".")))):
        st = "eos" if today > eos else "eoes" if today > eoes else "supported"
        rows.append({"branch": br, "ga": ga, "eoes": eoes, "eos": eos, "status": st})
    return rows


# ---------------------------------------------------------------- NVD client

def cpe_name(version: str) -> str:
    return f"cpe:2.3:o:fortinet:fortios:{version}:*:*:*:*:*:*:*"


def _cvss(metrics: Dict[str, Any]) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        ms = metrics.get(key) or []
        if ms:
            m = next((x for x in ms if x.get("type") == "Primary"), ms[0])
            d = m.get("cvssData") or {}
            score = d.get("baseScore")
            return (float(score) if score is not None else None,
                    (d.get("baseSeverity") or m.get("baseSeverity") or "").upper() or None, key[10:].replace("V", "v"))
    return None, None, None


def normalize_cve(item: Dict[str, Any]) -> Dict[str, Any]:
    c = item.get("cve") or item
    desc = next((d.get("value", "") for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    score, sev, ver = _cvss(c.get("metrics") or {})
    refs = [r.get("url", "") for r in c.get("references", []) if isinstance(r, dict)]
    fgir = next((m.group(0).upper() for u in refs for m in [_FGIR.search(u)] if m), None)
    advisory = next((u for u in refs if _FGIR.search(u)), None)
    title = c.get("cisaVulnerabilityName") or (desc.split(". ")[0] if desc else c.get("id", ""))
    return sanitize_cve({"id": c.get("id", ""), "published": (c.get("published") or "")[:10], "cvss": score,
                         "severity": sev, "cvss_version": ver, "kev": bool(c.get("cisaExploitAdd")),
                         "kev_added": c.get("cisaExploitAdd"), "title": title[:180], "fgir": fgir, "url": advisory})


def sanitize_cve(c: Dict[str, Any]) -> Dict[str, Any]:
    """Applied to NVD data and to everything read back from the cache (which anyone could have edited)."""
    c = clean_tree(dict(c))
    cid = str(c.get("id") or "")
    c["id"] = cid if _CVE_ID.fullmatch(cid) else "CVE-invalid"
    try:
        c["cvss"] = float(c["cvss"]) if c.get("cvss") is not None else None
    except (TypeError, ValueError):
        c["cvss"] = None
    c["kev"] = bool(c.get("kev"))
    c["title"] = str(c.get("title") or "")[:180]
    c["url"] = safe_url(c.get("url")) or (f"https://nvd.nist.gov/vuln/detail/{c['id']}" if c["id"] != "CVE-invalid" else "")
    return c


class AdvisoryClient:
    """mode: 'off' (never look up), 'cache' (use cached results only, no network), 'online' (refresh
    results older than max_age_hours, fall back to the cache if NVD cannot be reached)."""
    _lock = threading.Lock()
    _last = 0.0

    def __init__(self, mode: str = "cache", cache_dir: Optional[str] = None, api_key: Optional[str] = None,
                 timeout: int = 30, max_age_hours: int = 24, url: Optional[str] = None):
        self.mode, self.api_key, self.timeout, self.max_age = mode, api_key, timeout, max_age_hours * 3600
        self.cache_dir = cache_dir or os.path.join(os.path.expanduser("~"), ".cache", "rulescope", "nvd")
        self.url = url or os.environ.get("RULESCOPE_NVD_URL") or NVD_URL
        self._mem: Dict[str, Dict[str, Any]] = {}
        self._guard = threading.Lock()
        self._locks: Dict[str, threading.Lock] = {}

    def _version_lock(self, version: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(version, threading.Lock())

    def _cache_path(self, version: str) -> str:
        return os.path.join(self.cache_dir, f"fortios-{version}.json")

    def _read_cache(self, version: str) -> Optional[Dict[str, Any]]:
        try:
            with open(self._cache_path(version), encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or not isinstance(data.get("cves"), list):
            return None
        data["cves"] = [sanitize_cve(c) for c in data["cves"] if isinstance(c, dict)]
        data["fetched"] = str(data.get("fetched") or "")[:32] or None
        return data

    def _write_cache(self, version: str, data: Dict[str, Any]) -> None:
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.cache_dir, prefix=f".fortios-{version}-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(data, fh)
                os.replace(tmp, self._cache_path(version))
            except BaseException:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise
        except OSError:
            pass  # a read-only cache folder must not fail the audit

    def _get(self, params: Dict[str, str]) -> Dict[str, Any]:
        with AdvisoryClient._lock:  # NVD allows 5 requests / 30 s without a key, 50 with one
            gap = 0.7 if self.api_key else 6.5
            wait = AdvisoryClient._last + gap - time.monotonic()
            if wait > 0 and AdvisoryClient._last:
                time.sleep(wait)
            AdvisoryClient._last = time.monotonic()
        req = urllib.request.Request(self.url + "?" + urllib.parse.urlencode(params).replace("isVulnerable=", "isVulnerable"))
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "rulescope")
        if self.api_key:
            req.add_header("apiKey", self.api_key)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read())

    def _fetch(self, version: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        start, total = 0, 1
        while start < total:
            page = self._get({"cpeName": cpe_name(version), "isVulnerable": "", "resultsPerPage": "2000",
                              "startIndex": str(start)})
            items = page.get("vulnerabilities") or []
            out += [normalize_cve(i) for i in items]
            total = int(page.get("totalResults") or 0)
            start += int(page.get("resultsPerPage") or len(items) or 1)
            if not items:
                break
        return out

    def lookup(self, version_text: Optional[str]) -> Optional[Dict[str, Any]]:
        if self.mode == "off":
            return None
        version = parse_version(version_text)
        res: Dict[str, Any] = {"mode": self.mode, "source": NVD_SOURCE, "version": version, "cves": [],
                               "fetched": None, "error": None, "from_cache": False}
        if not version:
            res["error"] = "FortiOS version unknown"
            return res
        with self._version_lock(version):  # fleet workers on the same version wait for one lookup
            return self._lookup(version, res)

    def _lookup(self, version: str, res: Dict[str, Any]) -> Dict[str, Any]:
        if version in self._mem:
            return self._mem[version]
        cached = self._read_cache(version)
        age = None
        if cached and cached.get("fetched"):
            try:
                age = time.time() - _dt.datetime.fromisoformat(cached["fetched"]).timestamp()
            except ValueError:
                age = None
        if self.mode == "online" and (cached is None or age is None or age > self.max_age):
            try:
                cves = self._fetch(version)
                fetched = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()
                cached = {"fetched": fetched, "cpe": cpe_name(version), "source": NVD_SOURCE, "cves": cves}
                self._write_cache(version, cached)
            except urllib.error.HTTPError as e:
                res["error"] = f"NVD returned HTTP {e.code}" + (" (rate limit: add an API key)" if e.code in (403, 429) else "")
            except (urllib.error.URLError, OSError, ValueError) as e:
                res["error"] = f"NVD not reachable ({getattr(e, 'reason', e)})"
        else:
            res["from_cache"] = cached is not None
        if cached:
            res.update({"cves": cached.get("cves", []), "fetched": cached.get("fetched")})
            if res["error"]:
                res["error"] += f"; using cached results from {str(cached.get('fetched'))[:10]}"
                res["from_cache"] = True
        elif not res["error"]:
            res["error"] = "no cached advisory data (run once with --advisories online)"
        self._mem[version] = res
        return res


# ---------------------------------------------------------------- checks

def summarize(snap: Dict[str, Any], adv: Optional[Dict[str, Any]], table: Optional[Dict[str, Tuple[str, str, str]]] = None
              ) -> Dict[str, Any]:
    today = snap["collected_at"][:10]
    lc = lifecycle(snap["device"].get("version"), today, table)
    cves = sorted((adv or {}).get("cves") or [], key=lambda c: (not c.get("kev"), -(c.get("cvss") or 0), c.get("id", "")))
    counts = {"total": len(cves), "kev": sum(1 for c in cves if c.get("kev")),
              "critical": sum(1 for c in cves if (c.get("cvss") or 0) >= 9),
              "high": sum(1 for c in cves if 7 <= (c.get("cvss") or 0) < 9)}
    checked = bool(adv) and adv.get("fetched") is not None
    return {"version": lc["version"], "build": snap["device"].get("build"), "model": snap["device"].get("model"),
            "lifecycle": lc, "branches": lifecycle_table(today, table),
            "advisories": {"mode": (adv or {}).get("mode", "off"), "checked": checked, "source": NVD_SOURCE,
                           "fetched": (adv or {}).get("fetched"), "error": (adv or {}).get("error"),
                           "from_cache": (adv or {}).get("from_cache", False), "counts": counts, "cves": cves}}


def check_firmware(fw: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    lc = fw["lifecycle"]
    v = lc.get("version") or "?"
    if lc["status"] == "eos":
        out.append(finding("FIRMWARE_EOS", obj=f"FortiOS {v}",
            detail=f"FortiOS {lc['branch']} reached End of Support on {lc['eos']} ({-lc['days_to_eos']} days ago).",
            url=LIFECYCLE_SOURCE))
    elif lc["status"] == "eoes":
        out.append(finding("FIRMWARE_EOES", obj=f"FortiOS {v}",
            detail=f"FortiOS {lc['branch']} passed End of Engineering Support on {lc['eoes']}; End of Support is "
                   f"{lc['eos']} (in {lc['days_to_eos']} days).", url=LIFECYCLE_SOURCE))
    elif lc["status"] == "eoes_soon":
        out.append(finding("FIRMWARE_EOES_SOON", obj=f"FortiOS {v}",
            detail=f"FortiOS {lc['branch']} reaches End of Engineering Support on {lc['eoes']} (in {lc['days_to_eoes']} "
                   f"days) and End of Support on {lc['eos']}.", url=LIFECYCLE_SOURCE))
    for c in fw["advisories"]["cves"]:
        score = c.get("cvss") or 0
        ref = f"CVSS {score:g}" + (f", {c['fgir']}" if c.get("fgir") else "")
        if c.get("kev"):
            out.append(finding("FIRMWARE_KEV", obj=c["id"], url=c.get("url"),
                detail=f"{c['id']} ({ref}): {c['title']}. Exploited in the wild (CISA KEV since {c.get('kev_added')})."))
        elif score >= 7:
            out.append(finding("FIRMWARE_CVE", obj=c["id"], url=c.get("url"), severity="high" if score >= 9 else "medium",
                detail=f"{c['id']} ({ref}): {c['title']}."))
    return out
