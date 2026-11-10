"""Fleet mode: audit many FortiGates in one run and publish a static dashboard.

Inventory (INI). Values in [DEFAULT] apply to every device; vdom may list several VDOMs.

    [DEFAULT]
    token_file = /etc/rulescope/token

    [HQ-FW]
    host = 192.0.2.1
    pin_sha256 = 3f5c...e1a0     ; fingerprint from: rulescope cert --host 192.0.2.1

    [HQ-FW2]
    host = 192.0.2.2
    vdom = root, DMZ
    label = Headquarters

    [Branch-07]
    host = 192.0.2.7:8443
    token_env = BRANCH_TOKEN

    [Customer-X]
    config = /audits/customer-x.conf
    usage = /audits/customer-x-hits.csv
"""
from __future__ import annotations

import configparser
import datetime as _dt
import json
import os
import sys
import traceback
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from html import escape
from typing import Any, Callable, Dict, List, Optional

from . import __version__, checks, diff, firmware, net, notify, report, source
from .catalog import CHECKS, SEV_LABEL, SEVERITY_ORDER
from .safety import makedirs_restricted, write_restricted
from .ui import CONTROLS, THEME_HEAD, THEME_JS, html_open

TRUE = {"1", "yes", "true", "on"}


def load_inventory(path: str) -> List[Dict[str, Any]]:
    cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=(";",))
    with open(path, encoding="utf-8") as fh:
        cp.read_file(fh)
    devices = []
    for sec in cp.sections():
        o = cp[sec]
        vdoms = [v.strip() for v in o.get("vdom", "root").split(",") if v.strip()] or ["root"]
        for vd in vdoms:
            dev = {
                "name": sec if len(vdoms) == 1 else f"{sec}_{vd}", "section": sec, "vdom": vd,
                "host": o.get("host"), "config": o.get("config"), "port": int(o.get("port", "443")),
                "token_file": o.get("token_file"), "token_env": o.get("token_env"),
                "insecure": o.get("insecure", "no").lower() in TRUE, "ca_file": o.get("ca_file"),
                "pin_sha256": o.get("pin_sha256"),
                "timeout": int(o.get("timeout", "30")), "usage": o.get("usage"), "usage_since": o.get("usage_since"),
                "label": o.get("label", sec), "group": o.get("group", ""),
                "backup": o.get("backup", "yes").lower() in TRUE, "events": o.get("events", "yes").lower() in TRUE,
                "wan": o.get("wan"), "not_wan": o.get("not_wan"),
            }
            if not dev["host"] and not dev["config"]:
                raise ValueError(f"[{sec}] needs 'host' or 'config'")
            if dev["pin_sha256"]:
                net.normalize_pin(dev["pin_sha256"])  # a mistyped pin fails here, not in the middle of a run
            devices.append(dev)
    # devices are stored under their folder name, so two names that map to one folder would share
    # snapshots and reports ("HQ FW" and "HQ_FW")
    names = [source.safe_name(d["name"]) for d in devices]
    dup = {d["name"] for d in devices if names.count(source.safe_name(d["name"])) > 1}
    if dup:
        raise ValueError(f"duplicate device names: {', '.join(sorted(dup))}")
    return devices


def _history(path: str, entry: Dict[str, Any], keep: int = 400) -> List[Dict[str, Any]]:
    hist: List[Dict[str, Any]] = []
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                hist = json.load(fh)
        except (OSError, ValueError):
            hist = []
    hist.append(entry)
    hist = hist[-keep:]
    write_restricted(path, json.dumps(hist))
    return hist


def _write(path: str, text: str) -> None:
    write_restricted(path, text)  # group-readable for the web server, never world-readable


ALERT_DAYS = 7  # how long a risky-change alert stays on the dashboard


def _recent_alerts(path: str, new: List[str], now_iso: str) -> List[Dict[str, str]]:
    """Alerts of the last ALERT_DAYS days, newest first. Each run only sees the changes since the
    previous one, so without this an alert would disappear from the dashboard after one run."""
    items: List[Dict[str, str]] = []
    try:
        with open(path, encoding="utf-8") as fh:
            items = [x for x in json.load(fh) if isinstance(x, dict) and x.get("t") and x.get("a")]
    except (OSError, ValueError, TypeError):
        items = []
    try:
        cutoff = (_dt.datetime.fromisoformat(now_iso) - _dt.timedelta(days=ALERT_DAYS)).isoformat()
    except ValueError:
        cutoff = ""
    items = [x for x in items if str(x["t"]) >= cutoff] + [{"t": now_iso, "a": a} for a in new]
    if items or os.path.exists(path):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(items[-200:], fh)
    return list(reversed(items[-200:]))


def audit_device(dev: Dict[str, Any], out_dir: str, snap_dir: str, stale_days: int = 90, baseline_days: int = 30,
                 auditor: str = "", notifier: Optional[Callable[[str, List[str], int], None]] = None,
                 advisor: Optional[firmware.AdvisoryClient] = None, lifecycle: Optional[Dict[str, Any]] = None,
                 palette: str = "harbor") -> Dict[str, Any]:
    row: Dict[str, Any] = {"name": dev["name"], "label": dev.get("label", dev["name"]), "group": dev.get("group", ""),
                           "host": dev.get("host") or os.path.basename(dev.get("config") or ""), "vdom": dev["vdom"],
                           "status": "error", "when": _dt.datetime.now().strftime("%Y-%m-%d %H:%M")}
    try:
        token = None
        if dev.get("host") and not dev.get("config"):
            token = source.read_token(dev.get("token_file"), dev.get("token_env"))
        snap = source.take_snapshot(host=dev.get("host"), config=dev.get("config"), port=dev["port"], vdom=dev["vdom"],
                                    token=token, insecure=dev["insecure"], ca_file=dev.get("ca_file"),
                                    pin_sha256=dev.get("pin_sha256"),
                                    timeout=dev["timeout"], with_backup=dev.get("backup", True),
                                    with_events=dev.get("events", True), usage=dev.get("usage"),
                                    usage_since=dev.get("usage_since"))
        if dev.get("wan"):
            snap["wan_override"] = [x.strip() for x in dev["wan"].split(",") if x.strip()]
        if dev.get("not_wan"):
            snap["wan_exclude"] = [x.strip() for x in dev["not_wan"].split(",") if x.strip()]
        path = source.save_snapshot(snap, snap_dir, name=dev["name"])
        sdir = os.path.dirname(path)
        files = source.list_snapshots(sdir)
        prev_path = files[-2] if len(files) >= 2 else None
        base_path = source.pick_baseline(sdir, path, baseline_days)
        baseline = source.load_snapshot(base_path) if base_path else None
        adv = advisor.lookup(snap["device"].get("version")) if advisor else None
        res = checks.analyze(snap, stale_days=stale_days, baseline=baseline, advisories=adv, lifecycle_table=lifecycle)

        ddir = os.path.join(out_dir, source.safe_name(dev["name"]))
        makedirs_restricted(ddir)
        _write(os.path.join(ddir, "report.html"), report.html_report(res, snap, client=row["label"], auditor=auditor,
                                                                     palette=palette))
        _write(os.path.join(ddir, "findings.json"), json.dumps(res, indent=1))
        _write(os.path.join(ddir, "findings.csv"), report.findings_csv(res))
        _write(os.path.join(ddir, "practices.csv"), report.practices_csv(res))
        _write(os.path.join(ddir, "fix.txt"), report.remediation_cli(res))

        changes, alerts = 0, []
        if prev_path:
            d = diff.diff_snapshots(source.load_snapshot(prev_path), snap)
            changes = (sum(len(v) for v in d["policies"].values()) + len(d["objects"]))
            alerts = d["alerts"]
            if not d["empty"]:
                page = diff.render_html(d, palette)
                _write(os.path.join(ddir, "changes.html"), page)
                stamp = os.path.basename(path)[:-5]
                _write(os.path.join(ddir, f"changes-{stamp}.html"), page)
        if notifier:
            # alerts that could not be sent stay on disk and go out with the next run
            err = notify.deliver(os.path.join(ddir, "pending-alerts.json"),
                                 lambda todo: notifier(dev["name"], todo, changes), alerts)
            if err:  # a notification failure must not fail the audit, but it must be visible
                row["notify_error"] = err
        recent = _recent_alerts(os.path.join(ddir, "recent-alerts.json"), alerts, res["collected_at"])
        bp, fw = res["practices"], res["firmware"]
        hist = _history(os.path.join(ddir, "history.json"),
                        {"t": res["collected_at"], "score": res["score"], "grade": res["grade"], "bp": bp["percent"],
                         **{k: res["severity_counts"][k] for k in ("high", "medium", "low")}})
        dv = res["device"]
        cnt = fw["advisories"].get("counts") or {}
        row.update({
            "status": "ok", "hostname": dv.get("hostname"), "model": dv.get("model"), "version": dv.get("version"),
            "score": res["score"], "grade": res["grade"], "areas": res["areas"], "sev": res["severity_counts"],
            "exposed": report.internet_services(res), "risky": res["stats"].get("exposed_risky", 0),
            "cleanup": res["cleanup"]["percent"], "changes": changes, "alerts": alerts, "recent_alerts": recent,
            "prev_score": hist[-2]["score"] if len(hist) >= 2 else None,
            "trend": [h["score"] for h in hist[-30:]], "checks": sorted({f["check"] for f in res["findings"]}),
            "has_changes_page": os.path.exists(os.path.join(ddir, "changes.html")),
            "bp": {"pass": bp["counts"]["pass"], "assessed": bp["assessed"], "percent": bp["percent"]},
            "fw": {"version": fw["lifecycle"].get("version"), "branch": fw["lifecycle"].get("branch"),
                   "status": fw["lifecycle"]["status"], "eos": fw["lifecycle"].get("eos"),
                   "checked": fw["advisories"].get("checked"), "cves": cnt.get("total", 0), "kev": cnt.get("kev", 0),
                   "critical": cnt.get("critical", 0)},
            "quick_wins": len(res.get("quick_wins") or []),
        })
        source.prune(sdir)
    except Exception as e:  # one bad device must not stop the fleet run
        row["error"] = f"{type(e).__name__}: {e}"
        row["trace"] = traceback.format_exc(limit=3)
    return row


def run(devices: List[Dict[str, Any]], out_dir: str, snap_dir: str, workers: int = 6, stale_days: int = 90,
        baseline_days: int = 30, auditor: str = "", webhook: Optional[str] = None,
        syslog_target: Optional[str] = None, advisor: Optional[firmware.AdvisoryClient] = None,
        lifecycle: Optional[Dict[str, Any]] = None, palette: str = "harbor") -> Dict[str, Any]:
    makedirs_restricted(out_dir)
    for d in devices:
        if d.get("host") and d.get("insecure") and not d.get("pin_sha256"):
            print(f"warning: [{d['name']}] insecure = yes disables certificate checks; the API token can be captured "
                  "on the network. Set pin_sha256 (rulescope cert --host ...).", file=sys.stderr)

    def notifier(device: str, alerts: List[str], changes: int) -> None:
        if webhook:
            notify.webhook(webhook, device, alerts, changes)
        if syslog_target:
            notify.syslog(syslog_target, device, alerts)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        rows = list(ex.map(lambda d: audit_device(d, out_dir, snap_dir, stale_days, baseline_days, auditor,
                                                  notifier if (webhook or syslog_target) else None, advisor,
                                                  lifecycle, palette), devices))
    rows.sort(key=lambda r: (r.get("group", ""), r["name"]))
    summary = {"generated": _dt.datetime.now().strftime("%Y-%m-%d %H:%M"), "devices": rows,
               "lifecycle": firmware.lifecycle_table(_dt.date.today().isoformat(), lifecycle)}
    _write(os.path.join(out_dir, "fleet.json"), json.dumps(summary, indent=1))
    _write(os.path.join(out_dir, "index.html"), dashboard(summary, palette))
    return summary


# ---------------------------------------------------------------- dashboard

def _spark(vals: List[int]) -> str:
    if len(vals) < 2:
        return ""
    w, h = 90, 22
    step = w / (len(vals) - 1)
    pts = " ".join(f"{i * step:.1f},{h - 2 - (v / 100) * (h - 4):.1f}" for i, v in enumerate(vals))
    return (f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" aria-hidden="true">'
            f'<polyline points="{pts}" fill="none" style="stroke:var(--a-rules)" stroke-width="1.8"/></svg>')


FW_PILL = {"supported": ("ok", "Supported"), "eoes_soon": ("low", "Fixes end soon"), "eoes": ("medium", "Fixes ended"),
           "eos": ("high", "End of support"), "unknown": ("info", "Unknown")}


def dashboard(summary: Dict[str, Any], palette: str = "harbor") -> str:
    e = lambda x: escape("" if x is None else str(x))  # noqa: E731
    rows = summary["devices"]
    ok = [r for r in rows if r["status"] == "ok"]
    bad = [r for r in rows if r["status"] != "ok"]
    avg = round(sum(r["score"] for r in ok) / len(ok)) if ok else 0
    with_high = sum(1 for r in ok if r["sev"]["high"])
    n_alerts = sum(len(r.get("alerts", [])) for r in ok)
    changed = sum(1 for r in ok if r.get("changes"))
    fw_ok = [r for r in ok if r.get("fw")]
    out_support = sum(1 for r in fw_ok if r["fw"]["status"] == "eos")
    exploited = sum(1 for r in fw_ok if r["fw"].get("kev"))
    bp_rows = [r for r in ok if r.get("bp") and r["bp"]["assessed"]]
    bp_avg = round(sum(r["bp"]["percent"] for r in bp_rows) / len(bp_rows)) if bp_rows else 0

    def grade_cls(g: str) -> str:
        return {"A": "ok", "B": "ok", "C": "medium", "D": "high", "F": "high"}.get(g, "info")

    trs = []
    for r in ok:
        link = f'{e(source.safe_name(r["name"]))}/report.html'
        delta = "" if r.get("prev_score") is None else r["score"] - r["prev_score"]
        dtxt = "" if delta in ("", 0) else f'<span class="{"delta-up" if delta > 0 else "delta-down"}">{delta:+d}</span>'
        ch = (f'<a href="{e(source.safe_name(r["name"]))}/changes.html">{r["changes"]}</a>' if r.get("has_changes_page")
              else str(r.get("changes", 0)))
        al = f' <span class="pill high">{len(r["alerts"])} alert{"s" if len(r["alerts"]) != 1 else ""}</span>' if r.get("alerts") else ""
        risky = f" ({r['risky']} risky)" if r["risky"] else ""
        fw = r.get("fw") or {"status": "unknown"}
        cls, txt = FW_PILL.get(fw["status"], FW_PILL["unknown"])
        if fw.get("kev"):
            cls, txt = "high", f"{fw['kev']} exploited CVE{'s' if fw['kev'] != 1 else ''}"
        fw_cell = f'<span class="pill {cls}">{e(txt)}</span>'
        fw_rank = {"eos": 0, "eoes": 1, "eoes_soon": 2, "unknown": 3, "supported": 4}.get(fw["status"], 3) - (5 if fw.get("kev") else 0)
        bp = r.get("bp") or {"pass": 0, "assessed": 0, "percent": 0}
        trs.append(
            f'<tr><td><a href="{link}"><b>{e(r["label"])}</b></a><div class="dim">{e(r["name"])}, {e(r.get("hostname"))}</div></td>'
            f'<td>{e(r.get("group"))}</td><td class="mono">{e(r["host"])}</td><td>{e(r.get("model"))}</td>'
            f'<td class="mono">{e(r.get("version"))}</td><td data-v="{fw_rank}">{fw_cell}</td>'
            f'<td data-v="{r["score"]}"><span class="pill {grade_cls(r["grade"])}">{e(r["grade"])}</span> <b>{r["score"]}</b> {dtxt}</td>'
            f'<td>{_spark(r.get("trend", []))}</td>'
            f'<td data-v="{bp["percent"]}" class="num">{bp["pass"]}/{bp["assessed"]}</td>'
            f'<td data-v="{r["sev"]["high"]}" class="num">{r["sev"]["high"]}</td><td class="num">{r["sev"]["medium"]}</td><td class="num">{r["sev"]["low"]}</td>'
            f'<td data-v="{r["exposed"]}" class="num">{r["exposed"]}{risky}</td>'
            f'<td data-v="{r["cleanup"]}" class="num">{r["cleanup"]}%</td><td data-v="{r.get("changes", 0)}">{ch}{al}</td></tr>')
    common = Counter(c for r in ok for c in r.get("checks", []) if c in CHECKS)
    top = sorted(common.items(), key=lambda kv: (-kv[1], SEVERITY_ORDER[CHECKS[kv[0]][0]], CHECKS[kv[0]][2]))[:12]
    common_rows = "".join(
        f'<tr><td><span class="pill {CHECKS[c][0]}">{SEV_LABEL[CHECKS[c][0]]}</span></td><td>{e(CHECKS[c][2])}</td>'
        f'<td class="num">{n} of {len(ok)}</td></tr>' for c, n in top)
    versions = Counter(r.get("version") or "?" for r in ok)
    life = {b["branch"]: b for b in summary.get("lifecycle", [])}
    ver_rows = []
    for v, n in sorted(versions.items(), key=lambda kv: -kv[1]):
        sample = next((r for r in ok if (r.get("version") or "?") == v), {})
        fw = sample.get("fw") or {}
        cls, txt = FW_PILL.get(fw.get("status", "unknown"), FW_PILL["unknown"])
        eos = (life.get(fw.get("branch") or "") or {}).get("eos") or fw.get("eos") or ""
        cves = (f'{fw.get("cves", 0)}' + (f' <span class="pill high">{fw["kev"]} KEV</span>' if fw.get("kev") else "")
                if fw.get("checked") else '<span class="dim">not checked</span>')
        ver_rows.append(f'<tr><td class="mono">{e(v)}</td><td><span class="pill {cls}">{e(txt)}</span></td>'
                        f'<td class="mono">{e(eos)}</td><td>{cves}</td><td class="num">{n}</td>'
                        f'<td>{e(", ".join(r["name"] for r in ok if (r.get("version") or "?") == v))}</td></tr>')
    def recent(r: Dict[str, Any]) -> List[Dict[str, str]]:  # summaries written before 0.4.1 have no history
        return r.get("recent_alerts") or [{"t": r.get("when", ""), "a": a} for a in r.get("alerts", [])]

    alert_rows = "".join(f'<tr><td>{e(r["label"])}</td><td class="mono">{e(str(x.get("t", ""))[:16].replace("T", " "))}</td>'
                         f'<td>{e(x.get("a"))}</td></tr>' for r in ok for x in recent(r))
    notify_rows = "".join(f'<tr><td>{e(r["label"])}</td><td>{e(r.get("notify_error"))}</td></tr>'
                          for r in ok if r.get("notify_error"))
    err_rows = "".join(f'<tr><td>{e(r["label"])}</td><td class="mono">{e(r["host"])}</td><td>{e(r.get("error"))}</td></tr>' for r in bad)
    css = report.CSS + """.num{text-align:right;font-variant-numeric:tabular-nums}th[data-sort]{cursor:pointer}
th[data-sort]:hover{color:var(--link)}.wrap{max-width:1400px}.wrap .kpis{grid-template-columns:repeat(4,minmax(0,1fr))}
@media (max-width:900px){.wrap .kpis{grid-template-columns:repeat(2,minmax(0,1fr))}}"""
    js = """<script>document.querySelectorAll('th[data-sort]').forEach(function(th,i){th.addEventListener('click',function(){
var t=th.closest('table'),b=t.tBodies[0],idx=[].indexOf.call(th.parentNode.children,th),asc=th.dataset.dir!=='asc';th.dataset.dir=asc?'asc':'desc';
[].slice.call(b.rows).sort(function(x,y){var a=x.cells[idx],c=y.cells[idx];var va=a.dataset.v!==undefined?+a.dataset.v:a.textContent.trim(),
vc=c.dataset.v!==undefined?+c.dataset.v:c.textContent.trim();return (va>vc?1:va<vc?-1:0)*(asc?1:-1)}).forEach(function(r){b.appendChild(r)})})});</script>"""
    heads = ["Device", "Group", "Host", "Model", "FortiOS", "Firmware", "Score", "Trend", "Best practice", "High", "Med", "Low",
             "Exposed", "Cleanup", "Changes"]
    th = "".join(f'<th data-sort>{h}</th>' if h != "Trend" else "<th>Trend</th>" for h in heads)
    return f"""{html_open(palette)}<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Firewall fleet overview</title>{THEME_HEAD}<style>{css}</style></head><body><div class="wrap">
<header class="top"><div><div class="kicker">rulescope fleet</div><h1>Firewall fleet overview</h1>
<div class="meta">Generated <b>{e(summary['generated'])}</b>, {len(rows)} devices</div></div>
<div class="page-tools">{CONTROLS}</div></header>
<div class="kpis"><div style="--c:var(--brand-2)"><div class="n">{len(ok)}/{len(rows)}</div><div class="l">Devices audited</div></div>
<div style="--c:var(--a-rules)"><div class="n">{avg}</div><div class="l">Average score</div></div>
<div style="--c:var(--good)"><div class="n">{bp_avg}%</div><div class="l">Best practices met (average)</div></div>
<div style="--c:var(--sev-high)"><div class="n">{with_high}</div><div class="l">Devices with high findings</div></div>
<div style="--c:var(--a-device)"><div class="n">{out_support}</div><div class="l">Devices on unsupported FortiOS</div></div>
<div style="--c:var(--sev-high)"><div class="n">{exploited}</div><div class="l">Devices with exploited CVEs</div></div>
<div style="--c:var(--a-exposure)"><div class="n">{sum(r['exposed'] for r in ok)}</div><div class="l">Internet-exposed services</div></div>
<div style="--c:var(--sev-medium)"><div class="n">{n_alerts}</div><div class="l">Risky-change alerts ({changed} devices changed)</div></div></div>
{('<h2>Alerts</h2><p class="dim">Risky changes of the last ' + str(ALERT_DAYS) + ' days.</p><table><thead><tr><th>Device</th><th>Seen (UTC)</th><th>Alert</th></tr></thead><tbody>' + alert_rows + '</tbody></table>') if alert_rows else ''}
{('<h2>Notifications not delivered</h2><p class="dim">These alerts are kept and sent again with the next run.</p><table><thead><tr><th>Device</th><th>Error</th></tr></thead><tbody>' + notify_rows + '</tbody></table>') if notify_rows else ''}
<h2>Devices</h2><div class="tw"><table class="exp"><thead><tr>{th}</tr></thead><tbody>{''.join(trs)}</tbody></table></div>
<h2>FortiOS versions</h2><table><thead><tr><th>Version</th><th>Lifecycle</th><th>End of support</th><th>Known CVEs</th>
<th class="num">Devices</th><th>Names</th></tr></thead><tbody>{''.join(ver_rows)}</tbody></table>
<h2>Most common findings</h2><table><thead><tr><th>Severity</th><th>Finding</th><th class="num">Devices</th></tr></thead>
<tbody>{common_rows}</tbody></table>
{('<h2>Failed</h2><table><thead><tr><th>Device</th><th>Host</th><th>Error</th></tr></thead><tbody>' + err_rows + '</tbody></table>') if err_rows else ''}
<footer><p>rulescope {__version__}. This page lists weaknesses of production firewalls: serve it only to administrators.</p></footer>
</div>{THEME_JS}{js}</body></html>"""
