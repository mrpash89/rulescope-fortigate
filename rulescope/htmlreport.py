"""The client-facing HTML audit report (self-contained, light + dark, printable)."""
from __future__ import annotations

import datetime as _dt
from collections import OrderedDict
from typing import Any, Dict, List

from . import __version__
from .catalog import AREAS, CHECKS, CONTROL_NAMES, EFFORT, EFFORT_LABEL, SEV_LABEL, SEVERITY_ORDER
from .practices import DOMAINS, SOURCES, STATUS_LABEL
from .report import _e, _grouped, _target, _ts, _worst, executive_summary, internet_services, remediation_cli
from .safety import safe_url
from .ui import AREA_VAR, CONTROLS, CSS, LOGO, THEME_HEAD, THEME_JS, html_open

SEVS = ("high", "medium", "low", "info")
GRADE_COLOR = {"A": ("--good", "--good-bg"), "B": ("--good", "--good-bg"), "C": ("--sev-low", "--sev-low-bg"),
               "D": ("--sev-medium", "--sev-medium-bg"), "F": ("--sev-high", "--sev-high-bg")}


def _c(area: str) -> str:
    return f"--c:var({AREA_VAR[area]})"


def _pill(sev: str) -> str:
    return f'<span class="pill {sev}">{SEV_LABEL[sev]}</span>'


def _achip(area: str) -> str:
    return f'<span class="achip" style="{_c(area)}"><span class="dot"></span>{_e(AREAS[area][0])}</span>'


def _tw(head: str, rows: List[str], cls: str = "") -> str:
    return f'<div class="tw"><table class="{cls}"><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def _sec(sid: str, title: str, body: str, color: str = "", aside: str = "") -> str:
    style = f' style="{color}"' if color else ""
    aside_html = f'<span class="aside">{aside}</span>' if aside else ""
    return (f'<section id="{sid}"{style}><div class="sec-h"><h2>{_e(title)}</h2>{aside_html}</div>{body}</section>')


# ---------------------------------------------------------------- overview

FW_STATUS = {"supported": ("--good", "Supported"), "eoes_soon": ("--sev-low", "Fixes end soon"),
             "eoes": ("--sev-medium", "Engineering support ended"), "eos": ("--sev-high", "End of support"),
             "unknown": ("--sev-info", "Lifecycle unknown")}


def _fd(iso: Any) -> str:
    """'2026-09-30' -> '30 Sep 2026' (unambiguous for every reader)."""
    try:
        return _dt.date.fromisoformat(str(iso)[:10]).strftime("%d %b %Y").lstrip("0")
    except ValueError:
        return str(iso or "")


def _bp_color(pct: int) -> str:
    return "--good" if pct >= 80 else "--sev-low" if pct >= 60 else "--sev-medium" if pct >= 40 else "--sev-high"


def _meter(parts: List[tuple], total: int, label: str) -> str:
    if not total:
        return '<div class="meter"></div>'
    segs = "".join(f'<span style="width:{100 * n / total:.2f}%;background:var({c})"></span>' for n, c in parts if n)
    return f'<div class="meter" role="img" aria-label="{_e(label)}">{segs}</div>'


def _overview(result: Dict[str, Any], name: str, auditor: str) -> str:
    d, sc, c = result["device"], result["severity_counts"], result["cleanup"]
    src = {"api": "Live API", "config": "Config backup"}.get(result["source"], result["source"])
    usage = result.get("usage_source")
    usage_txt = "FortiGate counters" if usage == "counters" else (usage.replace("import:", "imported, ") if usage else "none")
    facts = [("Assessed", result["collected_at"][:10]), ("Device", d.get("hostname") or "-"), ("Model", d.get("model") or "-"),
             ("FortiOS", (d.get("version") or "-") + (f" build {d['build']}" if d.get("build") else "")),
             ("Serial", d.get("serial") or "-"), ("VDOM", d.get("vdom")), ("Data", src), ("Usage data", usage_txt)]
    if auditor:
        facts.insert(1, ("Prepared by", auditor))
    facts_html = "".join(f"<div><dt>{_e(k)}</dt><dd>{_e(v)}</dd></div>" for k, v in facts)
    hero = (f'<div class="hero"><div><h1>{_e(name)}</h1><div class="sub">Firewall security audit</div></div>'
            f'<dl class="facts">{facts_html}</dl></div>')

    g, gbg = GRADE_COLOR.get(result["grade"], ("--sev-info", "--sev-info-bg"))
    verdict = (f"Held at D or lower while {sc['high']} high-severity finding{'s' if sc['high'] != 1 else ''} remain."
               if sc["high"] else "No high-severity findings.")
    per_area: Dict[str, int] = {}
    for f in result["findings"]:
        per_area[f["area"]] = per_area.get(f["area"], 0) + 1
    bars = []
    for a, v in result["areas"].items():
        n = per_area.get(a, 0)
        tip = f"{AREAS[a][0]}: {v}/100, {n} finding{'s' if n != 1 else ''}"
        bars.append(f'<a class="bar" href="#area-{a}" style="{_c(a)}" data-tip="{_e(tip)}">'
                    f'<span class="name"><span class="dot"></span>{_e(AREAS[a][0])}</span>'
                    f'<span class="track"><i style="width:{max(v, 2)}%"></i></span><b>{v}</b></a>')
    grade = (f'<div class="key grade" style="--c:var({g});--g:var({g});--g-bg:var({gbg})">'
             f'<div class="gtop"><div class="letter" aria-label="Grade {result["grade"]}">{_e(result["grade"])}</div>'
             f'<div><div class="lbl">Security score</div><div class="score">{result["score"]}<small> / 100</small></div>'
             f'<div class="lbl" style="margin-top:4px">{_e(verdict)}</div></div></div>'
             f'<div class="bars" aria-label="Score by area">{"".join(bars)}</div></div>')

    high_titles = list(OrderedDict((f["check"], f["title"]) for f in result["findings"] if f["severity"] == "high").items())
    hl = "".join(f'<li><a href="#check-{cid}">{_e(t)}</a></li>' for cid, t in high_titles[:3]) or "<li>Nothing urgent.</li>"
    more = f'<li><a href="#findings">and {len(high_titles) - 3} more</a></li>' if len(high_titles) > 3 else ""
    highs = (f'<div class="key" style="--c:var(--sev-high)"><div class="lbl">Fix first</div>'
             f'<div class="big">{sc["high"]}</div><div class="lbl">high-severity findings</div><ul>{hl}{more}</ul></div>')

    n_exp = internet_services(result)
    risky = sorted({s for x in result.get("exposure", []) for s in x.get("risky", [])})
    risky_html = ("".join(f'<span class="svc">{_e(s)}</span>' for s in risky) if risky
                  else '<span class="dim" style="font-size:13px">No high-risk services among them.</span>')
    exposure = (f'<div class="key" style="{_c("exposure")}"><div class="lbl">Internet exposure</div>'
                f'<div class="big">{n_exp}</div><div class="lbl">services reachable from the internet</div>'
                f'<div>{risky_html}</div><a class="more" href="#exposure">See what is exposed</a></div>')

    fw = result.get("firmware") or {}
    lc, adv = fw.get("lifecycle") or {}, fw.get("advisories") or {}
    fcol, ftxt = FW_STATUS.get(lc.get("status", "unknown"), FW_STATUS["unknown"])
    cnt = adv.get("counts") or {}
    if adv.get("checked") and cnt.get("kev"):
        fcol = "--sev-high"
    life = {"supported": f"Supported until {_fd(lc.get('eos'))}",
            "eoes_soon": f"Fixes end {_fd(lc.get('eoes'))}; support ends {_fd(lc.get('eos'))}",
            "eoes": f"Fixes ended {_fd(lc.get('eoes'))}; support ends {_fd(lc.get('eos'))}",
            "eos": f"Out of support since {_fd(lc.get('eos'))}"}.get(lc.get("status"), "Branch not in the lifecycle table")
    vuln = (f"{cnt.get('total', 0)} known CVE{'s' if cnt.get('total') != 1 else ''}"
            + (f", <b style=\"color:var(--bad-ink)\">{cnt['kev']} exploited in the wild</b>" if cnt.get("kev") else "")
            if adv.get("checked") else "Known vulnerabilities not checked")
    fw_tile = (f'<div class="key" style="--c:var({fcol})"><div class="lbl">Firmware</div>'
               f'<div class="row"><div class="big sm">{_e(lc.get("version") or d.get("version") or "?")}</div>'
               f'<span class="pill {"ok" if lc.get("status") == "supported" else "high" if lc.get("status") == "eos" else "medium" if lc.get("status") in ("eoes", "eoes_soon") else "info"}">'
               f'{_e(ftxt)}</span></div><ul><li>{_e(life)}</li><li>{vuln}</li></ul>'
               f'<a class="more" href="#firmware">Lifecycle and advisories</a></div>')

    bp = result.get("practices") or {"counts": {}, "assessed": 0, "percent": 0, "total": 0}
    bc = bp["counts"]
    meter = _meter([(bc.get("pass", 0), "--good"), (bc.get("partial", 0), "--sev-medium"), (bc.get("fail", 0), "--sev-high")],
                   bp["assessed"], f"{bc.get('pass', 0)} pass, {bc.get('partial', 0)} partial, {bc.get('fail', 0)} fail")
    open_n = bc.get("unknown", 0) + bc.get("manual", 0)
    bp_tile = (f'<div class="key" style="--c:var({_bp_color(bp["percent"])})"><div class="lbl">Best-practice baseline</div>'
               f'<div class="big">{bc.get("pass", 0)}<small style="font-size:18px;color:var(--ink-3)"> / {bp["assessed"]}</small></div>'
               f'<div class="lbl">practices met of {bp["assessed"]} assessed</div>{meter}'
               f'<ul><li>{bc.get("fail", 0)} failed, {bc.get("partial", 0)} partial</li>'
               f'<li>{open_n} need data or a manual check, {bc.get("na", 0)} not applicable</li></ul>'
               f'<a class="more" href="#practices">Fortinet, CIS and Cyber Centre baseline</a></div>')

    qw = result.get("quick_wins") or []
    ql = "".join(f'<li><a href="#check-{q["check"]}">{_e(q["title"])}</a></li>' for q in qw[:3]) or "<li>None found.</li>"
    qw_tile = (f'<div class="key" style="--c:var(--brand-2)"><div class="lbl">Quick wins</div>'
               f'<div class="big">{len(qw)}</div><div class="lbl">one-setting fixes with ready commands</div><ul>{ql}</ul>'
               f'{"<a class=more href=#quickwins>Commands</a>" if qw else ""}</div>')

    cleanup = (f'<div class="key" style="{_c("rules")}"><div class="lbl">Cleanup potential</div>'
               f'<div class="big">{c["percent"]}%</div><div class="lbl">of rules can be removed</div>'
               f'<ul><li>{c["policies"]} of {c["total"]} rules unused, redundant, shadowed, expired or disabled</li>'
               f'<li>{c["objects"]} unreferenced object{"s" if c["objects"] != 1 else ""}</li></ul></div>')

    total = sum(sc.values())
    segs = "".join(f'<span style="width:{100 * sc[s] / total:.2f}%;background:var(--sev-{s})" tabindex="0" '
                   f'data-tip="{SEV_LABEL[s]}: {sc[s]}"></span>' for s in SEVS if sc[s]) if total else ""
    legend = "".join(f'<li><span class="sq" style="--c:var(--sev-{s})"></span>{SEV_LABEL[s]}<b>{sc[s]}</b></li>' for s in SEVS)
    checks_n = len({f["check"] for f in result["findings"]})
    doms = []
    for dom in DOMAINS:
        its = [i for i in bp.get("items", []) if i["domain"] == dom]
        k = {st: sum(1 for i in its if i["status"] == st) for st in ("pass", "partial", "fail")}
        n = sum(k.values())
        if not its:
            continue
        doms.append(f'<a class="bar dom" href="#practices"><span class="name">{_e(dom)}</span>'
                    + _meter([(k["pass"], "--good"), (k["partial"], "--sev-medium"), (k["fail"], "--sev-high")], n,
                             f"{dom}: {k['pass']} pass, {k['partial']} partial, {k['fail']} fail")
                    + f'<b>{k["pass"]}/{n}</b></a>')
    row2 = (f'<div class="row2"><div class="panel"><h3>Findings by severity</h3><div class="stack" role="img" '
            f'aria-label="{total} findings: {sc["high"]} high, {sc["medium"]} medium, {sc["low"]} low, {sc["info"]} info">{segs}</div>'
            f'<ul class="legend">{legend}</ul>{_largest(result)}<p class="dim" style="margin:10px 0 0;font-size:13px">'
            f'{total} findings from {checks_n} checks.</p></div>'
            f'<div class="panel"><h3>Best practice by domain</h3><div class="bars">{"".join(doms)}</div>'
            f'<p class="dim" style="margin:10px 0 0;font-size:13px">Practices met of those assessed; '
            f'<a href="#practices">see the evidence</a>.</p></div></div>')
    return (f'<section id="overview">{hero}<div class="keygrid">{grade}{highs}{exposure}{fw_tile}{bp_tile}{qw_tile}'
            f'{cleanup}</div>{row2}</section>')


def _largest(result: Dict[str, Any], n: int = 4) -> str:
    grouped = _grouped(result["findings"])
    top = sorted(grouped.items(), key=lambda kv: (-len(kv[1]), SEVERITY_ORDER[_worst(kv[1])]))[:n]
    if not top:
        return ""
    items = "".join(f'<li>{_pill(_worst(items))}<a href="#check-{cid}">{_e(CHECKS[cid][2])}</a><b>{len(items)}</b></li>'
                    for cid, items in top)
    return f'<ul class="groups" aria-label="Largest finding groups">{items}</ul>'


def _wan_details(result: Dict[str, Any]) -> str:
    why = result.get("wan_reasons") or {n: [] for n in result.get("wan_interfaces", [])}
    if not why:
        return ('<p class="lede">No internet-facing interface was identified. Rerun with --wan to name them.</p>')
    items = "".join(f"<li><b>{_e(n)}</b>: {_e(', '.join(r) or 'listed')}</li>" for n, r in sorted(why.items()))
    return (f'<details class="whywan"><summary>Internet-facing interfaces: {_e(", ".join(sorted(why)))}</summary>'
            f'<ul>{items}</ul><p class="dim" style="margin:6px 0 0">Wrong? Rerun with --wan or --not-wan.</p></details>')


def _summary(result: Dict[str, Any], name: str, redacted: bool) -> str:
    paras = "".join(f"<p>{_e(p)}</p>" for p in executive_summary(result, name))
    notes = list(result.get("notes", []))
    if redacted:
        notes.insert(0, "Names, addresses, hostname and serial in this report are pseudonymized.")
    icon = ('<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">'
            '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.5"/></svg>')
    note = (f'<div class="note">{icon}<div>{"".join(f"<p>{_e(n)}</p>" for n in notes)}</div></div>' if notes else "")
    return _sec("summary", "Executive summary", f'<div class="summary">{paras}</div>{note}')


def _actions(result: Dict[str, Any]) -> str:
    acts = result.get("top_actions", [])
    if not acts:
        return ""
    items = []
    for a in acts:
        area = CHECKS[a["check"]][1]
        more = f" and {a['more']} more" if a["more"] else ""
        items.append(
            f'<li style="{_c(area)}"><div>{_pill(a["severity"])} <span class="t">{_e(a["title"])}</span> '
            f'<span class="dim">({a["count"]})</span></div><div class="go"><a href="#check-{a["check"]}">Details</a></div>'
            f'<div class="rec">{_e(a["recommendation"])}</div>'
            f'<div class="tg">{_achip(area)} &nbsp; Affects {_e(", ".join(a["targets"]))}{_e(more)}</div></li>')
    return _sec("actions", "Priority actions",
                '<p class="lede">Ordered by risk: severity first, then how much of the score the area carries.</p>'
                f'<ol class="actions">{"".join(items)}</ol>')


def _progress(result: Dict[str, Any]) -> str:
    comp = result.get("comparison")
    if not comp:
        return ""
    delta = result["score"] - comp["score_before"]
    cls = "delta-up" if delta > 0 else "delta-down" if delta < 0 else "dim"
    sign = "+" if delta > 0 else ""

    def table(items: List[Dict[str, Any]]) -> str:
        if not items:
            return '<div class="empty">None.</div>'
        rows = [f'<tr><td>{_pill(f["severity"])}</td><td>{_e(f["title"])}</td><td>{_e(f["detail"])}</td></tr>' for f in items]
        return _tw("<th>Severity</th><th>Finding</th><th>Detail</th>", rows)

    keys = (f'<div class="kpis" style="grid-template-columns:repeat(4,minmax(0,1fr));margin:0 0 14px">'
            f'<div><div class="n">{comp["score_before"]} &rarr; {result["score"]} <span class="{cls}">{sign}{delta}</span></div>'
            f'<div class="l">Score ({_e(comp["grade_before"])} &rarr; {_e(result["grade"])})</div></div>'
            f'<div style="--c:var(--good)"><div class="n">{len(comp["resolved"])}</div><div class="l">Resolved</div></div>'
            f'<div style="--c:var(--sev-high)"><div class="n">{len(comp["new"])}</div><div class="l">New</div></div>'
            f'<div><div class="n">{comp["persisting"]}</div><div class="l">Still open</div></div></div>')
    body = (keys + f'<div class="two"><div><h3 style="margin-bottom:8px">Resolved</h3>{table(comp["resolved"])}</div>'
            f'<div><h3 style="margin-bottom:8px">New</h3>{table(comp["new"])}</div></div>')
    return _sec("progress", f"Progress since {comp['baseline_date'][:10]}", body)


def _quick_wins(result: Dict[str, Any]) -> str:
    qw = result.get("quick_wins") or []
    if not qw:
        return ""
    items = []
    for q in qw:
        more = f" and {q['more']} more" if q["more"] else ""
        items.append(f'<li style="{_c(CHECKS[q["check"]][1])}">{_pill(q["severity"])}<span class="t">'
                     f'<a href="#check-{q["check"]}">{_e(q["title"])}</a><span class="tg">{_e(", ".join(q["targets"]) + more)}'
                     f'</span></span><span class="dim">{q["count"]}</span></li>')
    cli = remediation_cli(result, only={q["check"] for q in qw}, safe_only=True, title="quick wins")
    return _sec("quickwins", "Quick wins",
                '<p class="lede">Single settings that close a finding without touching allowed traffic or management access. '
                'The script below contains only these changes; review it and apply it in one session.</p>'
                f'<ul class="qw">{"".join(items)}</ul><div class="codebox"><button type="button" class="copy" data-copy>Copy</button>'
                f'<pre>{_e(cli)}</pre></div>')


def _practices(result: Dict[str, Any]) -> str:
    bp = result.get("practices")
    if not bp:
        return ""
    c = bp["counts"]
    order = ["fail", "partial", "pass", "manual", "unknown", "na"]
    chips = "".join(f'<button type="button" class="chip" data-bpst="{st}" aria-pressed="true"><span class="pill {st}" '
                    f'style="padding:0 6px 0 5px;background:none;box-shadow:none"></span>{STATUS_LABEL[st]} <span class="n">{c[st]}</span></button>'
                    for st in order if c.get(st))
    meter = _meter([(c["pass"], "--good"), (c["partial"], "--sev-medium"), (c["fail"], "--sev-high")], bp["assessed"],
                   f"{c['pass']} pass, {c['partial']} partial, {c['fail']} fail of {bp['assessed']} assessed")
    head = (f'<div class="bpbar"><b>{c["pass"]} of {bp["assessed"]} assessed practices met ({bp["percent"]}%)</b>{meter}'
            f'<span class="dim" style="font-size:13px">{bp["total"]} practices in the baseline</span></div>'
            f'<div class="filters" style="margin-top:-4px"><span class="lbl">Status</span>{chips}</div>')
    rows = []
    for dom in DOMAINS:
        its = [i for i in bp["items"] if i["domain"] == dom]
        if not its:
            continue
        ok = sum(1 for i in its if i["status"] == "pass")
        assessed = sum(1 for i in its if i["status"] in ("pass", "partial", "fail"))
        rows.append(f'<tr class="dom" data-dom="{_e(dom)}"><td colspan="4">{_e(dom)}<span>{ok} of {assessed} assessed met</span></td></tr>')
        for i in its:
            links = "".join(f'<a href="#check-{cid}">{_e(CHECKS[cid][2])}</a>' for cid in i["checks"])
            rows.append(f'<tr data-st="{i["status"]}" data-domrow="{_e(dom)}" id="bp-{i["id"]}">'
                        f'<td class="st"><span class="pill {i["status"]}">{STATUS_LABEL[i["status"]]}</span></td>'
                        f'<td class="pr">{_e(i["title"])}<span class="src">{_e(i["sources"])}</span></td>'
                        f'<td class="ev">{_e(i["evidence"])}</td><td class="lk">{links}</td></tr>')
    table = _tw("<th>Status</th><th>Practice</th><th>Evidence from this configuration</th><th>Findings</th>", rows, "bp")
    src = "; ".join(f"{k}: {v}" for k, v in SOURCES.items())
    return _sec("practices", "Best-practice baseline",
                '<p class="lede">FortiGate hardening practices from Fortinet, the CIS FortiGate benchmark and the Canadian Centre '
                'for Cyber Security, each checked against this configuration. "Not assessed" means the data was not '
                'available, never that the practice passed.</p>' + head + table +
                f'<p class="dim" style="font-size:12.5px;margin-top:10px">Sources. {_e(src)}. CIS numbers follow the 7.0.x v1.4.0 '
                'benchmark unless marked 7.4.</p>', aside=f"{c['pass']}/{bp['assessed']} met")


def _timeline(lc: Dict[str, Any], today: str) -> str:
    try:
        ga, eoes, eos, now = (_dt.date.fromisoformat(x) for x in (lc["ga"], lc["eoes"], lc["eos"], today))
    except (TypeError, ValueError, KeyError):
        return ""
    start, end = ga, max(eos, now) + _dt.timedelta(days=45)
    span = max((end - start).days, 1)

    def pct(x: _dt.date) -> float:
        return max(0.0, min(100.0, 100 * (x - start).days / span))
    segs = [(pct(eoes) - pct(ga), "--good"), (pct(eos) - pct(eoes), "--sev-medium"), (100 - pct(eos), "--sev-high")]
    rail = "".join(f'<span style="width:{w:.2f}%;background:var({c})"></span>' for w, c in segs if w > 0)
    legend = (f'<li><span class="sq" style="--c:var(--good)"></span>Fixes and patches until {_fd(lc["eoes"])}</li>'
              f'<li><span class="sq" style="--c:var(--sev-medium)"></span>Technical support only until {_fd(lc["eos"])}</li>'
              f'<li><span class="sq" style="--c:var(--sev-high)"></span>No support or security fixes after that</li>')
    return (f'<div class="lc" role="img" aria-label="FortiOS {lc["branch"]}: GA {lc["ga"]}, end of engineering support '
            f'{lc["eoes"]}, end of support {lc["eos"]}, today {today}"><div class="rail">{rail}</div>'
            f'<span class="tick l" style="left:0">Released {_fd(lc["ga"])}</span>'
            f'<span class="today" style="left:{pct(now):.2f}%"><b>Today</b></span></div>'
            f'<ul class="legend lcl">{legend}</ul>')


def _firmware(result: Dict[str, Any]) -> str:
    fw = result.get("firmware")
    if not fw:
        return ""
    lc, adv = fw["lifecycle"], fw["advisories"]
    today = result["collected_at"][:10]
    col, txt = FW_STATUS.get(lc["status"], FW_STATUS["unknown"])
    pill_cls = {"supported": "ok", "eos": "high", "eoes": "medium", "eoes_soon": "low"}.get(lc["status"], "info")
    kv = [("Version", f"FortiOS {lc.get('version') or '?'}" + (f" build {fw.get('build')}" if fw.get("build") else "")),
          ("Model", fw.get("model") or "-"), ("Branch", lc.get("branch") or "-")]
    if lc.get("eos"):
        kv += [("Engineering support until", lc["eoes"]), ("Support until", lc["eos"])]
    kvs = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in kv)
    left = (f'<div class="panel" style="border-top:4px solid var({col})"><h3>Lifecycle <span class="pill {pill_cls}" '
            f'style="margin-left:6px">{_e(txt)}</span></h3><dl class="kvs">{kvs}</dl>{_timeline(lc, today) if lc.get("eos") else ""}'
            f'<p class="dim" style="font-size:12.5px;margin:0">Dates from Fortinet\'s product life cycle page, checked '
            f'{_e(lc.get("checked"))}. Replace them with --lifecycle-file if Fortinet changes them.</p></div>')
    cnt = adv.get("counts") or {}
    if adv.get("checked"):
        stat = [("Known CVEs", cnt.get("total", 0), "--sev-info"), ("Exploited in the wild (CISA KEV)", cnt.get("kev", 0), "--sev-high"),
                ("Critical (CVSS 9+)", cnt.get("critical", 0), "--sev-high"), ("High (CVSS 7 to 8.9)", cnt.get("high", 0), "--sev-medium")]
        kpis = "".join(f'<div style="--c:var({c})"><div class="n">{n}</div><div class="l">{_e(l)}</div></div>' for l, n, c in stat)
        when = (adv.get("fetched") or "")[:10]
        right = (f'<div class="panel"><h3>Known vulnerabilities</h3><div class="kpis" style="grid-template-columns:repeat(2,minmax(0,1fr));'
                 f'margin:0 0 10px">{kpis}</div><p class="dim" style="font-size:12.5px;margin:0">{_e(adv.get("source"))}, CVEs whose '
                 f'affected versions include {_e(lc.get("version"))}; retrieved {_e(when)}'
                 f'{" from the local cache" if adv.get("from_cache") else ""}. A CVE may already be mitigated by a workaround: '
                 'check the linked advisory.</p></div>')
    else:
        why = adv.get("error") or "advisory lookup is off"
        right = ('<div class="panel"><h3>Known vulnerabilities</h3><p>Not checked for this report: ' + _e(why) + '.</p>'
                 '<p class="dim" style="font-size:13px">Run with <code>--advisories online</code> to look up this exact version in '
                 'the NIST National Vulnerability Database, including CISA\'s list of actively exploited vulnerabilities. '
                 'Results are cached, so later runs and air-gapped installs can use <code>--advisories cache</code>.</p></div>')
    body = f'<div class="fwgrid">{left}{right}</div>'
    cves = adv.get("cves") or []
    if cves:
        rows = []
        for cv in cves[:60]:
            score = cv.get("cvss")
            sev = "high" if (score or 0) >= 9 else "medium" if (score or 0) >= 7 else "low" if (score or 0) >= 4 else "info"
            fgir = f'<div class="dim">{_e(cv["fgir"])}</div>' if cv.get("fgir") else ""
            kev = '<span class="pill high">Exploited</span>' if cv.get("kev") else ""
            sc_txt = "" if score is None else f"{score:g}"
            href = safe_url(cv.get("url")) or f"https://nvd.nist.gov/vuln/detail/{_e(cv.get('id', ''))}"
            rows.append(f'<tr><td class="mono" style="white-space:nowrap"><a href="{_e(href)}" target="_blank" '
                        f'rel="noopener">{_e(cv["id"])}</a>{fgir}</td><td>{_pill(sev)} <b>{sc_txt}</b></td><td>{kev}</td>'
                        f'<td class="mono">{_e(cv.get("published"))}</td><td>{_e(cv.get("title"))}</td></tr>')
        more = f'<p class="dim" style="font-size:13px">{len(cves) - 60} more in findings.json.</p>' if len(cves) > 60 else ""
        body += _tw("<th>CVE</th><th>CVSS</th><th>KEV</th><th>Published</th><th>Title</th>", rows, "exp") + more
    brows = "".join(f'<tr class="{"cur" if b["branch"] == lc.get("branch") else ""}"><td class="mono">{_e(b["branch"])}</td>'
                    f'<td class="mono">{_e(b["ga"])}</td><td class="mono">{_e(b["eoes"])}</td><td class="mono">{_e(b["eos"])}</td>'
                    f'<td><span class="pill {"ok" if b["status"] == "supported" else "high" if b["status"] == "eos" else "medium"}">'
                    f'{_e({"supported": "Supported", "eoes": "Support only", "eos": "End of support"}[b["status"]])}</span></td></tr>'
                    for b in fw.get("branches", []))
    body += ('<details class="whywan" style="margin-top:12px"><summary>All FortiOS branches</summary>'
             + _tw("<th>Branch</th><th>GA</th><th>End of engineering support</th><th>End of support</th><th>Status</th>",
                   [brows]) + "</details>")
    return _sec("firmware", "Firmware and advisories", body, f"--c:var({col})", _e(txt))


def _exposure(result: Dict[str, Any]) -> str:
    rows_in = result.get("exposure", [])
    lede = '<p class="lede">What the internet can reach through this firewall.</p>' + _wan_details(result)
    if not rows_in:
        return _sec("exposure", "Internet exposure", lede + '<div class="empty">No inbound rules, WAN management access, '
                    'SSL-VPN or IPsec listeners facing the internet were found.</div>', _c("exposure"))
    rows = []
    for x in sorted(rows_in, key=lambda x: (SEVERITY_ORDER[x["severity"]], x["kind"], x.get("policyid") or 0)):
        risky = "".join(f'<span class="svc">{_e(s)}</span>' for s in x.get("risky", []))
        rule = (f'<a href="#inv-{_e(x["policyid"])}">#{_e(x["policyid"])}</a>' if x.get("policyid") is not None
                else _e(x.get("label") or ""))
        hits = "" if x.get("hits") is None else "{:,}".format(x["hits"])
        rows.append(f'<tr><td>{_pill(x["severity"])}</td><td>{_e(x["kind"])}</td><td>{_e(x["source"])}</td>'
                    f'<td class="mono">{_e(x["external"])}</td><td>{_e(x["internal"])}</td>'
                    f'<td>{_e(x["service"])}<div>{risky}</div></td><td>{_e(x["protection"])}</td><td>{rule}</td>'
                    f'<td class="num">{hits}</td></tr>')
    head = ("<th>Risk</th><th>Type</th><th>From</th><th>Internet side</th><th>Reaches</th><th>Service</th>"
            "<th>Protection</th><th>Rule</th><th class='num'>Hits</th>")
    return _sec("exposure", "Internet exposure", lede + _tw(head, rows, "exp"), _c("exposure"),
                f"{internet_services(result)} reachable services")


# ---------------------------------------------------------------- findings

def _findings(result: Dict[str, Any]) -> str:
    grouped = _grouped(result["findings"])
    if not grouped:
        return _sec("findings", "Findings", '<div class="empty">No findings.</div>')
    sc = result["severity_counts"]
    per_area: Dict[str, int] = {}
    for f in result["findings"]:
        per_area[f["area"]] = per_area.get(f["area"], 0) + 1
    chips = ['<span class="lbl">Severity</span>']
    chips += [f'<button type="button" class="chip" data-fsev="{s}" aria-pressed="true"><span class="sq" '
              f'style="--c:var(--sev-{s})"></span>{SEV_LABEL[s]} <span class="n">{sc[s]}</span></button>' for s in SEVS if sc[s]]
    chips.append('<span class="vsep"></span><span class="lbl">Area</span>')
    chips += [f'<button type="button" class="chip" data-farea="{a}" aria-pressed="true" style="{_c(a)}"><span class="dot"></span>'
              f'{_e(AREAS[a][0])} <span class="n">{per_area[a]}</span></button>' for a in AREAS if per_area.get(a)]
    total = len(result["findings"])
    filters = (f'<div class="filters" role="search">{"".join(chips)}'
               '<input class="search" type="search" placeholder="Search policy ID, object, interface or text" '
               'aria-label="Search findings" data-fsearch>'
               '<button type="button" class="chip" data-expand="1">Expand all</button>'
               '<button type="button" class="chip" data-expand="0">Collapse all</button>'
               f'<span class="shown" data-fshown>{total} of {total} findings shown</span></div>')

    groups = []
    for a in AREAS:
        cards = []
        for cid, items in grouped.items():
            if CHECKS[cid][1] != a:
                continue
            _, _, ttl, why, rec = CHECKS[cid]
            worst = _worst(items)
            rows = []
            for f in items:
                sev_mark = _pill(f["severity"]) + " " if f["severity"] != worst else ""
                text = f"{_target(f)} {f['detail']}".lower()
                tgt = (f'<a href="{_e(safe_url(f["url"]))}" target="_blank" rel="noopener">{_e(_target(f))}</a>' if safe_url(f.get("url"))
                       and f["policyid"] is None else _e(_target(f)))
                rows.append(f'<tr data-sev="{f["severity"]}" data-text="{_e(text)}"><td class="id">{sev_mark}{tgt}</td>'
                            f'<td>{_e(f["detail"])}</td></tr>')
            refs = items[0].get("compliance") or []
            ctl = f'<p class="ctl">Relevant controls: {_e("; ".join(refs))}</p>' if refs else ""
            open_attr = " open" if worst == "high" else ""
            card_text = f"{ttl} {cid}".lower()
            cards.append(
                f'<details class="fcard" id="check-{cid}" data-area="{a}" data-text="{_e(card_text)}" style="{_c(a)}"{open_attr}>'
                f'<summary>{_pill(worst)}<span class="ttl">{_e(ttl)}</span>'
                f'<span class="eff {EFFORT[cid]}">{EFFORT_LABEL[EFFORT[cid]]}</span><span class="cnt">{len(items)} '
                f'item{"s" if len(items) != 1 else ""}</span></summary><div class="body">'
                f'<p class="why">{_e(why)}</p><p class="rec"><b>Recommendation:</b> {_e(rec)}</p>{ctl}'
                f'<div class="tw"><table class="rows"><tbody>{"".join(rows)}</tbody></table></div></div></details>')
        if not cards:
            continue
        n = per_area.get(a, 0)
        groups.append(f'<div class="area-group" id="area-{a}" data-group="{a}" style="{_c(a)}">'
                      f'<div class="area-h"><span class="dot"></span><h3>{_e(AREAS[a][0])}</h3>'
                      f'<span class="meta2">Score {result["areas"][a]}/100, {n} finding{"s" if n != 1 else ""}</span></div>'
                      f'{"".join(cards)}</div>')
    empty = ('<div class="empty" data-fempty hidden>No findings match these filters. '
             '<button type="button" class="chip" data-freset>Show all</button></div>')
    return _sec("findings", "Findings", filters + "".join(groups) + empty, aside=f"{total} findings")


# ---------------------------------------------------------------- appendices

def _changes(result: Dict[str, Any]) -> str:
    log = result.get("change_log") or []
    if not log:
        return ""
    rows = [f'<tr><td class="mono">{_e(_ts(e.get("time"), "%Y-%m-%d %H:%M"))}</td><td>{_e(e.get("user"))}</td>'
            f'<td>{_e(e.get("ui"))}</td><td>{_e(e.get("action"))}</td><td>{_e(e.get("cfgpath"))} {_e(e.get("cfgobj"))}</td>'
            f'<td>{_e(e.get("cfgattr") or e.get("msg"))}</td></tr>' for e in log]
    return _sec("changes", "Recent configuration changes",
                '<p class="lede">From the FortiGate system event log. Secret values are masked.</p>' +
                _tw("<th>Time (UTC)</th><th>User</th><th>Interface</th><th>Action</th><th>Object</th><th>Change</th>",
                    rows, "exp"))


def _compliance(result: Dict[str, Any]) -> str:
    by: Dict[str, Dict[str, Dict[str, int]]] = {fw: {} for fw in CONTROL_NAMES}
    for f in result["findings"]:
        for ref in f.get("compliance", []):
            fw, _, ctl = ref.rpartition(" ")
            by.setdefault(fw, {}).setdefault(ctl, {})
            by[fw][ctl][f["check"]] = by[fw][ctl].get(f["check"], 0) + 1
    tabs, panels = [], []
    for i, (fw, names) in enumerate(CONTROL_NAMES.items()):
        hit_controls = sum(1 for ctl in names if by.get(fw, {}).get(ctl))
        tabs.append(f'<button type="button" class="tab" role="tab" aria-selected="{"true" if i == 0 else "false"}" '
                    f'aria-controls="fw-{i}" id="fwt-{i}">{_e(fw)} <span class="dim">{hit_controls}/{len(names)}</span></button>')
        rows = []
        for ctl, cname in names.items():
            hits = by.get(fw, {}).get(ctl, {})
            n = sum(hits.values())
            status = (f'<span class="pill high">{n} finding{"s" if n != 1 else ""}</span>' if hits
                      else '<span class="pill ok">No findings</span>')
            linked = ", ".join(f'<a href="#check-{cid}">{_e(CHECKS[cid][2])}</a> ({k})' for cid, k in hits.items())
            rows.append(f'<tr><td class="mono" style="white-space:nowrap">{_e(ctl)}</td><td>{_e(cname)}</td>'
                        f'<td>{status}</td><td>{linked}</td></tr>')
        hidden = "" if i == 0 else " hidden"
        panels.append(f'<div class="tab-panel" role="tabpanel" id="fw-{i}" aria-labelledby="fwt-{i}"{hidden}>'
                      f'<h3 class="print-only" style="margin:12px 0 6px">{_e(fw)}</h3>'
                      + _tw("<th>Control</th><th>Title</th><th>Status</th><th>Related findings</th>", rows) + "</div>")
    return _sec("compliance", "Compliance view",
                '<p class="lede">Controls related to the automated checks. "No findings" means the checks found nothing '
                'for that control, not that the control is met. The mapping is indicative, not a certification.</p>'
                f'<div class="tabs" role="tablist">{"".join(tabs)}</div>{"".join(panels)}')


def _remediation(result: Dict[str, Any]) -> str:
    cli = remediation_cli(result)
    return _sec("remediation", "Remediation commands",
                '<p class="lede">Review every block and take a backup first. Lines starting with # change allowed traffic, '
                'VPN peers or management access and are commented out on purpose. Rules are disabled, not deleted.</p>'
                f'<div class="codebox"><button type="button" class="copy" data-copy>Copy</button><pre>{_e(cli)}</pre></div>')


def _inventory(result: Dict[str, Any], snap: Dict[str, Any]) -> str:
    by_pid: Dict[int, List[str]] = {}
    for f in result["findings"]:
        if f["policyid"] is not None:
            by_pid.setdefault(f["policyid"], []).append(f["check"])
    hits = snap.get("hits")
    rows = []
    for seq, p in enumerate(snap["policies"], 1):
        h = hits.get(str(p["policyid"])) if hits is not None else None
        tags = sorted(set(by_pid.get(p["policyid"], [])))
        tag_html = "".join(f'<a class="tag" href="#check-{t}">{_e(t)}</a>' for t in tags)
        dis = p["status"] != "enable"
        isdb = "ISDB" if p.get("internet-service") == "enable" else ""
        src = ", ".join(p["srcaddr"] + p["srcaddr6"]) or ("ISDB" if p.get("internet-service-src") == "enable" else "")
        dst = ", ".join(p["dstaddr"] + p["dstaddr6"]) or isdb
        svc = ", ".join(p["service"]) or isdb
        text = " ".join([str(p["policyid"]), p["name"], " ".join(p["srcintf"]), " ".join(p["dstintf"]), src, dst, svc,
                         p["action"], " ".join(tags)]).lower()
        hit_txt = "" if h is None else "{:,}".format(h["hit_count"])
        rows.append(
            f'<tr id="inv-{_e(p["policyid"])}" data-text="{_e(text)}" data-has="{1 if tags else 0}"{" class=off" if dis else ""}>'
            f'<td class="num">{seq}</td><td class="num">{_e(p["policyid"])}</td>'
            f'<td>{_e(p["name"])}{" <span class=dim>(disabled)</span>" if dis else ""}</td>'
            f'<td>{_e(", ".join(p["srcintf"]))} &rarr; {_e(", ".join(p["dstintf"]))}</td><td>{_e(src)}</td><td>{_e(dst)}</td>'
            f'<td>{_e(svc)}</td><td class="act-{_e(p["action"])}">{_e(p["action"])}</td><td class="num">{hit_txt}</td>'
            f'<td class="mono">{"" if h is None else _ts(h["last_used"])}</td><td>{tag_html}</td></tr>')
    tools = ('<div class="toolbar"><input class="search" type="search" placeholder="Filter by ID, name, interface, address, service" '
             'aria-label="Filter policies" data-isearch><label><input type="checkbox" data-ionly> Only rules with findings</label>'
             f'<span class="shown" data-ishown>{len(rows)} of {len(rows)} rules</span></div>')
    head = ("<th class='num'>Seq</th><th class='num'>ID</th><th>Name</th><th>Interfaces</th><th>Source</th><th>Destination</th>"
            "<th>Service</th><th>Action</th><th class='num'>Hits</th><th>Last hit</th><th>Findings</th>")
    return _sec("inventory", "Policy inventory", tools + _tw(head, rows, "inv"), aside=f"{len(rows)} rules")


PAGE_JS = """<script>(function(){
function $$(s,r){return [].slice.call((r||document).querySelectorAll(s))}
/* section tracking in the side navigation */
var links=$$('nav.side a[href^="#"]'),byId={};
links.forEach(function(a){byId[a.getAttribute('href').slice(1)]=a});
if('IntersectionObserver' in window){
  var io=new IntersectionObserver(function(es){es.forEach(function(e){
    if(!e.isIntersecting)return;var a=byId[e.target.id];if(!a)return;
    links.forEach(function(l){l.removeAttribute('aria-current')});a.setAttribute('aria-current','true');
    var p=a.closest('.sub');if(p&&p.previousElementSibling)p.previousElementSibling.setAttribute('aria-current','true');
  })},{rootMargin:'-80px 0px -70% 0px'});
  Object.keys(byId).forEach(function(id){var el=document.getElementById(id);if(el)io.observe(el)});
}
/* findings filters */
var sevOn={},areaOn={},q=$$('[data-fsearch]')[0],shown=$$('[data-fshown]')[0],empty=$$('[data-fempty]')[0];
var cards=$$('details.fcard'),total=$$('details.fcard tr[data-sev]').length;
$$('[data-fsev]').forEach(function(b){sevOn[b.dataset.fsev]=true});
$$('[data-farea]').forEach(function(b){areaOn[b.dataset.farea]=true});
function apply(){var t=q?q.value.trim().toLowerCase():'',n=0;
  cards.forEach(function(c){var any=0,cardHit=t&&c.dataset.text.indexOf(t)>=0;
    $$('tr[data-sev]',c).forEach(function(r){var ok=sevOn[r.dataset.sev]!==false&&areaOn[c.dataset.area]!==false&&
      (!t||cardHit||r.dataset.text.indexOf(t)>=0);r.hidden=!ok;if(ok)any++});
    c.hidden=!any;n+=any;if(t&&any)c.open=true});
  $$('[data-group]').forEach(function(g){g.hidden=!$$('details.fcard',g).some(function(c){return !c.hidden})});
  if(shown)shown.textContent=n+' of '+total+' findings shown';if(empty)empty.hidden=n>0}
function toggle(b,store,key){var on=b.getAttribute('aria-pressed')!=='true';b.setAttribute('aria-pressed',on);store[key]=on;apply()}
$$('[data-fsev]').forEach(function(b){b.addEventListener('click',function(){toggle(b,sevOn,b.dataset.fsev)})});
$$('[data-farea]').forEach(function(b){b.addEventListener('click',function(){toggle(b,areaOn,b.dataset.farea)})});
if(q)q.addEventListener('input',apply);
$$('[data-freset]').forEach(function(b){b.addEventListener('click',function(){
  $$('[data-fsev],[data-farea]').forEach(function(x){x.setAttribute('aria-pressed','true')});
  Object.keys(sevOn).forEach(function(k){sevOn[k]=true});Object.keys(areaOn).forEach(function(k){areaOn[k]=true});
  if(q)q.value='';apply()})});
$$('[data-expand]').forEach(function(b){b.addEventListener('click',function(){
  var open=b.dataset.expand==='1';cards.forEach(function(c){if(!c.hidden)c.open=open})})});
/* open the target card when a link points into a collapsed one */
function reveal(){var h=location.hash.slice(1);if(!h)return;var el=document.getElementById(h);
  if(el&&el.tagName==='DETAILS'){el.hidden=false;el.open=true}}
window.addEventListener('hashchange',reveal);reveal();
/* inventory filter */
var iq=$$('[data-isearch]')[0],io2=$$('[data-ionly]')[0],ish=$$('[data-ishown]')[0],irows=$$('table.inv tbody tr');
function ifilter(){var t=iq?iq.value.trim().toLowerCase():'',only=io2&&io2.checked,n=0;
  irows.forEach(function(r){var ok=(!t||r.dataset.text.indexOf(t)>=0)&&(!only||r.dataset.has==='1');r.hidden=!ok;if(ok)n++});
  if(ish)ish.textContent=n+' of '+irows.length+' rules'}
if(iq)iq.addEventListener('input',ifilter);if(io2)io2.addEventListener('change',ifilter);
/* best-practice status filter */
var bpOn={};$$('[data-bpst]').forEach(function(b){bpOn[b.dataset.bpst]=true;b.addEventListener('click',function(){
  var on=b.getAttribute('aria-pressed')!=='true';b.setAttribute('aria-pressed',on);bpOn[b.dataset.bpst]=on;
  $$('table.bp tr[data-st]').forEach(function(r){r.hidden=bpOn[r.dataset.st]===false});
  $$('table.bp tr.dom').forEach(function(d){d.hidden=!$$('table.bp tr[data-domrow="'+d.dataset.dom+'"]').some(function(r){return !r.hidden})})})});
/* compliance tabs */
$$('[role=tab]').forEach(function(t){t.addEventListener('click',function(){
  $$('[role=tab]').forEach(function(x){x.setAttribute('aria-selected',x===t);
    var p=document.getElementById(x.getAttribute('aria-controls'));if(p)p.hidden=x!==t})})});
/* copy remediation script */
$$('[data-copy]').forEach(function(b){b.addEventListener('click',function(){
  var txt=b.parentNode.querySelector('pre').textContent;
  function done(){b.textContent='Copied';setTimeout(function(){b.textContent='Copy'},1600)}
  if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(txt).then(done)}
  else{var ta=document.createElement('textarea');ta.value=txt;document.body.appendChild(ta);ta.select();
    try{document.execCommand('copy');done()}catch(e){}document.body.removeChild(ta)}})});
/* print everything expanded */
var was=[];window.addEventListener('beforeprint',function(){was=cards.map(function(c){return c.open});
  $$('details').forEach(function(d){d.open=true});$$('[hidden]').forEach(function(e){if(e.closest('main'))e.dataset.wasHidden='1',e.hidden=false})});
window.addEventListener('afterprint',function(){cards.forEach(function(c,i){c.open=was[i]});
  $$('[data-was-hidden]').forEach(function(e){e.hidden=true;delete e.dataset.wasHidden})});
})();</script>"""


def _nav(result: Dict[str, Any]) -> str:
    per_area: Dict[str, int] = {}
    for f in result["findings"]:
        per_area[f["area"]] = per_area.get(f["area"], 0) + 1
    items = [("overview", "Overview", "", ""), ("summary", "Executive summary", "", "")]
    if result.get("top_actions"):
        items.append(("actions", "Priority actions", "", str(len(result["top_actions"]))))
    if result.get("quick_wins"):
        items.append(("quickwins", "Quick wins", "", str(len(result["quick_wins"]))))
    if result.get("comparison"):
        items.append(("progress", "Progress", "", ""))
    bp = result.get("practices")
    if bp:
        items.append(("practices", "Best-practice baseline", "", f"{bp['counts']['pass']}/{bp['assessed']}"))
    items.append(("exposure", "Internet exposure", _c("exposure"), str(internet_services(result))))
    fw = result.get("firmware")
    if fw:
        col = FW_STATUS.get(fw["lifecycle"]["status"], FW_STATUS["unknown"])[0]
        kev = (fw["advisories"].get("counts") or {}).get("kev")
        items.append(("firmware", "Firmware", f"--c:var({'--sev-high' if kev else col})",
                      str(fw["advisories"]["counts"]["total"]) if fw["advisories"].get("checked") else ""))
    out = ['<nav class="side" aria-label="Report sections"><ol>']
    for sid, label, style, cnt in items:
        st = f' style="{style}"' if style else ""
        dot = '<span class="dot"></span>' if style else ""
        out.append(f'<li><a href="#{sid}"{st}>{dot}{_e(label)}<span class="cnt">{cnt}</span></a></li>')
    out.append(f'<li><a href="#findings">Findings<span class="cnt">{len(result["findings"])}</span></a></li>')
    subs = "".join(f'<li><a href="#area-{a}" style="{_c(a)}"><span class="dot"></span>{_e(AREAS[a][0])}'
                   f'<span class="cnt">{per_area[a]}</span></a></li>' for a in AREAS if per_area.get(a))
    out.append(f'<li class="sub"><ol>{subs}</ol></li>')
    if result.get("change_log"):
        out.append('<li><a href="#changes">Configuration changes</a></li>')
    out.append('<li class="grp">Reference</li>')
    for sid, label in (("compliance", "Compliance view"), ("remediation", "Remediation commands"), ("inventory", "Policy inventory")):
        out.append(f'<li><a href="#{sid}">{label}</a></li>')
    out.append("</ol></nav>")
    return "".join(out)


def html_report(result: Dict[str, Any], snap: Dict[str, Any], client: str = "", auditor: str = "",
                title: str = "Firewall security audit", redacted: bool = False, palette: str = "harbor") -> str:
    d = result["device"]
    name = client or d.get("hostname") or "FortiGate"
    g, _ = GRADE_COLOR.get(result["grade"], ("--sev-info", ""))
    topbar = (f'<header class="topbar"><span class="mark">{LOGO}<span>rulescope</span></span>'
              f'<span class="who">{_e(name)}, {_e(result["collected_at"][:10])}</span>'
              f'<span class="gchip"><span class="dot" style="--c:var({g})"></span>Grade {_e(result["grade"])}, '
              f'{result["score"]}/100</span><span class="spacer"></span>{CONTROLS}'
              '<button class="tbtn" type="button" onclick="window.print()" aria-label="Print or save as PDF">'
              '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">'
              '<path d="M6 9V3h12v6M6 18H4v-7h16v7h-2M7 14h10v7H7z"/></svg><span>Print</span></button></header>')
    weights = ", ".join(f"{AREAS[a][0].lower()} {round(AREAS[a][1] * 100)}%" for a in AREAS)
    foot = (f'<footer class="foot"><p>Generated by rulescope {__version__} on {_e(result["collected_at"])}.</p>'
            "<p>How the score works: each area starts at 100. Absolute findings cost severity weight &times; (1 + log2 n), "
            "capped at 4&times; the weight; hygiene findings cost weight &times; (1 + 9 &times; share of rules or objects "
            f"affected). Weights: high 15, medium 6, low 2, info 0. The overall score is the weighted mean of areas ({_e(weights)}), "
            "capped at 69 while any high-severity finding remains.</p><p>Shadow and redundancy findings are reported only when "
            "coverage is provable from the configuration; FQDN, geography, ISDB and VIP objects are treated conservatively. "
            "Best-practice items and compliance references are indicative and do not replace a formal certification.</p></footer>")
    body = "".join([_overview(result, name, auditor), _summary(result, name, redacted), _actions(result), _quick_wins(result),
                    _progress(result), _practices(result), _exposure(result), _firmware(result), _findings(result),
                    _changes(result), _compliance(result), _remediation(result), _inventory(result, snap), foot])
    return (f'{html_open(palette)}<head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{_e(title)}: {_e(name)}</title>{THEME_HEAD}<style>{CSS}.print-only{{display:none}}'
            f'@media print{{.print-only{{display:block}}}}</style></head>'
            f'<body>{topbar}<div class="shell">{_nav(result)}<main>{body}</main></div>{THEME_JS}{PAGE_JS}</body></html>')
