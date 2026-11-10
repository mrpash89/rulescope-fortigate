"""Client-facing outputs: HTML report, FortiOS remediation script, CSV, console summary."""
from __future__ import annotations

import csv
import datetime as _dt
import io
import unicodedata
from collections import OrderedDict
from html import escape
from typing import Any, Dict, List, Optional

import re

from .catalog import AREAS, CHECKS, EFFORT_LABEL, SEVERITY_ORDER
from .safety import clean, clean_multiline, csv_cell

def _e(x: Any) -> str:
    return escape("" if x is None else str(x))


def _ts(epoch: Optional[int], fmt: str = "%Y-%m-%d") -> str:
    if not epoch:
        return ""
    return _dt.datetime.fromtimestamp(int(epoch), _dt.timezone.utc).strftime(fmt)


def _grouped(findings: List[Dict[str, Any]]) -> "OrderedDict[str, List[Dict[str, Any]]]":
    g: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()
    for f in findings:
        g.setdefault(f["check"], []).append(f)
    return g


def _worst(items: List[Dict[str, Any]]) -> str:
    return min((f["severity"] for f in items), key=lambda s: SEVERITY_ORDER[s])


def _target(f: Dict[str, Any]) -> str:
    return f"Policy #{f['policyid']}" if f["policyid"] is not None else str(f["object"])


def wan_text(result: Dict[str, Any]) -> str:
    why = result.get("wan_reasons") or {n: [] for n in result.get("wan_interfaces", [])}
    if not why:
        return "none identified"
    return ", ".join(f"{n} ({'; '.join(r)})" if r else n for n, r in sorted(why.items()))


def internet_services(result: Dict[str, Any]) -> int:
    return sum(1 for x in result.get("exposure", []) if x["kind"] in ("Rule", "Management", "SSL-VPN")
               and not str(x["source"]).startswith("blocked"))


# ---------------------------------------------------------------- remediation CLI

def _cli_unsafe(text: str) -> bool:
    return any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in text)


def _cli_comment(text: str) -> str:
    return "\n".join("# " + "".join(c.encode("unicode_escape").decode("ascii") if _cli_unsafe(c) else c
                                 for c in line) for line in (text.splitlines() or [""]))


def remediation_cli(result: Dict[str, Any], only: Optional[set] = None, safe_only: bool = False,
                    title: str = "remediation") -> str:
    dev = result["device"]
    multi = dev.get("multi_vdom")
    vdom = dev.get("vdom", "root")
    valid_vdom = isinstance(vdom, str) and bool(vdom.strip()) and not _cli_unsafe(vdom)
    lines = [
        _cli_comment(f"rulescope {title} script"),
        _cli_comment(f"Device: {dev.get('hostname') or '-'}  {dev.get('model', '')} {dev.get('version', '')}  VDOM: {dev.get('vdom')}"),
        _cli_comment(f"Generated: {result['collected_at']}"),
        "#",
        "# REVIEW EVERY BLOCK BEFORE APPLYING. Take a config backup first.",
        "# Lines prefixed with '#' change traffic behaviour, VPN peers or management reachability",
        "# and are left commented out on purpose. Uncomment only after review.",
        "# Policies are disabled rather than deleted so the change is reversible.",
        "",
    ]
    vdom_blocks: List[str] = []
    global_blocks: List[str] = []
    withheld_blocks: List[str] = []
    seen = set()
    for check, items in _grouped(result["findings"]).items():
        if only is not None and check not in only:
            continue
        for f in items:
            key = (f["cli_scope"], tuple(f["cli"]))
            if not f["cli"] or key in seen or (safe_only and not f["cli_safe"]):
                continue
            seen.add(key)
            block = [f"# [{f['severity'].upper()}] {CHECKS[check][2]}: {clean(f['detail'])}"]
            for ln in f["cli"]:
                for phys in str(ln).splitlines() or [""]:  # comment out every physical line, never a list item
                    block.append(phys if f["cli_safe"] else "# " + phys)
            (global_blocks if f["cli_scope"] == "global" else vdom_blocks).append("\n".join(block))
    lines += [b + "\n" for b in withheld_blocks]
    if not vdom_blocks and not global_blocks:
        return "\n".join(lines + ["# No remediation commands generated."]) + "\n"
    if global_blocks:
        if multi:
            lines.append("config global")
        lines += [b + "\n" for b in global_blocks]
        if multi:
            lines.append("end\n")
    if vdom_blocks:
        if multi:
            lines += ["config vdom", f"edit {clean(dev.get('vdom', 'root')).replace(' ', '_')}"]
        lines += [b + "\n" for b in vdom_blocks]
        if multi:
            lines += ["next", "end"]
    return guard_script("\n".join(lines) + "\n")


# The only statements rulescope ever generates. Anything else in a script line means the input was
# crafted to inject commands, so the line is disabled and the script says so at the top.
_ALLOWED = re.compile(r"^\s*(?:config|edit|set|unset|append|next|end|move|delete)(?:\s|$)")


def guard_script(text: str) -> str:
    out, blocked = [], 0
    for ln in text.split("\n"):
        ln = clean(ln)
        if ln.strip() and not ln.lstrip().startswith("#") and not _ALLOWED.match(ln):
            out.append("# BLOCKED, unexpected statement: " + ln)
            blocked += 1
        else:
            out.append(ln)
    if blocked:
        out.insert(0, f"# WARNING: {blocked} unexpected line(s) were blocked. The input may have been crafted; "
                      "do not apply this script without reading it.")
    return "\n".join(out)


# ---------------------------------------------------------------- CSV

def findings_csv(result: Dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "check", "title", "area", "effort", "policy_id", "object", "detail", "recommendation",
                "compliance", "reference", "owner", "status", "notes"])
    for f in result["findings"]:
        w.writerow([csv_cell(clean(v)) for v in (
            f["severity"], f["check"], f["title"], f["category"], EFFORT_LABEL.get(f.get("effort", ""), ""),
            f["policyid"] if f["policyid"] is not None else "", f["object"] or "", f["detail"], f["recommendation"],
            "; ".join(f.get("compliance", [])), f.get("url", ""), "", "", "")])
    return "﻿" + buf.getvalue()  # BOM so Excel opens UTF-8 (Hebrew names) correctly


def practices_csv(result: Dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "domain", "practice", "sources", "status", "evidence", "related_checks", "owner", "target_date", "notes"])
    for i in (result.get("practices") or {}).get("items", []):
        w.writerow([csv_cell(clean(v)) for v in (i["id"], i["domain"], i["title"], i["sources"], i["status"],
                                                 i["evidence"], "; ".join(i["checks"]), "", "", "")])
    return "\ufeff" + buf.getvalue()


# ---------------------------------------------------------------- console

def console_summary(result: Dict[str, Any]) -> str:
    d, s, c = result["device"], result["stats"], result["cleanup"]
    sc = result["severity_counts"]
    areas = "  ".join(f"{AREAS[a][0]} {v}" for a, v in result["areas"].items())
    out = [
        f"{d.get('hostname') or 'FortiGate'}  {d.get('model', '')} {d.get('version', '')}  vdom={d.get('vdom')}  source={result['source']}",
        f"Score {result['score']}/100 (grade {result['grade']})   high={sc['high']} medium={sc['medium']} low={sc['low']} info={sc['info']}",
        f"Areas: {areas}",
        f"Internet-facing: {wan_text(result)}   (wrong? use --wan / --not-wan)",
        f"Policies: {s['policies']} ({s['enabled']} enabled, {s['accept']} accept, {s['deny']} deny); "
        f"removable {c['policies']} ({c['percent']}%); internet-exposed services {internet_services(result)}",
    ]
    bp, fw = result.get("practices"), result.get("firmware")
    if bp:
        c = bp["counts"]
        out.append(f"Best practice: {c['pass']} of {bp['assessed']} assessed met ({bp['percent']}%); {c['fail']} fail, "
                   f"{c['partial']} partial, {c['unknown']} not assessed, {c['manual']} manual, {c['na']} n/a")
    if fw:
        lc, adv = fw["lifecycle"], fw["advisories"]
        life = {"supported": f"supported until {lc['eos']}", "eoes_soon": f"engineering support ends {lc['eoes']}, end of support {lc['eos']}",
                "eoes": f"engineering support ended {lc['eoes']}, end of support {lc['eos']}",
                "eos": f"END OF SUPPORT since {lc['eos']}"}.get(lc["status"], "not in lifecycle table")
        cnt = adv.get("counts") or {}
        vul = (f"{cnt.get('total', 0)} CVEs ({cnt.get('kev', 0)} exploited, {cnt.get('critical', 0)} critical)"
               if adv.get("checked") else "advisories not checked (--advisories online)")
        out.append(f"Firmware: FortiOS {lc.get('version') or '?'} {life}; {vul}")
    if result.get("quick_wins"):
        out.append(f"Quick wins: {len(result['quick_wins'])} one-setting fixes (see the report's Quick wins section)")
    comp = result.get("comparison")
    if comp:
        out.append(f"Since {comp['baseline_date'][:10]}: score {comp['score_before']} -> {result['score']}, "
                   f"{len(comp['resolved'])} resolved, {len(comp['new'])} new, {comp['persisting']} persisting")
    out.append("")
    for check, items in _grouped(result["findings"]).items():
        out.append(f"[{_worst(items).upper():6}] {CHECKS[check][2]} x{len(items)}")
        for f in items[:5]:
            out.append(f"           - {f['detail']}")
        if len(items) > 5:
            out.append(f"           ... {len(items) - 5} more")
    for n in result.get("notes", []):
        out.append(f"note: {n}")
    return clean_multiline("\n".join(out))


# ---------------------------------------------------------------- HTML

from .ui import CSS  # noqa: E402,F401  (shared stylesheet, re-exported for fleet and diff pages)


def executive_summary(result: Dict[str, Any], name: str) -> List[str]:
    sc, c = result["severity_counts"], result["cleanup"]
    high_f = sorted((f for f in result["findings"] if f["severity"] == "high"),
                    key=lambda f: -AREAS[f["area"]][1])
    highs = OrderedDict((f["title"], 1) for f in high_f)
    paras = []
    p = (f"{name} scored {result['score']}/100 (grade {result['grade']}) across internet exposure, rule base, device "
         "hardening, logging and inspection, VPN and objects.")
    if sc["high"]:
        top = list(highs)[:3]
        p += (f" {sc['high']} high-severity issue{'s' if sc['high'] != 1 else ''} need{'s' if sc['high'] == 1 else ''} "
              f"prompt attention, including: {'; '.join(top)}.")
    else:
        p += " No high-severity issues were found."
    paras.append(p)
    n_exp = internet_services(result)
    risky = sorted({svc for x in result.get("exposure", []) for svc in x.get("risky", [])})
    p2 = (f"{n_exp} service{'s are' if n_exp != 1 else ' is'} reachable from the internet"
          + (f", including {', '.join(risky)}, which attackers routinely target." if risky else "."))
    if c["total"]:
        p2 += (f" {c['policies']} of {c['total']} rules ({c['percent']}%) are unused, redundant, shadowed, expired or "
               f"disabled and are candidates for removal")
        p2 += f", and {c['objects']} objects are unreferenced." if c["objects"] else "."
    paras.append(p2)
    fw, bp = result.get("firmware"), result.get("practices")
    if fw:
        lc, adv = fw["lifecycle"], fw["advisories"]
        cnt = adv.get("counts") or {}
        p3 = ""
        if lc["status"] == "eos":
            p3 = (f"The firewall runs FortiOS {lc['version']}, whose branch reached end of support on {lc['eos']}: "
                  "Fortinet no longer fixes its vulnerabilities, so upgrading is the first priority.")
        elif lc["status"] == "eoes":
            p3 = (f"FortiOS {lc['version']} is past end of engineering support ({lc['eoes']}) and reaches end of support on "
                  f"{lc['eos']}; the upgrade should be planned now.")
        elif lc["status"] == "eoes_soon":
            p3 = f"Engineering support for FortiOS {lc['branch']} ends on {lc['eoes']}; the upgrade should be planned."
        if adv.get("checked") and cnt.get("kev"):
            p3 += (f" This version is affected by {cnt['kev']} vulnerabilit{'y' if cnt['kev'] == 1 else 'ies'} that attackers "
                   "are actively exploiting (CISA KEV).")
        elif adv.get("checked") and cnt.get("critical"):
            p3 += f" This version has {cnt['critical']} known critical vulnerabilit{'y' if cnt['critical'] == 1 else 'ies'}."
        if p3:
            paras.append(p3.strip())
    if bp and bp["assessed"]:
        c = bp["counts"]
        paras.append(f"Against the FortiGate best-practice baseline (Fortinet, CIS and the Canadian Cyber Centre), "
                     f"{c['pass']} of {bp['assessed']} assessed practices are met, {c['partial']} partly and {c['fail']} not"
                     + (f"; {len(result.get('quick_wins') or [])} of the gaps can be closed with a single setting each." if result.get("quick_wins") else "."))
    weakest = min(result["areas"].items(), key=lambda kv: kv[1])
    if weakest[1] < 100:
        paras.append(f"The weakest area is {AREAS[weakest[0]][0].lower()} ({weakest[1]}/100). "
                     "The actions below are ordered by risk; the remediation appendix contains ready-to-review "
                     "FortiOS commands for most of them.")
    return paras


def html_report(result: Dict[str, Any], snap: Dict[str, Any], client: str = "", auditor: str = "",
                title: str = "Firewall security audit", redacted: bool = False, palette: str = "harbor") -> str:
    from .htmlreport import html_report as _render
    return _render(result, snap, client=client, auditor=auditor, title=title, redacted=redacted, palette=palette)
