"""Change tracking between two snapshots: what changed, who changed it, and which changes are risky."""
from __future__ import annotations

import bisect
import datetime as _dt
from html import escape
from typing import Any, Dict, List, Optional, Tuple

from . import exposure, model
from .resolve import Resolver
from .safety import clean_multiline

POLICY_IGNORE = {"policyid"}
# snapshot key, label, fields compared (None = all), FortiOS cfgpath used in change logs
TABLES: List[Tuple[str, str, Optional[List[str]], str]] = [
    ("addresses", "Address", None, "firewall.address"),
    ("addrgrps", "Address group", None, "firewall.addrgrp"),
    ("services", "Service", None, "firewall.service.custom"),
    ("servicegrps", "Service group", None, "firewall.service.group"),
    ("vips", "VIP", None, "firewall.vip"),
    ("vipgrps", "VIP group", None, "firewall.vipgrp"),
    ("zones", "Zone", None, "system.zone"),
    ("local_in", "Local-in policy", None, "firewall.local-in-policy"),
    ("interfaces", "Interface", ["allowaccess", "role"], "system.interface"),
    ("admins", "Admin", ["accprofile", "trusthosts", "two_factor"], "system.admin"),
    ("api_users", "API user", ["accprofile", "trusthosts"], "system.api-user"),
    ("ipsec_p1", "IPsec phase 1", None, "vpn.ipsec.phase1-interface"),
]
_MGMT = {"https", "http", "ssh", "telnet", "snmp"}
SETTING_LABELS = {  # snapshot settings key -> (label, FortiOS cfgpath in change logs)
    "password_policy": ("Password policy", "system.password-policy"), "auto_install": ("USB auto-install", "system.auto-install"),
    "ntp": ("NTP", "system.ntp"), "ha": ("HA", "system.ha"), "eventfilter": ("Event log filter", "log.eventfilter"),
    "snmp_agent": ("SNMP agent", "system.snmp.sysinfo"), "autoupdate": ("FortiGuard update schedule", "system.autoupdate.schedule"),
}
# (object type, field, new value that weakens security, alert text)
WEAKENING = [
    ("System global", "strong-crypto", "disable", "strong-crypto was disabled"),
    ("System global", "ssl-static-key-ciphers", "enable", "Static-key TLS ciphers were enabled"),
    ("System global", "private-data-encryption", "disable", "Private data encryption was disabled"),
    ("Password policy", "status", "disable", "The admin password policy was disabled"),
    ("USB auto-install", "auto-install-config", "enable", "USB configuration auto-install was enabled"),
    ("USB auto-install", "auto-install-image", "enable", "USB firmware auto-install was enabled"),
    ("NTP", "ntpsync", "disable", "NTP time synchronization was disabled"),
    ("Event log filter", "event", "disable", "Event logging was disabled"),
    ("FortiGuard update schedule", "status", "disable", "Scheduled FortiGuard updates were disabled"),
]


_RULE_OBJECTS = {"Address", "Address group", "Service", "Service group", "VIP", "VIP group"}


def _table(snap: Dict[str, Any], key: str) -> Optional[Dict[str, Dict[str, Any]]]:
    """A snapshot table as {name: fields}. Lists (local-in policies) and name -> members maps
    (zones, VIP groups) are brought into that shape so they are compared like every other table."""
    v = snap.get(key)
    if v is None:
        return None
    if key == "local_in":
        return {str(x.get("policyid")): x for x in v}
    if key in ("vipgrps", "zones"):
        return {n: {"member": list(m)} for n, m in v.items()}
    return v


def _pkey(p: Dict[str, Any]) -> str:
    return p.get("uuid") or f"id:{p['policyid']}"


def _fields_changed(a: Dict[str, Any], b: Dict[str, Any], ignore=(), only: Optional[List[str]] = None) -> List[Tuple[str, Any, Any]]:
    # Without `only`, compare the fields both sides have: a field that a newer rulescope version started
    # to collect (or a snapshot schema upgrade added) is not a configuration change.
    keys = only if only is not None else sorted(set(a) & set(b))
    return [(k, a.get(k), b.get(k)) for k in keys if k not in ignore and a.get(k) != b.get(k)]


def _moved(old_keys: List[str], new_keys: List[str]) -> List[str]:
    """Keys outside the longest increasing subsequence = the minimal set of rules that moved."""
    old_set = set(old_keys)
    common = [k for k in new_keys if k in old_set]
    pos = {k: i for i, k in enumerate(old_keys)}
    seq = [pos[k] for k in common]
    tails: List[int] = []
    tails_idx: List[int] = []
    parent = [-1] * len(seq)
    for i, v in enumerate(seq):
        j = bisect.bisect_left(tails, v)
        if j == len(tails):
            tails.append(v)
            tails_idx.append(i)
        else:
            tails[j] = v
            tails_idx[j] = i
        parent[i] = tails_idx[j - 1] if j else -1
    keep = set()
    i = tails_idx[-1] if tails_idx else -1
    while i >= 0:
        keep.add(common[i])
        i = parent[i]
    return [k for k in common if k not in keep]


def _events_between(new: Dict[str, Any], start_iso: str, end_iso: str) -> List[Dict[str, Any]]:
    log = new.get("change_log") or []
    lo, hi = model.iso_epoch(start_iso) - 120, model.iso_epoch(end_iso) + 120
    return [e for e in log if lo < (e.get("time") or 0) <= hi]


def _who(events: List[Dict[str, Any]], cfgpath: str, obj: str) -> List[str]:
    out = []
    for e in events:
        if e.get("cfgpath") == cfgpath and str(e.get("cfgobj")) == obj:
            t = _dt.datetime.fromtimestamp(e["time"], _dt.timezone.utc).strftime("%Y-%m-%d %H:%M") if e.get("time") else "?"
            s = f"{e.get('user') or '?'} via {e.get('ui') or '?'} at {t} UTC ({e.get('action') or 'change'})"
            if s not in out:
                out.append(s)
    return out


def diff_snapshots(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    old, new = model.upgrade(old), model.upgrade(new)
    op = {_pkey(p): p for p in old["policies"]}
    np_ = {_pkey(p): p for p in new["policies"]}
    events = _events_between(new, old["collected_at"], new["collected_at"])
    res: Dict[str, Any] = {
        "old": {"collected_at": old["collected_at"], "version": old["device"].get("version")},
        "new": {"collected_at": new["collected_at"], "version": new["device"].get("version")},
        "device": new["device"].get("hostname"),
        "policies": {"added": [np_[k] for k in np_ if k not in op], "removed": [op[k] for k in op if k not in np_],
                     "modified": [], "moved": []},
        "objects": [], "attribution": {}, "events": events[:200],
    }
    for k in np_:
        if k in op:
            ignore = POLICY_IGNORE
            if op[k].get("unsupported_match") is None or np_[k].get("unsupported_match") is None:
                ignore = ignore | {"unsupported_match"}
            ch = _fields_changed(op[k], np_[k], ignore)
            if ch:
                res["policies"]["modified"].append({"policy": np_[k], "changes": ch})
    for k in _moved([_pkey(p) for p in old["policies"]], [_pkey(p) for p in new["policies"]]):
        res["policies"]["moved"].append(np_[k])

    for key, lbl, only, cfgpath in TABLES:
        o, n = _table(old, key), _table(new, key)
        if o is None or n is None:
            continue
        for name in n:
            if name not in o:
                res["objects"].append({"type": lbl, "name": name, "change": "added", "changes": [], "cfgpath": cfgpath})
            else:
                fields = [k for k in only if k in o[name] and k in n[name]] if only else None
                ch = _fields_changed(o[name], n[name], only=fields)
                if ch:
                    res["objects"].append({"type": lbl, "name": name, "change": "modified", "changes": ch, "cfgpath": cfgpath})
        for name in o:
            if name not in n:
                res["objects"].append({"type": lbl, "name": name, "change": "removed", "changes": [], "cfgpath": cfgpath})
    for key, lbl, cfgpath in (("global", "System global", "system.global"), ("sslvpn", "SSL-VPN settings", "vpn.ssl.settings")):
        a, b = old.get(key) or {}, new.get(key) or {}
        if not a or not b:
            continue  # not readable in one snapshot (or SSL-VPN not configured): no claim either way
        ch = _fields_changed(a, b, only=sorted(set(a) & set(b)))
        if ch:
            res["objects"].append({"type": lbl, "name": "", "change": "modified", "changes": ch, "cfgpath": cfgpath})
    so, sn = old.get("settings") or {}, new.get("settings") or {}
    for key, (lbl, cfgpath) in SETTING_LABELS.items():
        a, b = so.get(key), sn.get(key)
        if not isinstance(a, dict) or not isinstance(b, dict):
            continue  # not collected in one of the snapshots: no claim either way
        ch = _fields_changed(a, b, only=sorted(set(a) & set(b)))
        if ch:
            res["objects"].append({"type": lbl, "name": "", "change": "modified", "changes": ch, "cfgpath": cfgpath})

    if events:
        P = res["policies"]
        for p in P["added"] + P["removed"] + [m["policy"] for m in P["modified"]] + P["moved"]:
            who = _who(events, "firewall.policy", str(p["policyid"]))
            if who:
                res["attribution"][f"policy:{p['policyid']}"] = who
        for o in res["objects"]:
            who = _who(events, o["cfgpath"], o["name"])
            if who:
                res["attribution"][f"{o['type']}:{o['name']}"] = who
    res["alerts"] = change_alerts(old, new, res)
    res["empty"] = not (any(res["policies"].values()) or res["objects"]
                        or res["old"]["version"] != res["new"]["version"])
    return res


def change_alerts(old: Dict[str, Any], new: Dict[str, Any], d: Dict[str, Any]) -> List[str]:
    """Changes that weaken security and deserve a notification."""
    alerts: List[str] = []
    wan = exposure.wan_interfaces(new)
    r = Resolver(new)
    for o in d["objects"]:
        if o["type"] == "Interface" and o["name"] in wan:
            before = set((old["interfaces"].get(o["name"]) or {}).get("allowaccess", []))
            after = set((new["interfaces"].get(o["name"]) or {}).get("allowaccess", []))
            added = sorted((after - before) & _MGMT)
            if added:
                alerts.append(f"Management access added on internet-facing interface {o['name']}: {', '.join(added)}")
        elif o["type"] in ("Admin", "API user"):
            if o["change"] == "added":
                alerts.append(f"New {o['type'].lower()} account: {o['name']}")
            elif o["change"] == "modified":
                for f, a, b in o["changes"]:
                    if f == "trusthosts" and a and not b:
                        alerts.append(f"Trusted hosts removed from {o['type'].lower()} {o['name']}")
                    if f == "accprofile":
                        alerts.append(f"{o['type']} {o['name']} profile changed: {a} -> {b}")
                    if f == "two_factor" and b == "disable":
                        alerts.append(f"Two-factor authentication removed from {o['type'].lower()} {o['name']}")
        elif o["type"] in {w[0] for w in WEAKENING}:
            for f, a, b in o["changes"]:
                for typ, field, bad, text in WEAKENING:
                    if o["type"] == typ and f == field and b == bad:
                        alerts.append(text)
                if o["type"] == "System global" and f == "admin-https-ssl-versions" and any(
                        v in str(b) for v in ("tlsv1-0", "tlsv1-1")):
                    alerts.append(f"Admin GUI TLS versions weakened to {b}")
                if o["type"] == "System global" and f == "admintimeout":
                    try:
                        if int(b) > 15 >= int(a or 0):
                            alerts.append(f"Admin idle timeout raised to {b} minutes")
                    except (TypeError, ValueError):
                        pass
        elif o["type"] == "SSL-VPN settings":
            fields = ", ".join(f for f, _, _ in o["changes"])
            alerts.append(f"SSL-VPN settings changed ({fields})")
        elif o["type"] == "Local-in policy":
            # local-in policies decide who can reach the firewall itself (admin GUI, SSH, VPN)
            if o["change"] == "removed":
                was = next((x for x in old.get("local_in") or [] if str(x.get("policyid")) == o["name"]), {})
                if was.get("action") == "deny" and was.get("status") == "enable":
                    alerts.append(f"Local-in deny policy #{o['name']} was removed")
            elif o["change"] == "modified":
                alerts.append(f"Local-in policy #{o['name']} changed ({', '.join(f for f, _, _ in o['changes'])})")

    def from_wan(p: Dict[str, Any]) -> bool:
        ifs = r.interfaces(p.get("srcintf", []))
        return ifs is None or bool(set(ifs) & wan)

    def inbound(p: Dict[str, Any]) -> bool:
        if p.get("action") not in ("accept", "ipsec") or p.get("status") != "enable":
            return False
        return from_wan(p)

    def closure(names: List[str]) -> set:
        """The names plus everything reachable through address, service and VIP groups."""
        seen: set = set()
        todo = list(names)
        while todo:
            n = todo.pop()
            if n in seen:
                continue
            seen.add(n)
            for tbl in ("addrgrps", "servicegrps"):
                g = (new.get(tbl) or {}).get(n)
                if g:
                    todo += list(g.get("member", [])) + list(g.get("exclude-member", []))
            todo += list((new.get("vipgrps") or {}).get(n, []))
        return seen

    # an object changes what an existing inbound rule allows without the rule itself changing
    used: Dict[str, List[int]] = {}
    for p in new["policies"]:
        if inbound(p):
            for n in closure(p.get("srcaddr", []) + p.get("dstaddr", []) + p.get("service", [])):
                used.setdefault(n, []).append(p["policyid"])
    for o in d["objects"]:
        if o["type"] in _RULE_OBJECTS and o["change"] == "modified" and o["name"] in used:
            fields = [f for f, _, _ in o["changes"] if f not in ("comment", "name")]
            if fields:
                pids = used[o["name"]]
                shown = ", ".join(f"#{x}" for x in pids[:4]) + (" and more" if len(pids) > 4 else "")
                alerts.append(f"{o['type']} {o['name']}, used by inbound rule{'s' if len(pids) > 1 else ''} {shown}, "
                              f"changed ({', '.join(fields)})")

    for p in d["policies"]["removed"]:
        if p.get("action") == "deny" and p.get("status") == "enable" and from_wan(p):
            alerts.append(f"Deny rule for traffic from the internet was removed: #{p['policyid']} "
                          f"{p.get('name') or ''}".rstrip())
    for p in d["policies"]["moved"]:
        if p.get("status") == "enable" and from_wan(p):
            alerts.append(f"Rule order changed for a rule from the internet: #{p['policyid']} {p.get('name') or ''}".rstrip())

    for p in d["policies"]["added"]:
        if inbound(p):
            alerts.append(f"New inbound rule from the internet: #{p['policyid']} {p.get('name') or ''}".rstrip())
        if p.get("logtraffic") == "disable" and p.get("action") == "accept":
            alerts.append(f"New accept rule without logging: #{p['policyid']}")
    for m in d["policies"]["modified"]:
        p, fields = m["policy"], {f for f, _, _ in m["changes"]}
        if inbound(p) and fields & {"action", "status", "srcintf", "srcaddr", "dstaddr", "service", "srcaddr-negate"}:
            alerts.append(f"Inbound rule #{p['policyid']} changed ({', '.join(sorted(fields))})")
        for f, a, b in m["changes"]:
            if f == "logtraffic" and b == "disable":
                alerts.append(f"Logging disabled on rule #{p['policyid']}")
            if f == "status" and b != "enable" and p.get("action") == "deny" and from_wan(p):
                alerts.append(f"Deny rule for traffic from the internet was disabled: #{p['policyid']}")
    return alerts


def _fmt(v: Any) -> str:
    if isinstance(v, list):
        return ", ".join(map(str, v)) or "(empty)"
    return "(unset)" if v in (None, "") else str(v)


def _plabel(p: Dict[str, Any]) -> str:
    return f"#{p['policyid']}" + (f" '{p['name']}'" if p.get("name") else "")


def render_text(d: Dict[str, Any]) -> str:
    out = [f"Changes on {d['device'] or 'device'}: {d['old']['collected_at']} -> {d['new']['collected_at']}"]
    if d["old"]["version"] != d["new"]["version"]:
        out.append(f"  FortiOS: {d['old']['version']} -> {d['new']['version']}")
    if d["empty"]:
        out.append("  No changes.")
        return clean_multiline("\n".join(out))
    for a in d.get("alerts", []):
        out.append(f"  ! {a}")
    att = d.get("attribution", {})

    def by(key: str) -> None:
        for w in att.get(key, []):
            out.append(f"      by {w}")

    P = d["policies"]
    for p in P["added"]:
        out.append(f"  + policy {_plabel(p)}  {','.join(p['srcintf'])}->{','.join(p['dstintf'])} {p['action']}")
        by(f"policy:{p['policyid']}")
    for p in P["removed"]:
        out.append(f"  - policy {_plabel(p)}")
        by(f"policy:{p['policyid']}")
    for m in P["modified"]:
        out.append(f"  ~ policy {_plabel(m['policy'])}")
        for f, a, b in m["changes"]:
            out.append(f"      {f}: {_fmt(a)} -> {_fmt(b)}")
        by(f"policy:{m['policy']['policyid']}")
    for p in P["moved"]:
        out.append(f"  ^ policy {_plabel(p)} moved in sequence")
        by(f"policy:{p['policyid']}")
    sym = {"added": "+", "removed": "-", "modified": "~"}
    for o in d["objects"]:
        out.append(f"  {sym[o['change']]} {o['type'].lower()} {o['name']}".rstrip())
        for f, a, b in o["changes"]:
            out.append(f"      {f}: {_fmt(a)} -> {_fmt(b)}")
        by(f"{o['type']}:{o['name']}")
    return clean_multiline("\n".join(out))


def render_html(d: Dict[str, Any], palette: str = "harbor") -> str:
    from .ui import CONTROLS, CSS, THEME_HEAD, THEME_JS, html_open
    e = lambda x: escape(str(x))  # noqa: E731
    att = d.get("attribution", {})
    rows = []
    P = d["policies"]

    def who(key: str) -> str:
        return "<br>".join(e(w) for w in att.get(key, [])) or '<span class="dim">-</span>'

    for p in P["added"]:
        rows.append(("Added", f"Policy {_plabel(p)}", f"{e(', '.join(p['srcintf']))} &rarr; {e(', '.join(p['dstintf']))}, "
                     f"{e(', '.join(p['srcaddr']))} &rarr; {e(', '.join(p['dstaddr']))}, {e(', '.join(p['service']))}, {e(p['action'])}",
                     who(f"policy:{p['policyid']}")))
    for p in P["removed"]:
        rows.append(("Removed", f"Policy {_plabel(p)}", "", who(f"policy:{p['policyid']}")))
    for m in P["modified"]:
        rows.append(("Modified", f"Policy {_plabel(m['policy'])}",
                     "<br>".join(f"<b>{e(f)}</b>: {e(_fmt(a))} &rarr; {e(_fmt(b))}" for f, a, b in m["changes"]),
                     who(f"policy:{m['policy']['policyid']}")))
    for p in P["moved"]:
        rows.append(("Moved", f"Policy {_plabel(p)}", "Position in the rule sequence changed", who(f"policy:{p['policyid']}")))
    for o in d["objects"]:
        rows.append((o["change"].capitalize(), f"{o['type']} {o['name']}".strip(),
                     "<br>".join(f"<b>{e(f)}</b>: {e(_fmt(a))} &rarr; {e(_fmt(b))}" for f, a, b in o["changes"]),
                     who(f"{o['type']}:{o['name']}")))
    body = "".join(f"<tr><td>{e(a)}</td><td>{e(b)}</td><td>{c}</td><td>{w}</td></tr>" for a, b, c, w in rows) \
        or "<tr><td colspan=4>No changes.</td></tr>"
    alerts = "".join(f'<p><span class="pill high">Alert</span> {e(a)}</p>' for a in d.get("alerts", []))
    ver = (f"<p>FortiOS changed: {e(d['old']['version'])} &rarr; {e(d['new']['version'])}</p>"
           if d["old"]["version"] != d["new"]["version"] else "")
    ev_rows = "".join(
        f"<tr><td class=mono>{e(_dt.datetime.fromtimestamp(x['time'], _dt.timezone.utc).strftime('%Y-%m-%d %H:%M') if x.get('time') else '')}</td>"
        f"<td>{e(x.get('user'))}</td><td>{e(x.get('ui'))}</td><td>{e(x.get('action'))}</td>"
        f"<td>{e(x.get('cfgpath'))} {e(x.get('cfgobj'))}</td><td>{e(x.get('cfgattr') or x.get('msg'))}</td></tr>"
        for x in d.get("events", []))
    events = (f"<h2>Configuration events in this period</h2><table class=exp><thead><tr><th>Time (UTC)</th><th>User</th>"
              f"<th>Interface</th><th>Action</th><th>Object</th><th>Change</th></tr></thead><tbody>{ev_rows}</tbody></table>"
              if ev_rows else "")
    return (f"{html_open(palette)}<head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>Change report: {e(d['device'] or 'FortiGate')}</title>{THEME_HEAD}<style>{CSS}</style></head><body><div class=wrap>"
            f"<header class=top><div><div class=kicker>Configuration change report</div><h1>{e(d['device'] or 'FortiGate')}</h1>"
            f"<div class=meta>{e(d['old']['collected_at'])} &rarr; {e(d['new']['collected_at'])}</div></div>"
            f"<div class=page-tools>{CONTROLS}</div></header>{ver}"
            f"{('<h2>Alerts</h2>' + alerts) if alerts else ''}"
            f"<h2>Changes</h2><table><thead><tr><th>Change</th><th>Item</th><th>Details</th><th>Changed by</th></tr></thead>"
            f"<tbody>{body}</tbody></table>{events}</div>{THEME_JS}</body></html>")


def latest_two(directory: str) -> Tuple[str, str]:
    from .source import list_snapshots
    files = list_snapshots(directory)
    if len(files) < 2:
        raise SystemExit(f"Need at least two snapshots in {directory}, found {len(files)}.")
    return files[-2], files[-1]
