"""Audit checks and orchestration. Every check returns findings in one flat, JSON-serializable shape."""
from __future__ import annotations

import datetime as _dt
import math
from collections import Counter, OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from . import defaults, exposure, firmware, hardening, practices
from .catalog import (AREAS, CHECKS, EFFORT, INTRODUCED_0_4, RATIO_CHECKS, REMOVABLE_CHECKS, SEVERITY_ORDER,
                      compliance_refs, disable_cli, finding, label, q)
from .model import iso_epoch, upgrade
from .resolve import AddrSet, Resolver, SvcSet

PERMIT = ("accept", "ipsec")
COVERAGE_CHECKS = {"REDUNDANT", "SHADOW_CONFLICT", "SHADOW_DEAD"}
_MATCH_CHECKS = COVERAGE_CHECKS | {"ANY_ANY", "OUTBOUND_UNRESTRICTED", "SERVICE_ALL"}
_NEGATIONS = ("srcaddr-negate", "dstaddr-negate", "service-negate")


def _coverage_skipped(p: Dict[str, Any]) -> bool:
    return p.get("unsupported_match") != [] or any(p.get(k) == "enable" for k in _NEGATIONS)



# ---------------------------------------------------------------- matching model

@dataclass
class Match:
    p: Dict[str, Any]
    src_if: Optional[FrozenSet[str]]
    dst_if: Optional[FrozenSet[str]]
    src: AddrSet
    dst: AddrSet
    svc: SvcSet
    ident: Set[str]
    isdb_src: Optional[Set[str]]
    isdb_dst: Optional[Set[str]]
    src6: Set[str]
    dst6: Set[str]
    skip: bool


_ISDB_DST = ["internet-service-name", "internet-service-group", "internet-service-custom",
             "internet-service-custom-group", "internet-service-id"]
_ISDB_SRC = ["internet-service-src-name", "internet-service-src-group", "internet-service-src-custom",
             "internet-service-src-custom-group", "internet-service-src-id"]


def _build_match(p: Dict[str, Any], r: Resolver) -> Match:
    def isdb(enabled: str, fields: List[str]) -> Optional[Set[str]]:
        if enabled != "enable":
            return None
        return {f"{f}:{v}" for f in fields for v in p.get(f, [])}

    skip = _coverage_skipped(p)
    return Match(
        p=p, src_if=r.interfaces(p["srcintf"]), dst_if=r.interfaces(p["dstintf"]),
        src=r.addresses(p["srcaddr"]), dst=r.addresses(p["dstaddr"]), svc=r.services(p["service"]),
        ident=set(p.get("users", [])) | set(p.get("groups", [])) | set(p.get("fsso-groups", [])),
        isdb_src=isdb(p.get("internet-service-src", "disable"), _ISDB_SRC),
        isdb_dst=isdb(p.get("internet-service", "disable"), _ISDB_DST),
        src6=set(p.get("srcaddr6", [])), dst6=set(p.get("dstaddr6", [])), skip=skip,
    )


def _if_covers(a: Optional[FrozenSet[str]], b: Optional[FrozenSet[str]]) -> bool:
    if a is None:
        return True
    return b is not None and b <= a


def _covers_body(a: Match, b: Match) -> bool:
    """Coverage on everything except interfaces (the caller has already checked those)."""
    if a.skip or b.skip:
        return False
    if a.p["schedule"] not in ("always", b.p["schedule"]):
        return False
    if a.ident and not (b.ident and b.ident <= a.ident):
        return False
    if a.isdb_src is not None:
        if b.isdb_src is None or not b.isdb_src <= a.isdb_src:
            return False
    elif b.isdb_src is not None:
        if not a.src.is_full:
            return False
    elif not a.src.covers(b.src):
        return False
    if a.isdb_dst is not None:
        if b.isdb_dst is None or not b.isdb_dst <= a.isdb_dst:
            return False
    elif b.isdb_dst is not None:
        if not (a.dst.is_full and a.svc.is_all):
            return False
    elif not (a.dst.covers(b.dst) and a.svc.covers(b.svc)):
        return False
    for mine, theirs in ((a.src6, b.src6), (a.dst6, b.dst6)):
        if theirs and "all" not in mine and not theirs <= mine:
            return False
    return True


def covers(a: Match, b: Match) -> bool:
    """True if every packet that can match b is matched by a first."""
    return _if_covers(a.src_if, b.src_if) and _if_covers(a.dst_if, b.dst_if) and _covers_body(a, b)


class _CellIndex:
    """Interval 'stabbing' index: each interval is filed under the smallest aligned power-of-two
    block that contains it, so the rules whose intervals can contain a query interval are found
    by looking up that interval's 33 enclosing blocks (/0 .. /32)."""
    __slots__ = ("cells",)

    def __init__(self) -> None:
        self.cells: Dict[Tuple[int, int], List[int]] = {}

    def add(self, ivs: List[Tuple[int, int]], idx: int) -> None:
        seen = set()
        for lo, hi in ivs:
            lvl = 32 - (lo ^ hi).bit_length()
            key = (lvl, lo >> (32 - lvl))
            if key not in seen:
                seen.add(key)
                self.cells.setdefault(key, []).append(idx)

    def query(self, lo: int, hi: int, out: Set[int]) -> None:
        cells = self.cells
        for lvl in range(33 - (lo ^ hi).bit_length()):
            lst = cells.get((lvl, lo >> (32 - lvl)))
            if lst:
                out.update(lst)


def _widest(ivs: List[Tuple[int, int]]) -> Tuple[int, int]:
    return max(ivs, key=lambda t: t[1] - t[0])


class _Bucket:
    """Earlier rules sharing one (srcintf, dstintf) pair, indexed by destination (or, for rules whose
    destination is 'all', by source) so a rule is only compared with rules that could contain it."""
    __slots__ = ("all", "dst_idx", "fullsrc_idx", "dst_full")

    def __init__(self) -> None:
        self.all: List[int] = []
        self.dst_idx = _CellIndex()
        self.fullsrc_idx = _CellIndex()
        self.dst_full: List[int] = []

    def add(self, m: Match, i: int) -> None:
        self.all.append(i)
        if m.isdb_dst is not None:
            return
        if m.dst.is_full:
            self.dst_full.append(i)
            if m.isdb_src is None and m.src.iv:
                self.fullsrc_idx.add(m.src.iv, i)
        elif m.dst.iv:
            self.dst_idx.add(m.dst.iv, i)

    def candidates(self, b: Match) -> List[int]:
        if b.isdb_dst is not None or not b.dst.iv:
            return self.all
        out: Set[int] = set()
        if b.isdb_src is None and b.src.iv:
            self.fullsrc_idx.query(*_widest(b.src.iv), out)
        else:
            out.update(self.dst_full)
        if not b.dst.is_full:
            self.dst_idx.query(*_widest(b.dst.iv), out)
        return sorted(out)


def first_cover(matches: List[Match]) -> List[Optional[int]]:
    """For each rule, the index of the earliest enabled rule above it that fully covers it.

    Rules are bucketed by (srcintf, dstintf); inside a bucket an interval index narrows the
    candidates to rules whose addresses can contain the rule's addresses. Exactness is kept:
    every candidate is still verified with the full coverage test.
    """
    buckets: "OrderedDict[Tuple[Optional[FrozenSet[str]], Optional[FrozenSet[str]]], _Bucket]" = OrderedDict()
    out: List[Optional[int]] = []
    for i, b in enumerate(matches):
        best: Optional[int] = None
        if not b.skip:
            for (ks, kd), bucket in buckets.items():
                if not (_if_covers(ks, b.src_if) and _if_covers(kd, b.dst_if)):
                    continue
                for j in bucket.candidates(b):
                    if best is not None and j >= best:
                        break
                    if _covers_body(matches[j], b):
                        best = j
                        break
        out.append(best)
        key = (b.src_if, b.dst_if)
        bk = buckets.get(key)
        if bk is None:
            bk = buckets[key] = _Bucket()
        bk.add(b, i)
    return out


def first_cover_bruteforce(matches: List[Match]) -> List[Optional[int]]:
    """Reference implementation used by the tests to prove the index changes nothing."""
    out: List[Optional[int]] = []
    for i, b in enumerate(matches):
        out.append(next((j for j in range(i) if covers(matches[j], b)), None))
    return out


# ---------------------------------------------------------------- rule base

def _sched_expired(snap: Dict[str, Any], name: str, now: int, depth: int = 0) -> bool:
    sch = snap.get("schedules") or {}
    one = sch.get("onetime", {})
    if name in one:
        e = one[name].get("end_epoch")
        return e is not None and e < now - 86400
    grp = sch.get("groups", {}).get(name)
    if grp and depth < 5:
        return all(_sched_expired(snap, m, now, depth + 1) for m in grp)
    return False


def check_rulebase(snap: Dict[str, Any], r: Resolver, wan: Set[str], today: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    now = iso_epoch(snap["collected_at"])
    enabled = [p for p in snap["policies"] if p["status"] == "enable"]
    matches = [_build_match(p, r) for p in enabled]

    for b, idx in zip(matches, first_cover(matches)):
        if idx is None:
            continue
        pa, pb = matches[idx].p, b.p
        a_perm, b_perm = pa["action"] in PERMIT, pb["action"] in PERMIT
        if a_perm == b_perm:
            out.append(finding("REDUNDANT", policyid=pb["policyid"],
                detail=f"{label(pb)} is fully covered by earlier {label(pa)} ({pa['action']}).",
                cli=disable_cli(pb, f"redundant, covered by policy {pa['policyid']}", today)))
        elif a_perm:
            out.append(finding("SHADOW_CONFLICT", policyid=pb["policyid"],
                detail=f"Deny {label(pb)} is shadowed by earlier accept {label(pa)}.",
                cli=["config firewall policy", f"    move {pb['policyid']} before {pa['policyid']}", "end"],
                cli_safe=False))
        else:
            out.append(finding("SHADOW_DEAD", policyid=pb["policyid"],
                detail=f"Accept {label(pb)} is shadowed by earlier deny {label(pa)}.",
                cli=disable_cli(pb, f"shadowed by deny policy {pa['policyid']}", today)))

    for m in matches:
        p = m.p
        if p["action"] not in PERMIT:
            continue
        if not m.skip and m.svc.is_all and m.isdb_dst is None:
            outbound = bool(m.dst_if) and set(m.dst_if) <= wan
            dst_full = m.dst.is_full
            src_full = m.isdb_src is None and m.src.is_full
            if outbound and dst_full:
                out.append(finding("OUTBOUND_UNRESTRICTED", policyid=p["policyid"],
                    detail=f"{label(p)}: {', '.join(p['srcaddr']) or '-'} -> any internet destination, all services "
                           f"({','.join(p['srcintf'])} -> {','.join(p['dstintf'])})."))
            elif src_full and dst_full and not m.ident:
                out.append(finding("ANY_ANY", policyid=p["policyid"],
                    detail=f"{label(p)}: {','.join(p['srcintf'])} -> {','.join(p['dstintf'])}, all sources, "
                           "all destinations, all services."))
            else:
                out.append(finding("SERVICE_ALL", policyid=p["policyid"],
                    detail=f"{label(p)}: service ALL from {', '.join(p['srcaddr']) or '-'} to {', '.join(p['dstaddr']) or '-'}."))
        if p["logtraffic"] == "disable":
            cli = ["config firewall policy", f"    edit {p['policyid']}", "        set logtraffic all", "    next", "end"]
            out.append(finding("NO_LOG", policyid=p["policyid"], detail=f"{label(p)} has logtraffic disable.", cli=cli))
        to_wan = m.dst_if is None or bool(set(m.dst_if) & wan)
        has_profiles = p["utm-status"] == "enable" and any(p.get(f) for f in
            ("av-profile", "webfilter-profile", "dnsfilter-profile", "ips-sensor", "application-list",
             "file-filter-profile", "profile-group"))
        if to_wan and wan and not has_profiles:
            out.append(finding("NO_UTM_WAN", policyid=p["policyid"],
                detail=f"{label(p)} -> {','.join(p['dstintf'])} has no security profiles."))

    for p in enabled:
        if p["schedule"] and _sched_expired(snap, p["schedule"], now):
            out.append(finding("EXPIRED_SCHEDULE", policyid=p["policyid"],
                detail=f"{label(p)} uses schedule '{p['schedule']}', which has ended.",
                cli=disable_cli(p, f"schedule {p['schedule']} expired", today)))

    for p in snap["policies"]:
        if p["status"] != "enable":
            out.append(finding("DISABLED", policyid=p["policyid"], detail=f"{label(p)} is disabled.",
                cli=["config firewall policy", f"    delete {p['policyid']}", "end"], cli_safe=False))
        if not p.get("name") and not p.get("comments"):
            out.append(finding("NO_NAME", policyid=p["policyid"], detail=f"Policy #{p['policyid']} has neither name nor comment."))
    return out


def check_usage(snap: Dict[str, Any], stale_days: int, today: str) -> List[Dict[str, Any]]:
    hits = snap.get("hits")
    if hits is None:
        return []
    out = []
    now = iso_epoch(snap["collected_at"])
    for p in snap["policies"]:
        if p["status"] != "enable":
            continue
        h = hits.get(str(p["policyid"]))
        if h is None:
            continue
        if h["hit_count"] == 0:
            if p["action"] in PERMIT:
                out.append(finding("UNUSED", policyid=p["policyid"], detail=f"{label(p)}: 0 hits.",
                    cli=disable_cli(p, "zero hits", today)))
            else:
                out.append(finding("UNUSED_DENY", policyid=p["policyid"], detail=f"{label(p)}: 0 hits."))
        elif h["last_used"] and now - h["last_used"] > stale_days * 86400:
            days = int((now - h["last_used"]) // 86400)
            out.append(finding("STALE", policyid=p["policyid"],
                detail=f"{label(p)}: last hit {days} days ago ({h['hit_count']:,} hits total)."))
    return out


# ---------------------------------------------------------------- objects

def check_objects(snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    refs = snap.get("references")
    if refs is None:
        c: Counter = Counter()
        for p in snap["policies"]:
            for f in ("srcaddr", "dstaddr", "srcaddr6", "dstaddr6", "service"):
                c.update(p.get(f, []))
        for g in list(snap["addrgrps"].values()) + list(snap["servicegrps"].values()):
            c.update(g["member"])
            c.update(g.get("exclude-member", []))
        for members in snap.get("vipgrps", {}).values():
            c.update(members)
        for li in snap.get("local_in", []):
            c.update(li["srcaddr"] + li["dstaddr"] + li["service"])
        ssl = snap.get("sslvpn") or {}
        c.update(ssl.get("source_address", []))
        refs = c
    tables = [
        ("addresses", "firewall address", defaults.DEFAULT_ADDRESSES),
        ("addrgrps", "firewall addrgrp", defaults.DEFAULT_ADDRGRPS),
        ("services", "firewall service custom", defaults.DEFAULT_SERVICES),
        ("servicegrps", "firewall service group", defaults.DEFAULT_SERVICEGRPS),
        ("vips", "firewall vip", set()),
        ("vipgrps", "firewall vipgrp", set()),
    ]
    out = []
    for key, path, builtin in tables:
        for name, o in snap.get(key, {}).items():
            otype = o.get("type") if isinstance(o, dict) else None
            if name in builtin or otype == "interface-subnet":
                continue
            if refs.get(name, 0) == 0:
                out.append(finding("UNUSED_OBJECT", obj=name, detail=f"{path} {q(name)} is not referenced.",
                    cli=[f"config {path}", f"    delete {q(name)}", "end"]))
    return out


# ---------------------------------------------------------------- admin access

def check_admin(snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    admins = snap.get("admins") or {}
    for name, i in snap["interfaces"].items():
        aa = i.get("allowaccess", [])
        clean = [x for x in aa if x not in ("telnet", "http")]  # one fix per interface for both findings
        fix = ["config system interface", f"    edit {q(name)}", f"        set allowaccess {' '.join(clean) or 'ping'}",
               "    next", "end"]
        if "telnet" in aa:
            out.append(finding("ADMIN_TELNET", obj=name, detail=f"Interface {name} allows: {' '.join(aa)}.",
                               cli=fix, cli_scope="global"))
        if "http" in aa:
            out.append(finding("ADMIN_HTTP", obj=name, detail=f"Interface {name} allows: {' '.join(aa)}.",
                               cli=fix, cli_scope="global"))
    for a in admins.values():
        if not a["trusthosts"]:
            out.append(finding("ADMIN_NO_TRUSTHOST", obj=a["name"],
                               detail=f"Admin '{a['name']}' ({a['accprofile']}) has no trusted hosts."))
    if "admin" in admins:
        out.append(finding("DEFAULT_ADMIN", obj="admin", detail="Account 'admin' is present."))
    for u in (snap.get("api_users") or {}).values():
        if not u["trusthosts"]:
            out.append(finding("APIUSER_NO_TRUSTHOST", obj=u["name"], detail=f"API user '{u['name']}' has no trusted hosts."))
    g = snap.get("global", {})
    if g.get("strong-crypto") == "disable":
        out.append(finding("WEAK_CRYPTO", obj="system global", detail="strong-crypto is disabled.",
            cli=["config system global", "    set strong-crypto enable", "end"], cli_scope="global"))
    try:
        if int(g.get("admintimeout", "5")) > 15:
            out.append(finding("LONG_ADMIN_TIMEOUT", obj="system global",
                detail=f"admintimeout is {g['admintimeout']} minutes.",
                cli=["config system global", "    set admintimeout 15", "end"], cli_scope="global"))
    except ValueError:
        pass
    return out


# ---------------------------------------------------------------- VPN

_WEAK_ENC = {"des", "3des", "null"}
_WEAK_DH = {"1", "2", "5"}


def _weak_items(proposals: List[str], dh: Optional[List[str]]) -> Tuple[List[str], bool]:
    """Returns (weak items, any of them serious). sha1 alone is reported as a minor weakness."""
    weak, serious = [], False
    for prop in proposals:
        parts = prop.lower().split("-")
        enc, hsh = parts[0], parts[-1] if len(parts) > 1 else ""
        if enc in _WEAK_ENC or hsh == "md5":
            weak.append(prop)
            serious = True
        elif hsh == "sha1":
            weak.append(prop)
    for g in dh or []:
        if g in _WEAK_DH:
            weak.append(f"DH group {g}")
            serious = True
    return weak, serious


def check_vpn(snap: Dict[str, Any], r: Resolver, wan: Set[str]) -> List[Dict[str, Any]]:
    out = []
    for p1 in snap.get("ipsec_p1", {}).values():
        weak, serious = _weak_items(p1.get("proposal", []), p1.get("dhgrp"))
        if weak:
            out.append(finding("VPN_WEAK_CRYPTO", obj=p1["name"], severity="medium" if serious else "low",
                detail=f"Phase 1 '{p1['name']}' allows {', '.join(weak)}.",
                cli=["config vpn ipsec phase1-interface", f"    edit {q(p1['name'])}",
                     "        set proposal aes256-sha256 aes256gcm-prfsha384", "        set dhgrp 21 20 14",
                     "    next", "end"], cli_safe=False))
        if p1.get("ike_version") == "1" and p1.get("mode") == "aggressive" and p1.get("authmethod") == "psk":
            out.append(finding("VPN_AGGRESSIVE_PSK", obj=p1["name"],
                detail=f"Phase 1 '{p1['name']}' ({'dial-up' if p1.get('type') == 'dynamic' else 'site-to-site'}) "
                       "uses IKEv1 aggressive mode with a pre-shared key."))
    for p2 in snap.get("ipsec_p2", {}).values():
        weak, serious = _weak_items(p2.get("proposal", []), p2.get("dhgrp") if p2.get("pfs") != "disable" else None)
        if weak:
            out.append(finding("VPN_WEAK_CRYPTO", obj=p2["name"], severity="medium" if serious else "low",
                detail=f"Phase 2 '{p2['name']}' (tunnel {p2.get('phase1name') or '?'}) allows {', '.join(weak)}.",
                cli=["config vpn ipsec phase2-interface", f"    edit {q(p2['name'])}",
                     "        set proposal aes256-sha256 aes256gcm", "        set dhgrp 21 20 14",
                     "    next", "end"], cli_safe=False))
        if p2.get("pfs") == "disable":
            out.append(finding("VPN_NO_PFS", obj=p2["name"],
                detail=f"Phase 2 '{p2['name']}' (tunnel {p2.get('phase1name') or '?'}) has pfs disable.",
                cli=["config vpn ipsec phase2-interface", f"    edit {q(p2['name'])}", "        set pfs enable",
                     "        set dhgrp 21 20 14", "    next", "end"], cli_safe=False))
    ssl = snap.get("sslvpn") or {}
    if exposure.sslvpn_listening(snap, r, wan) and ssl.get("ssl_min_proto") in ("tls1-0", "tls1-1"):
        out.append(finding("SSLVPN_WEAK_TLS", obj="vpn ssl settings",
            detail=f"ssl-min-proto-ver is {ssl.get('ssl_min_proto')}.",
            cli=["config vpn ssl settings", "    set ssl-min-proto-ver tls1-2", "end"]))
    return out


# ---------------------------------------------------------------- scoring

SEV_WEIGHT = {"high": 15.0, "medium": 6.0, "low": 2.0, "info": 0.0}
HIGH_CAP = 69  # any high-severity finding limits the overall grade to D


def grade_for(s: int) -> str:
    return "A" if s >= 90 else "B" if s >= 80 else "C" if s >= 70 else "D" if s >= 55 else "F"


def score(findings: List[Dict[str, Any]], st: Dict[str, Any]) -> Dict[str, Any]:
    """Each area starts at 100. Absolute checks cost weight x (1 + log2 n), capped at 4x weight;
    hygiene checks cost weight x (1 + 9 x share of rules/objects affected). Overall = weighted
    mean of areas, capped at 69 (grade D) while any high-severity finding remains."""
    pen = {a: 0.0 for a in AREAS}
    per = Counter((f["check"], f["severity"]) for f in findings)
    for (cid, sev), n in per.items():
        w = SEV_WEIGHT[sev]
        if not w:
            continue
        base = RATIO_CHECKS.get(cid)
        if base:
            denom = st["enabled"] if base == "policies" else st["objects_total"]
            ratio = min(1.0, n / max(denom, 1))
            pen[CHECKS[cid][1]] += w * (1 + 9 * ratio)
        else:
            pen[CHECKS[cid][1]] += min(w * (1 + math.log2(n)), 4 * w)
    areas = {a: max(0, round(100 - p)) for a, p in pen.items()}
    overall = round(sum(areas[a] * AREAS[a][1] for a in AREAS))
    if any(f["severity"] == "high" for f in findings):
        overall = min(overall, HIGH_CAP)
    return {"score": overall, "grade": grade_for(overall), "areas": areas}


def stats(snap: Dict[str, Any]) -> Dict[str, Any]:
    pol = snap["policies"]
    en = [p for p in pol if p["status"] == "enable"]
    acc = [p for p in en if p["action"] in PERMIT]
    hits = snap.get("hits")
    zero = None
    if hits is not None:
        zero = sum(1 for p in en if (hits.get(str(p["policyid"])) or {}).get("hit_count", 1) == 0)
    return {
        "policies": len(pol), "enabled": len(en), "disabled": len(pol) - len(en),
        "accept": len(acc), "deny": len(en) - len(acc),
        "logged": sum(1 for p in acc if p["logtraffic"] != "disable"),
        "with_profiles": sum(1 for p in acc if p["utm-status"] == "enable"),
        "addresses": len(snap["addresses"]), "addrgrps": len(snap["addrgrps"]),
        "services": len(snap["services"]), "servicegrps": len(snap["servicegrps"]),
        "objects_total": sum(len(snap.get(k, {})) for k in ("addresses", "addrgrps", "services", "servicegrps",
                                                            "vips", "vipgrps")),
        "zero_hit": zero,
    }


def top_actions(findings: List[Dict[str, Any]], limit: int = 8) -> List[Dict[str, Any]]:
    groups: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()
    for f in findings:
        if f["severity"] != "info":
            groups.setdefault(f["check"], []).append(f)
    ranked = sorted(groups.items(), key=lambda kv: (min(SEVERITY_ORDER[f["severity"]] for f in kv[1]),
                                                    -AREAS[CHECKS[kv[0]][1]][1], -len(kv[1])))
    out = []
    for cid, items in ranked[:limit]:
        targets = [f"#{f['policyid']}" if f["policyid"] is not None else str(f["object"]) for f in items]
        out.append({"check": cid, "severity": min((f["severity"] for f in items), key=lambda s: SEVERITY_ORDER[s]),
                    "title": CHECKS[cid][2], "recommendation": CHECKS[cid][4], "count": len(items),
                    "targets": targets[:8], "more": max(0, len(targets) - 8)})
    return out


def quick_wins(findings: List[Dict[str, Any]], limit: int = 12) -> List[Dict[str, Any]]:
    """Single-setting fixes with ready, uncommented commands: the work that can be done today."""
    groups: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()
    for f in findings:
        if f.get("effort") == "quick" and f["severity"] != "info" and f["cli"] and f["cli_safe"]:
            groups.setdefault(f["check"], []).append(f)
    ranked = sorted(groups.items(), key=lambda kv: (min(SEVERITY_ORDER[f["severity"]] for f in kv[1]),
                                                    -AREAS[CHECKS[kv[0]][1]][1], -len(kv[1])))
    out = []
    for cid, items in ranked[:limit]:
        targets = [f"#{f['policyid']}" if f["policyid"] is not None else str(f["object"]) for f in items]
        out.append({"check": cid, "severity": min((f["severity"] for f in items), key=lambda s: SEVERITY_ORDER[s]),
                    "title": CHECKS[cid][2], "count": len(items), "targets": targets[:8], "more": max(0, len(targets) - 8)})
    return out


def cleanup(snap: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    removable = {f["policyid"] for f in findings if f["check"] in REMOVABLE_CHECKS and f["policyid"] is not None}
    total = len(snap["policies"])
    return {"policies": len(removable), "total": total,
            "percent": round(100 * len(removable) / total) if total else 0,
            "objects": sum(1 for f in findings if f["check"] == "UNUSED_OBJECT")}


def finding_key(f: Dict[str, Any]) -> Tuple[str, str, str]:
    return (f["check"], "" if f.get("policyid") is None else str(f["policyid"]), f.get("object") or "")


def compare(now: Dict[str, Any], before: Dict[str, Any]) -> Dict[str, Any]:
    """Resolved / new findings, counting only checks evaluated in both runs (a check added in a newer
    version, or one whose data the older run could not read, must not show up as 'new')."""
    ev_now = set(now["evaluated"]) if now.get("evaluated") is not None else set(CHECKS) - INTRODUCED_0_4
    ev_before = set(before["evaluated"]) if before.get("evaluated") is not None else set(CHECKS) - INTRODUCED_0_4
    both = ev_now & ev_before
    # Older findings JSON may claim these checks ran, but lacked complete match inputs.
    if now.get("policy_coverage_complete") is not True or before.get("policy_coverage_complete") is not True:
        both -= _MATCH_CHECKS
    b = {finding_key(f): f for f in before["findings"] if f["check"] in both}
    n = {finding_key(f): f for f in now["findings"] if f["check"] in both}
    slim = lambda f: {k: f.get(k) for k in ("check", "severity", "title", "policyid", "object", "detail")}  # noqa: E731
    return {
        "baseline_date": before["collected_at"], "score_before": before["score"], "grade_before": before["grade"],
        "resolved": [slim(f) for k, f in b.items() if k not in n],
        "new": [slim(f) for k, f in n.items() if k not in b],
        "persisting": sum(1 for k in n if k in b),
    }


def analysis_notes(snap: Dict[str, Any], wan: Set[str]) -> List[str]:
    notes = []
    src = snap.get("usage_source")
    since = snap.get("counter_since")
    if snap.get("hits") is None:
        notes.append("No usage data (offline config without --usage): zero-hit and stale-rule checks are skipped.")
    elif since:
        d = _dt.datetime.fromtimestamp(int(since), _dt.timezone.utc).strftime("%Y-%m-%d")
        notes.append(f"Usage data covers the period since {d}"
                     + (" (last reboot)" if src == "counters" else "") + ". Rules used only quarterly or yearly "
                     "may show zero hits; confirm with owners before deleting.")
    elif src == "counters":
        notes.append("Hit counters reset on reboot and when cleared; the counter window is unknown. "
                     "Confirm zero-hit rules with owners before deleting.")
    if not wan:
        notes.append("No internet-facing interface was identified (no WAN role, SD-WAN member, default route or "
                     "VIP external interface); exposure checks may be incomplete. Set them with --wan.")
    enabled = [p for p in snap["policies"] if p["status"] == "enable"]
    unknown = sum(p.get("unsupported_match") is None for p in enabled)
    unsupported = sorted({f for p in enabled for f in (p.get("unsupported_match") or [])}
                         | {f for p in enabled for f in _NEGATIONS if p.get(f) == "enable"})
    if unknown:
        notes.append(f"Policy coverage is unknown for {unknown} enabled policies: older snapshots did not preserve "
                     "unsupported match criteria. Recollect to assess redundancy, shadowing and broad matches; other checks continue.")
    if unsupported:
        notes.append("Redundancy, shadowing and broad-match checks exclude policies with unsupported match criteria: "
                     + ", ".join(unsupported) + ". No coverage-based cleanup is suggested for those policies.")
    return notes + list(snap.get("notes", []))


def analyze(snap: Dict[str, Any], stale_days: int = 90, baseline: Optional[Dict[str, Any]] = None,
            advisories: Optional[Dict[str, Any]] = None, lifecycle_table: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """`baseline` is an earlier snapshot or an earlier analysis result (findings JSON).
    `advisories` is the result of firmware.AdvisoryClient.lookup() for this device's version (None: not checked)."""
    snap = upgrade(snap)
    today = snap["collected_at"][:10]
    now = iso_epoch(snap["collected_at"])
    r = Resolver(snap)
    wan_why = exposure.wan_reasons(snap)
    wan = set(wan_why)
    exp_rows, exp_findings = exposure.analyze(snap, r, wan, today)
    fw = firmware.summarize(snap, advisories, lifecycle_table)
    findings = (check_rulebase(snap, r, wan, today) + check_usage(snap, stale_days, today)
                + check_objects(snap) + check_admin(snap) + check_vpn(snap, r, wan) + exp_findings
                + hardening.check_all(snap, r, wan, exp_rows, now) + firmware.check_firmware(fw))
    all_ports = {f["policyid"] for f in findings if f["check"] == "EXPOSED_ALL_PORTS"}
    findings = [f for f in findings if not (f["check"] in ("ANY_ANY", "SERVICE_ALL") and f["policyid"] in all_ports)]
    uuids = {p["policyid"]: p.get("uuid") or None for p in snap["policies"]}
    for f in findings:
        if f["policyid"] is not None:
            f["uuid"] = uuids.get(f["policyid"])
        f["compliance"] = compliance_refs(f["check"])
        f.setdefault("effort", EFFORT[f["check"]])
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["check"], f["policyid"] or 0, f["object"] or ""))

    st = stats(snap)
    st["exposed_rules"] = len({x["policyid"] for x in exp_rows if x["kind"] == "Rule"})
    st["exposed_risky"] = sum(1 for f in findings if f["check"] == "EXPOSED_RISKY")
    sc = score(findings, st)
    sev_counts = Counter(f["severity"] for f in findings)
    coverage_complete = all(not _coverage_skipped(p) for p in snap["policies"] if p["status"] == "enable")
    evaluated = hardening.evaluated(snap, fw)
    if not coverage_complete:
        evaluated -= _MATCH_CHECKS
    result = {
        "tool": "rulescope", "device": snap["device"], "source": snap["source"],
        "collected_at": snap["collected_at"], "counter_since": snap.get("counter_since"),
        "usage_source": snap.get("usage_source"), "notes": analysis_notes(snap, wan),
        "stale_days": stale_days, "stats": st, "wan_interfaces": sorted(wan), "wan_reasons": wan_why,
        "severity_counts": {k: sev_counts.get(k, 0) for k in SEVERITY_ORDER},
        **sc, "cleanup": cleanup(snap, findings), "top_actions": top_actions(findings),
        "quick_wins": quick_wins(findings), "exposure": exp_rows, "findings": findings,
        "evaluated": sorted(evaluated), "policy_coverage_complete": coverage_complete, "firmware": fw,
        "change_log": (snap.get("change_log") or [])[:50],
    }
    result["practices"] = practices.evaluate(snap, result, wan)
    if fw["advisories"]["error"] and fw["advisories"]["mode"] != "off":
        result["notes"].append(f"Firmware advisories: {fw['advisories']['error']}.")
    if baseline is not None:
        before = baseline if "findings" in baseline else analyze(baseline, stale_days)
        result["comparison"] = compare(result, before)
    return result
