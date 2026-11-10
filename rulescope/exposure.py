"""Internet exposure: what the internet can reach through this firewall, and how well it is protected.

Sources of exposure: inbound accept rules from internet-facing interfaces (to VIPs or to
routed destinations), management access on WAN interfaces, the SSL-VPN portal, and IKE
listeners for IPsec. Severity depends on who can reach the service (anyone, some countries,
specific addresses) and what the service is.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Set, Tuple

from .catalog import finding, label, q, step_down
from .resolve import Resolver, SvcSet, _merge

PERMIT = ("accept", "ipsec")

# name, [(proto, lo, hi)], severity when reachable from any internet source
RISKY_SERVICES: List[Tuple[str, List[Tuple[str, int, int]], str]] = [
    ("RDP", [("tcp", 3389, 3389), ("udp", 3389, 3389)], "high"),
    ("SMB", [("tcp", 445, 445)], "high"),
    ("NetBIOS", [("tcp", 137, 139), ("udp", 137, 139)], "high"),
    ("MS-RPC", [("tcp", 135, 135)], "high"),
    ("Telnet", [("tcp", 23, 23)], "high"),
    ("WinRM", [("tcp", 5985, 5986)], "high"),
    ("VNC", [("tcp", 5900, 5903)], "high"),
    ("MS SQL", [("tcp", 1433, 1433), ("udp", 1434, 1434)], "high"),
    ("MySQL", [("tcp", 3306, 3306)], "high"),
    ("PostgreSQL", [("tcp", 5432, 5432)], "high"),
    ("Oracle DB", [("tcp", 1521, 1521)], "high"),
    ("MongoDB", [("tcp", 27017, 27017)], "high"),
    ("Redis", [("tcp", 6379, 6379)], "high"),
    ("Elasticsearch", [("tcp", 9200, 9200)], "high"),
    ("Memcached", [("tcp", 11211, 11211), ("udp", 11211, 11211)], "high"),
    ("Docker API", [("tcp", 2375, 2376)], "high"),
    ("Kubelet", [("tcp", 10250, 10250)], "high"),
    ("LDAP", [("tcp", 389, 389), ("udp", 389, 389)], "high"),
    ("Kerberos", [("tcp", 88, 88), ("udp", 88, 88)], "high"),
    ("SNMP", [("udp", 161, 161)], "high"),
    ("NFS", [("tcp", 2049, 2049), ("udp", 2049, 2049)], "high"),
    ("RPCbind", [("tcp", 111, 111), ("udp", 111, 111)], "high"),
    ("TFTP", [("udp", 69, 69)], "high"),
    ("IPMI", [("udp", 623, 623)], "high"),
    ("X11", [("tcp", 6000, 6063)], "high"),
    ("rsync", [("tcp", 873, 873)], "high"),
    ("Modbus", [("tcp", 502, 502)], "high"),
    ("Siemens S7", [("tcp", 102, 102)], "high"),
    ("DNP3", [("tcp", 20000, 20000)], "high"),
    ("EtherNet/IP", [("tcp", 44818, 44818)], "high"),
    ("BACnet", [("udp", 47808, 47808)], "high"),
    ("SSH", [("tcp", 22, 22)], "medium"),
    ("FTP", [("tcp", 21, 21)], "medium"),
    ("SIP", [("udp", 5060, 5061), ("tcp", 5060, 5061)], "medium"),
    ("LDAPS", [("tcp", 636, 636)], "medium"),
    ("Kubernetes API", [("tcp", 6443, 6443)], "medium"),
]

MGMT_PROTOCOLS = {  # allowaccess keyword -> (label, proto, port setting or fixed port)
    "https": ("HTTPS admin", "tcp", "admin-sport"),
    "http": ("HTTP admin", "tcp", "admin-port"),
    "ssh": ("SSH admin", "tcp", "admin-ssh-port"),
    "telnet": ("Telnet admin", "tcp", "admin-telnet-port"),
    "snmp": ("SNMP", "udp", "161"),
    "fgfm": ("FortiManager (FGFM)", "tcp", "541"),
    "radius-acc": ("RADIUS accounting", "udp", "1813"),
    "capwap": ("CAPWAP (FortiAP)", "udp", "5246-5247"),
}
_ADMIN_LOGIN = {"https", "http", "ssh", "telnet"}
_PORT_DEFAULTS = {"admin-sport": "443", "admin-port": "80", "admin-ssh-port": "22", "admin-telnet-port": "23"}


def _range(s: str) -> Optional[Tuple[int, int]]:
    try:
        lo, _, hi = str(s).strip().partition("-")
        lo_i = int(lo)
        hi_i = int(hi) if hi else lo_i
        return min(lo_i, hi_i), max(lo_i, hi_i)
    except ValueError:
        return None


def wan_reasons(snap: Dict[str, Any]) -> Dict[str, List[str]]:
    """Internet-facing interfaces and why each one was chosen.

    Order of authority: a manual list (--wan) replaces detection; --not-wan always removes;
    an interface whose role is explicitly 'lan' or 'dmz' is never picked by the heuristics
    (default route, SD-WAN membership, DHCP client, VIP external interface), because in
    enterprise networks those often point at an upstream internal network, not the internet.
    """
    ifs = snap.get("interfaces", {})
    groups = {**snap.get("sdwan_zones", {}), **snap.get("zones", {})}

    def expand(names: List[str]) -> List[str]:  # zone / SD-WAN zone names -> member interfaces
        out: List[str] = []
        for n in names:
            out += groups.get(n) or [n]
        return out

    exclude = set(expand(snap.get("wan_exclude") or []))
    override = snap.get("wan_override")
    if override:
        return {n: ["set manually"] for n in expand(override) if n not in exclude}
    tunnels = {n for n, i in ifs.items() if i.get("type") == "tunnel"} | set(snap.get("ipsec_p1", {}))
    reasons: Dict[str, List[str]] = {}

    def add(n: Optional[str], why: str, by_role: bool = False) -> None:
        if not n or n == "ssl.root" or n in exclude:
            return
        if not by_role:
            if n in tunnels or ifs.get(n, {}).get("role") in ("lan", "dmz"):
                return
        lst = reasons.setdefault(n, [])
        if why not in lst:
            lst.append(why)

    for n, i in ifs.items():
        if i.get("role") == "wan":
            add(n, "role wan", by_role=True)
        elif i.get("mode") in ("dhcp", "pppoe") and i.get("role") in ("undefined", ""):
            add(n, f"{i['mode']} client")
    sdz = snap.get("sdwan_zones", {})
    for z, members in sdz.items():
        for m in members:
            add(m, f"SD-WAN member ({z})")
    for r in snap.get("default_routes", []):
        add(r.get("device"), "default route")
        for z in r.get("sdwan_zone", []):
            for m in sdz.get(z, []):
                add(m, f"default route via SD-WAN zone {z}")
        if r.get("sdwan"):
            for m in [x for ms in sdz.values() for x in ms]:
                add(m, "default route via SD-WAN")
    for v in snap.get("vips", {}).values():
        e = v.get("extintf")
        if e and e != "any":
            add(e, "VIP external interface")
    return reasons


def wan_interfaces(snap: Dict[str, Any]) -> Set[str]:
    return set(wan_reasons(snap))


def _address_leaves(snap: Dict[str, Any], names: List[str], depth: int = 0) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for n in names:
        if n in snap["addresses"]:
            out.append(snap["addresses"][n])
        elif n in snap["addrgrps"] and depth < 20:
            out += _address_leaves(snap, snap["addrgrps"][n]["member"], depth + 1)
    return out


_PRIVATE = [(0x0A000000, 0x0AFFFFFF), (0xAC100000, 0xAC1FFFFF), (0xC0A80000, 0xC0A8FFFF)]  # RFC 1918
BROAD_SOURCE = 2 ** 24  # this many public addresses (a /8) or more count as "anyone on the internet"


def public_size(ivs: List[Tuple[int, int]]) -> int:
    """Number of public (non RFC 1918) IPv4 addresses in merged intervals."""
    n = 0
    for lo, hi in ivs:
        n += hi - lo + 1
        for plo, phi in _PRIVATE:
            a, b = max(lo, plo), min(hi, phi)
            if a <= b:
                n -= b - a + 1
    return n


def _upper_bound(snap: Dict[str, Any], r: Resolver, names: List[str], depth: int = 0) -> List[Tuple[int, int]]:
    """IPv4 intervals the names can match at most: a group with exclusions counts with all its members."""
    ivs: List[Tuple[int, int]] = []
    for n in names:
        g = snap["addrgrps"].get(n)
        if g is not None and n not in snap["addresses"] and depth < 20:
            ivs += _upper_bound(snap, r, g.get("member", []), depth + 1)
        else:
            ivs += r.address(n).iv
    return ivs


def source_scope(snap: Dict[str, Any], r: Resolver, names: List[str], negate: bool = False,
                 isdb: Optional[List[str]] = None) -> Tuple[str, str]:
    """('any'|'geo'|'isdb'|'restricted', human text)."""
    if isdb:
        return "isdb", "Internet services: " + ", ".join(isdb)
    if negate:
        return "any", "Any except " + ", ".join(names)
    if not names or r.addresses(names).is_full:
        return "any", "Any (internet)"
    # A source list that is not literally "all" can still be most of the internet: a wide range, or a
    # group built as "everything except a few networks". Both are reported like an unrestricted source.
    if public_size(_merge(_upper_bound(snap, r, names))) >= BROAD_SOURCE:
        return "any", "Broad range: " + ", ".join(names[:4]) + (f" +{len(names) - 4}" if len(names) > 4 else "")
    countries = sorted({a["country"] for a in _address_leaves(snap, names) if a["type"] == "geography" and a["country"]})
    if countries:
        return "geo", "Countries: " + ", ".join(countries)
    shown = ", ".join(names[:4]) + (f" +{len(names) - 4}" if len(names) > 4 else "")
    return "restricted", shown


def protection(p: Dict[str, Any]) -> str:
    if p.get("utm-status") != "enable":
        return "none"
    parts = []
    if p.get("profile-group"):
        parts.append(f"profile group '{p['profile-group']}'")
    for f, name in (("ips-sensor", "IPS"), ("av-profile", "AV"), ("webfilter-profile", "web filter"),
                    ("application-list", "app control"), ("file-filter-profile", "file filter")):
        if p.get(f):
            parts.append(name)
    ssl = p.get("ssl-ssh-profile") or ""
    if ssl:
        parts.append("deep inspection" if "deep" in ssl else "certificate inspection" if "certificate" in ssl
                     else f"SSL profile '{ssl}'")
    return ", ".join(parts) or "none"


def has_ips(p: Dict[str, Any]) -> bool:
    return p.get("utm-status") == "enable" and bool(p.get("ips-sensor") or p.get("profile-group"))


def _vip_targets(snap: Dict[str, Any], names: List[str]) -> List[str]:
    out: List[str] = []
    for n in names:
        if n in snap["vips"]:
            out.append(n)
        elif n in snap["vipgrps"]:
            out += [m for m in snap["vipgrps"][n] if m in snap["vips"]]
    return out


def _risky_in(svc: SvcSet, ports: Optional[Tuple[str, int, int]] = None) -> List[Tuple[str, str]]:
    """Risky services allowed by svc (or overlapping one VIP port range). Returns [(name, severity)]."""
    out = []
    for name, ranges, sev in RISKY_SERVICES:
        for proto, lo, hi in ranges:
            if ports is not None:
                vp, vlo, vhi = ports
                if vp != proto or not (vlo <= hi and lo <= vhi):
                    continue
                out.append((name, sev))
                break
            if svc.allows_port(proto, lo, hi):
                out.append((name, sev))
                break
    return out


_SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _worst(sevs: List[str]) -> str:
    return min(sevs, key=lambda s: _SEV_RANK[s]) if sevs else "info"


def _scope_sev(base: str, kind: str) -> Optional[str]:
    if kind == "any":
        return base
    if kind in ("geo", "isdb"):
        return step_down(base)
    return None  # specific sources: listed in the table, no finding


# ---------------------------------------------------------------- analysis

def analyze(snap: Dict[str, Any], r: Resolver, wan: Set[str], today: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    rows: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    hits = snap.get("hits")

    def hit(pid: int) -> Optional[int]:
        if hits is None:
            return None
        h = hits.get(str(pid))
        return None if h is None else h["hit_count"]

    for p in snap["policies"]:
        if p["status"] != "enable" or p["action"] not in PERMIT:
            continue
        src_if = r.interfaces(p["srcintf"])
        dst_if = r.interfaces(p["dstintf"])
        if not (src_if is None or set(src_if) & wan):
            continue
        vips = _vip_targets(snap, p["dstaddr"])
        if not vips:
            if dst_if is not None and dst_if and set(dst_if) <= wan:
                continue  # WAN->WAN transit: not an inbound publication
            if src_if is None:
                # any->x without VIPs is an inbound publication only when it names public addresses
                dst = r.addresses(p["dstaddr"])
                if dst.is_full or public_size(dst.iv) == 0:
                    continue
        isdb_src = [v for f in ("internet-service-src-name", "internet-service-src-group",
                                "internet-service-src-custom", "internet-service-src-custom-group")
                    for v in p.get(f, [])] if p.get("internet-service-src") == "enable" else None
        kind, src_text = source_scope(snap, r, p["srcaddr"], p.get("srcaddr-negate") == "enable", isdb_src)
        if isdb_src is not None and p.get("internet-service-src-negate") == "enable":
            # "every source except these internet services" is an unrestricted source, not an ISDB allow list
            kind, src_text = "any", "Any except internet services: " + (", ".join(isdb_src) or "listed IDs")
        svc = r.services(p["service"])
        svc_text = ", ".join(p["service"]) or ("ISDB" if p.get("internet-service") == "enable" else "-")
        prot, risky, all_ports = protection(p), [], False

        targets: List[Tuple[str, str, str]] = []  # (external, internal, service)
        for vn in vips:
            v = snap["vips"][vn]
            ext_ip = v.get("extip") or "?"
            mapped = ", ".join(v.get("mappedip") or []) or "?"
            if v.get("portforward") == "enable" or v.get("type") not in ("static-nat", ""):
                proto = (v.get("protocol") or "tcp").lower()
                ext_r = _range(v.get("extport", "")) or (0, 65535)
                map_r = _range(v.get("mappedport", "")) or ext_r
                allowed = svc.allows_port(proto, *map_r) or svc.allows_port(proto, *ext_r)
                if not allowed:
                    continue
                ext_txt = f"{ext_ip}:{v.get('extport') or '*'}"
                int_txt = f"{mapped}:{v.get('mappedport') or v.get('extport') or '*'}"
                risky += _risky_in(svc, (proto, *map_r))
                targets.append((ext_txt, f"{int_txt} (VIP {vn})", f"{proto.upper()}/{v.get('mappedport') or v.get('extport')}"))
            else:
                if svc.is_all:
                    all_ports = True  # reported once as EXPOSED_ALL_PORTS, not as 36 risky services
                else:
                    risky += _risky_in(svc)
                targets.append((ext_ip, f"{mapped} (VIP {vn})", "ALL" if svc.is_all else svc_text))
        if not vips:
            if svc.is_all:
                all_ports = True
            else:
                risky += _risky_in(svc)
            targets.append((", ".join(p["dstaddr"]) + " (routed)", f"{', '.join(p['dstintf'])} (routed)",
                            "ALL" if svc.is_all else svc_text))
        if not targets:
            continue

        names = sorted({n for n, _ in risky})
        sev_hint = _worst([s for _, s in risky]) if risky else ("high" if all_ports else "info")
        for ext, internal, service in targets:
            rows.append({"kind": "Rule", "policyid": p["policyid"], "label": label(p), "source": src_text,
                         "source_kind": kind, "external": ext, "internal": internal, "service": service,
                         "risky": names, "protection": prot, "logging": p["logtraffic"], "hits": hit(p["policyid"]),
                         "severity": _scope_sev(sev_hint, kind) or "info"})

        if names:
            sev = _scope_sev(_worst([s for _, s in risky]), kind)
            if sev:
                findings.append(finding("EXPOSED_RISKY", policyid=p["policyid"], severity=sev,
                    detail=f"{label(p)}: {', '.join(names)} reachable from {src_text} via "
                           f"{'; '.join(t[1] for t in targets)}."))
        if all_ports:
            sev = _scope_sev("high", kind) or "low"
            findings.append(finding("EXPOSED_ALL_PORTS", policyid=p["policyid"], severity=sev,
                detail=f"{label(p)}: all ports of {'; '.join(t[1] for t in targets if t[2] == 'ALL')} from {src_text}."))
        if kind != "restricted" and not has_ips(p):
            findings.append(finding("EXPOSED_NO_IPS", policyid=p["policyid"], severity=_scope_sev("medium", kind),
                detail=f"{label(p)}: {svc_text} from {src_text}, protection: {prot}."))

    a_rows, a_findings = _admin_exposure(snap, r, wan)
    s_rows, s_findings = _sslvpn_exposure(snap, r, wan)
    return rows + a_rows + s_rows + _ipsec_rows(snap, wan), findings + a_findings + s_findings


def _local_in_block(snap: Dict[str, Any], r: Resolver, iface: str, proto: str, port: Tuple[int, int]) -> Optional[int]:
    """Policy id of an enabled local-in deny that drops this port from all sources on this interface.

    Only a deny that provably applies counts: always active, no negated field, every source, and a
    destination that is "all" or contains the interface's own address."""
    try:
        own_ip = int(ipaddress.IPv4Address(str(snap["interfaces"][iface]["ip"]).split()[0].split("/")[0]))
    except (KeyError, IndexError, ValueError):
        own_ip = 0  # unknown or dynamic address: only a deny for every destination counts
    for li in snap.get("local_in", []):
        if li["status"] != "enable" or li["action"] != "deny":
            continue
        if any(li.get(k) == "enable" for k in ("srcaddr-negate", "dstaddr-negate", "service-negate")):
            continue
        if li.get("schedule") not in (None, "", "always"):
            continue
        ifs = r.interfaces(li["intf"]) if li["intf"] else None
        if ifs is not None and iface not in ifs:
            continue
        if not r.addresses(li["srcaddr"] or ["all"]).is_full:
            continue
        dst = r.addresses(li.get("dstaddr") or ["all"])
        if not dst.is_full and not (own_ip and any(lo <= own_ip <= hi for lo, hi in dst.iv)):
            continue
        svc = r.services(li["service"] or ["ALL"])
        if svc.allows_port(proto, *port, loose=False):
            return li["policyid"]
    return None


def _admin_exposure(snap: Dict[str, Any], r: Resolver, wan: Set[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    rows, out = [], []
    g = snap.get("global", {})
    admins = snap.get("admins")
    open_admins = [a["name"] for a in (admins or {}).values() if not a["trusthosts"]]
    trust_note = ("admins unknown (token cannot read)" if admins is None else
                  f"no trusted hosts on: {', '.join(open_admins)}" if open_admins else
                  "all admins restricted by trusted hosts")
    for name in sorted(wan):
        i = snap["interfaces"].get(name)
        if not i:
            continue
        exposed_login, blocked_by = [], []
        for kw in i.get("allowaccess", []):
            if kw not in MGMT_PROTOCOLS:
                continue
            lbl, proto, port_ref = MGMT_PROTOCOLS[kw]
            port = (g.get(port_ref) or _PORT_DEFAULTS.get(port_ref, port_ref)) if not port_ref[0].isdigit() else port_ref
            rng = _range(port) or (0, 0)
            blk = _local_in_block(snap, r, name, proto, rng)
            if kw in _ADMIN_LOGIN:
                (blocked_by.append(blk) if blk else exposed_login.append(kw))
            rows.append({"kind": "Management", "policyid": None, "label": "", "source":
                         (f"blocked by local-in #{blk}" if blk else ("Any (internet)" if kw in _ADMIN_LOGIN or kw == "snmp" else "Any")),
                         "source_kind": "restricted" if blk else "any", "external": f"{name}:{port}",
                         "internal": "FortiGate", "service": f"{lbl} ({proto.upper()}/{port})", "risky": [],
                         "protection": trust_note if kw in _ADMIN_LOGIN else "-", "logging": "-", "hits": None,
                         "severity": "info" if blk else ("high" if kw in _ADMIN_LOGIN and (open_admins or admins is None)
                                                          else "medium" if kw in _ADMIN_LOGIN else "info")})
        if exposed_login or blocked_by:
            aa = i.get("allowaccess", [])
            keep = [x for x in aa if x not in _ADMIN_LOGIN]
            if exposed_login:
                sev = "high" if (open_admins or admins is None) else "medium"
                detail = (f"WAN interface {name} accepts {', '.join(sorted(exposed_login))}; {trust_note}.")
            else:
                sev = "low"
                detail = (f"WAN interface {name} has {', '.join(sorted(set(aa) & _ADMIN_LOGIN))} enabled, "
                          f"blocked by local-in policy #{blocked_by[0]}. Remove it from allowaccess so a later "
                          "local-in change cannot expose it.")
            out.append(finding("ADMIN_WAN", obj=name, severity=sev, detail=detail,
                cli=["config system interface", f"    edit {q(name)}", f"        set allowaccess {' '.join(keep) or 'ping'}",
                     "    next", "end"], cli_scope="global", cli_safe=False))
    return rows, out


def sslvpn_listening(snap: Dict[str, Any], r: Resolver, wan: Set[str]) -> List[str]:
    ssl = snap.get("sslvpn")
    if not ssl or ssl.get("status") == "disable" or not ssl.get("source_interface"):
        return []
    ifs = r.interfaces(ssl["source_interface"])
    if ifs is None:
        return sorted(wan) or ["any"]
    return sorted(set(ifs) & wan)


def _sslvpn_exposure(snap: Dict[str, Any], r: Resolver, wan: Set[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    on = sslvpn_listening(snap, r, wan)
    if not on:
        return [], []
    ssl = snap["sslvpn"]
    kind, src_text = source_scope(snap, r, ssl.get("source_address") or [],
                                  ssl.get("source_address_negate") == "enable")
    used = any("ssl.root" in p["srcintf"] and p["status"] == "enable" for p in snap["policies"])
    rows = [{"kind": "SSL-VPN", "policyid": None, "label": "", "source": src_text, "source_kind": kind,
             "external": f"{iface}:{ssl.get('port')}", "internal": "FortiGate SSL-VPN portal",
             "service": f"HTTPS/{ssl.get('port')}", "risky": [],
             "protection": f"min {ssl.get('ssl_min_proto')}" + ("" if used else "; no policy uses ssl.root"),
             "logging": "-", "hits": None, "severity": _scope_sev("medium", kind) or "info"} for iface in on]
    out = []
    sev = _scope_sev("medium", kind)
    if sev:
        extra = "" if used else " No enabled firewall policy uses ssl.root, so the portal may serve no purpose - consider disabling it."
        out.append(finding("SSLVPN_EXPOSED", obj="vpn ssl settings", severity=sev,
            detail=f"SSL-VPN listens on {', '.join(on)} port {ssl.get('port')} for {src_text}.{extra}"))
    return rows, out


def _ipsec_rows(snap: Dict[str, Any], wan: Set[str]) -> List[Dict[str, Any]]:
    rows = []
    for p1 in snap.get("ipsec_p1", {}).values():
        if p1.get("interface") not in wan:
            continue
        dialup = p1.get("type") == "dynamic"
        rows.append({"kind": "IPsec", "policyid": None, "label": p1["name"],
                     "source": "Any (dial-up)" if dialup else (p1.get("remote_gw") or "peer"),
                     "source_kind": "any" if dialup else "restricted", "external": f"{p1['interface']}:500/4500",
                     "internal": f"tunnel {p1['name']}", "service": "IKE UDP/500, 4500", "risky": [],
                     "protection": f"IKEv{p1.get('ike_version')}, {p1.get('mode')} mode, {p1.get('authmethod')}",
                     "logging": "-", "hits": None, "severity": "info"})
    return rows
