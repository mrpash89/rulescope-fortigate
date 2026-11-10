"""Object resolution and set-coverage math used for shadow/redundancy detection.

Principle: be conservative. Anything we cannot reason about exactly (FQDN, geo,
wildcard, dynamic, groups with exclusions, VIPs, ISDB) becomes an opaque token that
is only covered by an identical token - or, for plain IPv4 objects, by 0.0.0.0/0.
A "shadowed" finding therefore means "provably shadowed", never "maybe".
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

FULL = (0, 2**32 - 1)
PROTO_NUM = {"tcp": 6, "udp": 17, "sctp": 132, "udplite": 136}
_PORT_FIELDS = (("tcp", "tcp-portrange"), ("udp", "udp-portrange"),
                ("udplite", "udplite-portrange"), ("sctp", "sctp-portrange"))
_OPAQUE_ADDR_TYPES = {"fqdn", "geography", "wildcard", "wildcard-fqdn", "dynamic", "mac", "route-tag"}


def _merge(iv: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    out: List[List[int]] = []
    for lo, hi in sorted(iv):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [(a, b) for a, b in out]


def _covered(inner: List[Tuple[int, int]], outer_merged: List[Tuple[int, int]]) -> bool:
    for lo, hi in inner:
        if not any(a <= lo and hi <= b for a, b in outer_merged):
            return False
    return True


# ---------------------------------------------------------------- addresses

@dataclass
class AddrSet:
    iv: List[Tuple[int, int]] = field(default_factory=list)  # merged IPv4 intervals
    tokens: Set[str] = field(default_factory=set)            # opaque objects
    vips: Set[str] = field(default_factory=set)              # VIPs need an exact match

    @property
    def is_full(self) -> bool:
        return FULL in self.iv

    def covers(self, other: "AddrSet") -> bool:
        if other.vips and not other.vips <= self.vips:
            return False
        if self.is_full:
            return True
        if other.tokens and not other.tokens <= self.tokens:
            return False
        if not other.iv:
            return True
        if not self.iv or other.iv[0][0] < self.iv[0][0] or other.iv[-1][1] > self.iv[-1][1]:
            return False  # cheap bounding-box reject before the interval walk
        return _covered(other.iv, self.iv)


def _subnet_interval(s: str) -> Optional[Tuple[int, int]]:
    try:
        s = s.strip()
        if "/" in s:
            net = ipaddress.IPv4Network(s, strict=False)
        else:
            ip, mask = s.split()
            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return int(net.network_address), int(net.broadcast_address)
    except (ValueError, TypeError):
        return None


class Resolver:
    def __init__(self, snap: Dict):
        self.snap = snap
        self._addr_cache: Dict[str, AddrSet] = {}
        self._svc_cache: Dict[str, "SvcSet"] = {}
        self.vip_names = set(snap.get("vips", []))
        self.vipgrps = snap.get("vipgrps", {})
        self.ifmap: Dict[str, Set[str]] = {}
        for z, members in {**snap.get("sdwan_zones", {}), **snap.get("zones", {})}.items():
            self.ifmap[z] = set(members) or {f"zone:{z}"}

    # --- addresses
    def address(self, name: str, depth: int = 0) -> AddrSet:
        if name in self._addr_cache:
            return self._addr_cache[name]
        r = AddrSet()
        addrs, grps = self.snap["addresses"], self.snap["addrgrps"]
        if depth > 20:
            r.tokens.add(f"addr:{name}")
        elif name in addrs:
            a = addrs[name]
            t = a["type"]
            if t in ("ipmask", "interface-subnet"):
                iv = _subnet_interval(a["subnet"])
                r.iv = [iv] if iv else []
                if not iv:
                    r.tokens.add(f"addr:{name}")
            elif t == "iprange":
                try:
                    lo = int(ipaddress.IPv4Address(a["start-ip"]))
                    hi = int(ipaddress.IPv4Address(a["end-ip"]))
                    r.iv = [(min(lo, hi), max(lo, hi))]
                except ValueError:
                    r.tokens.add(f"addr:{name}")
            else:
                r.tokens.add(f"addr:{name}")
        elif name in grps:
            g = grps[name]
            if g.get("exclude") == "enable":
                r.tokens.add(f"addr:{name}")
            else:
                ivs: List[Tuple[int, int]] = []
                for m in g["member"]:
                    s = self.address(m, depth + 1)
                    ivs += s.iv
                    r.tokens |= s.tokens
                    r.vips |= s.vips
                r.iv = _merge(ivs)
        elif name in self.vip_names:
            r.vips.add(name)
        elif name in self.vipgrps:
            r.vips |= set(self.vipgrps[name]) or {name}
        elif name == "all":
            r.iv = [FULL]
        else:
            r.tokens.add(f"unknown:{name}")
        r.iv = _merge(r.iv)
        self._addr_cache[name] = r
        return r

    def addresses(self, names: List[str]) -> AddrSet:
        out = AddrSet()
        ivs: List[Tuple[int, int]] = []
        for n in names:
            s = self.address(n)
            ivs += s.iv
            out.tokens |= s.tokens
            out.vips |= s.vips
        out.iv = _merge(ivs)
        return out

    # --- services
    def service(self, name: str, depth: int = 0) -> "SvcSet":
        if name in self._svc_cache:
            return self._svc_cache[name]
        r = SvcSet()
        svcs, grps = self.snap["services"], self.snap["servicegrps"]
        if depth > 20:
            r.tokens.add(f"svc:{name}")
        elif name in svcs:
            s = svcs[name]
            proto = s["protocol"].upper()
            restricted = (s.get("iprange") not in ("", "0.0.0.0", "0.0.0.0-0.0.0.0")) or bool(s.get("fqdn"))
            if restricted:
                # Opaque for coverage (it only applies to some addresses), but the ports it opens are
                # kept so the exposure checks still see a risky service published through it.
                r.tokens.add(f"svc:{name}")
                if proto == "IP":
                    try:
                        r.loose_ip.add(int(s.get("protocol-number") or 0))
                    except ValueError:
                        pass
                elif "TCP" in proto or "UDP" in proto or "SCTP" in proto:
                    for p, fld in _PORT_FIELDS:
                        for rng in s.get(fld, []):
                            parsed = _parse_portrange(rng)
                            if parsed:
                                r.loose.setdefault(p, []).append((parsed[0], parsed[1]))
            elif proto == "IP":
                try:
                    r.ip.add(int(s.get("protocol-number") or 0))
                except ValueError:
                    r.tokens.add(f"svc:{name}")
            elif proto == "ICMP":
                t = s.get("icmptype")
                if s.get("icmpcode") not in (None, ""):
                    r.tokens.add(f"svc:{name}")  # limited to one ICMP code: only an identical service covers it
                else:
                    try:
                        r.icmp.add(int(t) if t not in (None, "") else None)
                    except ValueError:
                        r.tokens.add(f"svc:{name}")
            elif "TCP" in proto or "UDP" in proto or "SCTP" in proto:
                for p, fld in _PORT_FIELDS:
                    for rng in s.get(fld, []):
                        parsed = _parse_portrange(rng)
                        if parsed:
                            r.ports.setdefault(p, []).append(parsed)
                        else:
                            r.tokens.add(f"svc:{name}")
            else:  # ICMP6, proxy services etc.
                r.tokens.add(f"svc:{name}")
        elif name in grps:
            for m in grps[name]["member"]:
                r.merge(self.service(m, depth + 1))
        elif name == "ALL":
            r.ip.add(0)
        else:
            r.tokens.add(f"svc:{name}")
        self._svc_cache[name] = r
        return r

    def services(self, names: List[str]) -> "SvcSet":
        out = SvcSet()
        for n in names:
            out.merge(self.service(n))
        return out

    # --- interfaces
    def interfaces(self, names: List[str]) -> Optional[FrozenSet[str]]:
        """None means 'any'."""
        out: Set[str] = set()
        for n in names:
            if n == "any":
                return None
            out |= self.ifmap.get(n, {n})
        return frozenset(out)


def _parse_portrange(s: str) -> Optional[Tuple[int, int, int, int]]:
    try:
        dst, _, src = s.partition(":")
        dlo, _, dhi = dst.partition("-")
        dlo_i, dhi_i = int(dlo), int(dhi or dlo)
        if src:
            slo, _, shi = src.partition("-")
            slo_i, shi_i = int(slo), int(shi or slo)
        else:
            slo_i, shi_i = 0, 65535
        if slo_i <= 1 and shi_i == 65535:
            slo_i = 0
        return (min(dlo_i, dhi_i), max(dlo_i, dhi_i), slo_i, shi_i)
    except ValueError:
        return None


@dataclass
class SvcSet:
    ip: Set[int] = field(default_factory=set)                       # IP protocol numbers, 0 = ALL
    icmp: Set[Optional[int]] = field(default_factory=set)            # None = any ICMP type
    ports: Dict[str, List[Tuple[int, int, int, int]]] = field(default_factory=dict)
    tokens: Set[str] = field(default_factory=set)
    # ports and protocols of opaque services (limited to an address range or FQDN): used only by
    # allows_port, never by covers
    loose: Dict[str, List[Tuple[int, int]]] = field(default_factory=dict)
    loose_ip: Set[int] = field(default_factory=set)

    def merge(self, o: "SvcSet") -> None:
        self.ip |= o.ip
        self.icmp |= o.icmp
        self.tokens |= o.tokens
        self.loose_ip |= o.loose_ip
        for p, rs in o.ports.items():
            self.ports.setdefault(p, []).extend(rs)
        for p, lr in o.loose.items():
            self.loose.setdefault(p, []).extend(lr)

    @property
    def is_all(self) -> bool:
        return 0 in self.ip

    def allows_port(self, proto: str, lo: int, hi: int, loose: bool = True) -> bool:
        """True if any destination port in [lo, hi] of this protocol is permitted (source ports ignored).
        `loose` also counts services that only apply to some addresses; pass False when the answer must
        hold for every address (a deny rule that is relied on as a block)."""
        if self.is_all or PROTO_NUM.get(proto) in self.ip:
            return True
        if loose and (0 in self.loose_ip or PROTO_NUM.get(proto) in self.loose_ip):
            return True
        if loose and any(dlo <= hi and lo <= dhi for dlo, dhi in self.loose.get(proto, [])):
            return True
        return any(dlo <= hi and lo <= dhi for dlo, dhi, _, _ in self.ports.get(proto, []))

    def covers(self, o: "SvcSet") -> bool:
        if self.is_all:
            return True
        if o.is_all or not o.tokens <= self.tokens:
            return False
        if not o.ip <= self.ip:
            return False
        if o.icmp and 1 not in self.ip:
            if None not in self.icmp and not o.icmp <= self.icmp:
                return False
        for p, ranges in o.ports.items():
            if PROTO_NUM[p] in self.ip:
                continue
            mine = self.ports.get(p, [])
            for dlo, dhi, slo, shi in ranges:
                usable = _merge([(a, b) for a, b, c, d in mine if c <= slo and shi <= d])
                if not _covered([(dlo, dhi)], usable):
                    return False
        return True

    def describe_any(self) -> bool:
        return self.is_all
