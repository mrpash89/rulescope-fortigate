"""Normalized snapshot model (schema 3).

Both input paths (a config backup file, or the live REST API) are converted into the
same plain-JSON snapshot, so the analysis, report and diff code never care where the
data came from. Snapshots deliberately never contain the raw config: backups carry
encrypted password hashes, PSKs and private keys.
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import fgtconf

SCHEMA = 3

POLICY_LIST_FIELDS = [
    "srcintf", "dstintf", "srcaddr", "dstaddr", "srcaddr6", "dstaddr6", "service",
    "users", "groups", "fsso-groups", "poolname",
    "internet-service-name", "internet-service-group", "internet-service-custom",
    "internet-service-custom-group", "internet-service-id",
    "internet-service-src-name", "internet-service-src-group", "internet-service-src-custom",
    "internet-service-src-custom-group", "internet-service-src-id",
]

# CLI defaults: backups omit values that equal the default, so these must be applied.
POLICY_DEFAULTS = {
    "name": "", "uuid": "", "comments": "",
    "action": "deny", "status": "enable", "schedule": "", "logtraffic": "utm",
    "nat": "disable", "srcaddr-negate": "disable", "dstaddr-negate": "disable",
    "service-negate": "disable", "internet-service": "disable", "internet-service-src": "disable",
    "utm-status": "disable", "inspection-mode": "flow", "ssl-ssh-profile": "",
    "av-profile": "", "webfilter-profile": "", "dnsfilter-profile": "", "ips-sensor": "",
    "application-list": "", "emailfilter-profile": "", "file-filter-profile": "",
    "profile-group": "", "profile-type": "single", "match-vip": "disable",
}

PROFILE_FIELDS = ["av-profile", "webfilter-profile", "dnsfilter-profile", "ips-sensor",
                  "application-list", "emailfilter-profile", "file-filter-profile", "profile-group"]


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def iso_epoch(iso: str) -> int:
    return int(_dt.datetime.fromisoformat(iso).timestamp())


# ---------------------------------------------------------------- value helpers

def _names(v: Any) -> List[str]:
    """API returns [{"name": x}] (or other key names); config returns [x, y]."""
    if v is None or v == "":
        return []
    if isinstance(v, str):
        return v.split()
    if isinstance(v, (int, float)):
        return [str(v)]
    out = []
    for item in v:
        if isinstance(item, dict):
            for k in ("name", "q_origin_key", "interface-name", "range", "id"):
                if k in item:
                    out.append(str(item[k]))
                    break
        else:
            out.append(str(item))
    return out


def _scalar(v: Any, default: str = "") -> str:
    if v is None or v == []:
        return default
    if isinstance(v, list):
        return " ".join(str(x) for x in v)
    return str(v)


_DATE_RE = re.compile(r"(\d{4})[/-](\d{1,2})[/-](\d{1,2})")
_TIME_RE = re.compile(r"(\d{1,2}):(\d{2})")


def sched_epoch(s: str) -> Optional[int]:
    """FortiOS one-time schedules look like '00:00 2024/12/31' (device local time; treated as UTC)."""
    if not s:
        return None
    if s.isdigit():
        n = int(s)
        return n // 1000 if n > 10**11 else n
    m = _DATE_RE.search(s)
    if not m:
        return None
    t = _TIME_RE.search(s)
    hh, mm = (int(t.group(1)), int(t.group(2))) if t else (0, 0)
    try:
        return int(_dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), hh, mm,
                                tzinfo=_dt.timezone.utc).timestamp())
    except ValueError:
        return None


# ---------------------------------------------------------------- object builders

def _policy(pid: Any, raw: Dict[str, Any]) -> Dict[str, Any]:
    p: Dict[str, Any] = {"policyid": int(pid)}
    for f in POLICY_LIST_FIELDS:
        p[f] = _names(raw.get(f))
    for f, d in POLICY_DEFAULTS.items():
        p[f] = _scalar(raw.get(f), d)
    return p


def _address(name: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": name,
        "type": _scalar(raw.get("type"), "ipmask"),
        "subnet": _scalar(raw.get("subnet"), "0.0.0.0 0.0.0.0"),
        "start-ip": _scalar(raw.get("start-ip"), "0.0.0.0"),
        "end-ip": _scalar(raw.get("end-ip"), "0.0.0.0"),
        "fqdn": _scalar(raw.get("fqdn")),
        "country": _scalar(raw.get("country")),
        "comment": _scalar(raw.get("comment")),
    }


def _group(name: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": name,
        "member": _names(raw.get("member")),
        "exclude": _scalar(raw.get("exclude"), "disable"),
        "exclude-member": _names(raw.get("exclude-member")),
        "comment": _scalar(raw.get("comment")),
    }


def _service(name: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    def ranges(k: str) -> List[str]:
        v = raw.get(k)
        return v.split() if isinstance(v, str) else [str(x) for x in (v or [])]

    return {
        "name": name,
        "protocol": _scalar(raw.get("protocol"), "TCP/UDP/SCTP"),
        "tcp-portrange": ranges("tcp-portrange"),
        "udp-portrange": ranges("udp-portrange"),
        "udplite-portrange": ranges("udplite-portrange"),
        "sctp-portrange": ranges("sctp-portrange"),
        "protocol-number": _scalar(raw.get("protocol-number"), "0"),
        "icmptype": _scalar(raw.get("icmptype")),
        "iprange": _scalar(raw.get("iprange"), "0.0.0.0"),
        "fqdn": _scalar(raw.get("fqdn")),
        "comment": _scalar(raw.get("comment")),
    }


def _vip(name: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": name,
        "type": _scalar(raw.get("type"), "static-nat"),
        "extip": _scalar(raw.get("extip")),
        "mappedip": _names(raw.get("mappedip")),
        "extintf": _scalar(raw.get("extintf"), "any"),
        "portforward": _scalar(raw.get("portforward"), "disable"),
        "protocol": _scalar(raw.get("protocol"), "tcp"),
        "extport": _scalar(raw.get("extport")),
        "mappedport": _scalar(raw.get("mappedport")),
        "comment": _scalar(raw.get("comment")),
    }


def _interface(name: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    aa = raw.get("allowaccess")
    return {
        "name": name,
        "vdom": _scalar(raw.get("vdom")),
        "role": _scalar(raw.get("role"), "undefined"),
        "type": _scalar(raw.get("type")),
        "mode": _scalar(raw.get("mode"), "static"),
        "ip": _scalar(raw.get("ip"), "0.0.0.0 0.0.0.0"),
        "alias": _scalar(raw.get("alias")),
        "allowaccess": aa.split() if isinstance(aa, str) else [str(x) for x in (aa or [])],
    }


def _trusthosts_admin(raw: Dict[str, Any]) -> List[str]:
    out = []
    for i in range(1, 11):
        v = _scalar(raw.get(f"trusthost{i}"))
        if v and v not in ("0.0.0.0 0.0.0.0", "0.0.0.0/0"):
            out.append(v)
    return out


def _sslvpn(raw: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    return {
        "status": _scalar(raw.get("status"), "enable"),
        "port": _scalar(raw.get("port"), "443"),
        "source_interface": _names(raw.get("source-interface")),
        "source_address": _names(raw.get("source-address")),
        "source_address_negate": _scalar(raw.get("source-address-negate"), "disable"),
        "ssl_min_proto": _scalar(raw.get("ssl-min-proto-ver"), "tls1-2"),
        "servercert": _scalar(raw.get("servercert"), "Fortinet_Factory"),
    }


def _phase1(name: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    dh = raw.get("dhgrp")
    return {
        "name": name,
        "interface": _scalar(raw.get("interface")),
        "type": _scalar(raw.get("type"), "static"),
        "ike_version": _scalar(raw.get("ike-version"), "1"),
        "mode": _scalar(raw.get("mode"), "main"),
        "authmethod": _scalar(raw.get("authmethod"), "psk"),
        "proposal": _names(raw.get("proposal")),
        "dhgrp": _names(dh) if dh not in (None, "", []) else None,
        "remote_gw": _scalar(raw.get("remote-gw")),
    }


def _phase2(name: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    dh = raw.get("dhgrp")
    return {
        "name": name,
        "phase1name": _scalar(raw.get("phase1name")),
        "proposal": _names(raw.get("proposal")),
        "pfs": _scalar(raw.get("pfs"), "enable"),
        "dhgrp": _names(dh) if dh not in (None, "", []) else None,
    }


def _local_in(pid: Any, raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "policyid": int(pid),
        "intf": _names(raw.get("intf")),
        "srcaddr": _names(raw.get("srcaddr")),
        "dstaddr": _names(raw.get("dstaddr")),
        "service": _names(raw.get("service")),
        "action": _scalar(raw.get("action"), "deny"),
        "status": _scalar(raw.get("status"), "enable"),
        "schedule": _scalar(raw.get("schedule"), "always"),
        "srcaddr-negate": _scalar(raw.get("srcaddr-negate"), "disable"),
    }


def _default_route(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    dst = _scalar(raw.get("dst"), "0.0.0.0 0.0.0.0")
    if dst not in ("0.0.0.0 0.0.0.0", "0.0.0.0/0", "0.0.0.0/0.0.0.0"):
        return None
    if _scalar(raw.get("status"), "enable") == "disable" or _scalar(raw.get("blackhole"), "disable") == "enable":
        return None
    return {
        "device": _scalar(raw.get("device")),
        "sdwan_zone": _names(raw.get("sdwan-zone")),
        "sdwan": "enable" in (_scalar(raw.get("sdwan")), _scalar(raw.get("virtual-wan-link"))),
    }


def _onetime(name: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    start, end = _scalar(raw.get("start")), _scalar(raw.get("end"))
    end_utc = raw.get("end-utc")
    return {"name": name, "start": start, "end": end,
            "end_epoch": sched_epoch(str(end_utc)) if end_utc else sched_epoch(end)}


def empty_snapshot(source: str) -> Dict[str, Any]:
    return {
        "schema": SCHEMA, "source": source, "collected_at": now_iso(),
        "device": {"hostname": "", "serial": "", "version": "", "build": "", "model": "",
                   "vdom": "root", "multi_vdom": False},
        "counter_since": None, "usage_source": None, "policies": [], "hits": None,
        "addresses": {}, "addrgrps": {}, "services": {}, "servicegrps": {},
        "vips": {}, "vipgrps": {}, "zones": {}, "sdwan_zones": {},
        "interfaces": {}, "admins": None, "api_users": None, "global": {},
        "schedules": {"onetime": {}, "groups": {}},
        "sslvpn": None, "ipsec_p1": {}, "ipsec_p2": {}, "local_in": [], "default_routes": [],
        "references": None, "references_source": None, "change_log": None, "notes": [],
        "wan_override": None, "wan_exclude": [],
        "settings": {}, "settings_source": None, "profiles": None, "accprofiles": None, "licenses": None,
    }


def upgrade(snap: Dict[str, Any]) -> Dict[str, Any]:
    """Bring older snapshots up to the current schema so diffs and re-analysis keep working.
    Settings that older versions did not collect stay unknown, so their checks are skipped."""
    for collection in ("policies", "local_in"):
        for index, policy in enumerate(snap.get(collection, [])):
            if type(policy.get("policyid")) is not int:
                raise ValueError(f"{collection}[{index}].policyid must be an integer")
    if snap.get("schema") == SCHEMA:
        return snap
    if snap.get("schema") not in (1, 2):
        raise ValueError(f"unsupported snapshot schema {snap.get('schema')}")
    base = empty_snapshot(snap.get("source", "config"))
    for k, v in base.items():
        snap.setdefault(k, v)
    if isinstance(snap.get("vips"), list):
        snap["vips"] = {n: _vip(n, {}) for n in snap["vips"]}
    for i in snap["interfaces"].values():
        i.setdefault("mode", "static")
    snap["schema"] = SCHEMA
    return snap


def version_tuple(v: Optional[str]) -> Optional[Tuple[int, int, int]]:
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", v or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None


_GLOBAL_DEFAULTS = {
    "strong-crypto": "enable", "admintimeout": "5", "admin-sport": "443", "admin-port": "80",
    "admin-ssh-port": "22", "admin-telnet-port": "23", "admin-https-redirect": "enable",
    "admin-lockout-threshold": "3", "admin-lockout-duration": "60", "ssl-static-key-ciphers": "enable",
    "pre-login-banner": "disable", "post-login-banner": "disable", "private-data-encryption": "disable",
    "gui-display-hostname": "", "timezone": "", "admin-server-cert": "",
}


def _global(g: Dict[str, Any], version: str = "") -> Dict[str, Any]:
    """System global settings the checks use. Backups omit defaults, so they are filled in here; a
    default that differs between FortiOS versions and is not known for this one stays None (unknown)."""
    out: Dict[str, Any] = {k: _scalar(g.get(k), d) for k, d in _GLOBAL_DEFAULTS.items()}
    tls = g.get("admin-https-ssl-versions")
    vt = version_tuple(version)
    out["admin-https-ssl-versions"] = (_scalar(tls) if tls not in (None, "", []) else
                                       "tlsv1-2 tlsv1-3" if vt and vt >= (7, 0, 0) else None)
    return out


# ---------------------------------------------------------------- hardening settings
# key: (scope, config path / API key, {field: default}); scope "global" or "vdom".
SETTING_SECTIONS: Dict[str, Tuple[str, str, Dict[str, str]]] = {
    "password_policy": ("global", "system password-policy", {
        "status": "disable", "apply-to": "admin-password", "minimum-length": "8", "min-lower-case-letter": "0",
        "min-upper-case-letter": "0", "min-non-alphanumeric": "0", "min-number": "0", "expire-status": "disable"}),
    "auto_install": ("global", "system auto-install", {"auto-install-config": "enable", "auto-install-image": "enable"}),
    "ntp": ("global", "system ntp", {"ntpsync": "enable", "type": "fortiguard"}),
    "dns": ("global", "system dns", {"primary": "", "secondary": "", "protocol": "cleartext"}),
    "ha": ("global", "system ha", {"mode": "standalone", "monitor": "", "ha-mgmt-status": "disable"}),
    "eventfilter": ("vdom", "log eventfilter", {"event": "enable", "system": "enable", "vpn": "enable", "user": "enable"}),
    "snmp_agent": ("global", "system snmp sysinfo", {"status": "disable"}),
    "autoupdate": ("global", "system autoupdate schedule", {"status": "enable", "frequency": ""}),
}
LOG_TARGETS = ["fortianalyzer", "fortianalyzer2", "fortianalyzer3", "fortianalyzer-cloud",
               "syslogd", "syslogd2", "syslogd3", "syslogd4", "fortiguard"]


# config path -> (REST endpoint, VDOM-scoped). Tables and singletons are both read through these.
API_SETTING_PATHS: Dict[str, Tuple[str, bool]] = {
    "system password-policy": ("cmdb/system/password-policy", False),
    "system auto-install": ("cmdb/system/auto-install", False),
    "system ntp": ("cmdb/system/ntp", False),
    "system dns": ("cmdb/system/dns", False),
    "system ha": ("cmdb/system/ha", False),
    "log eventfilter": ("cmdb/log/eventfilter", True),
    "system snmp sysinfo": ("cmdb/system.snmp/sysinfo", False),
    "system snmp community": ("cmdb/system.snmp/community", False),
    "system snmp user": ("cmdb/system.snmp/user", False),
    "system autoupdate schedule": ("cmdb/system.autoupdate/schedule", False),
    "system accprofile": ("cmdb/system/accprofile", False),
    "user ldap": ("cmdb/user/ldap", True),
    "vpn ssl web portal": ("cmdb/vpn.ssl.web/portal", True),
    "ips sensor": ("cmdb/ips/sensor", True),
    "dnsfilter profile": ("cmdb/dnsfilter/profile", True),
    "firewall profile-group": ("cmdb/firewall/profile-group", True),
    **{f"log {t} setting": (f"cmdb/log.{t}/setting", False) for t in LOG_TARGETS},
}


def _pick(raw: Dict[str, Any], fields: Dict[str, str]) -> Dict[str, str]:
    return {k: _scalar(raw.get(k), d) for k, d in fields.items()}


def _quoted_names(v: Any) -> List[str]:
    """Interface lists come as token lists (backup), name dicts or a quoted string (some API fields)."""
    if isinstance(v, str):
        return [a or b for a, b in re.findall(r'"([^"]+)"|(\S+)', v)]
    return _names(v)


def _settings_build(single: Callable[[str, str], Optional[Dict[str, Any]]],
                    table: Callable[[str, str], Optional[List[Dict[str, Any]]]]) -> Dict[str, Any]:
    """`single(scope, path)` returns a settings dict (None if unreadable); `table(scope, path)` a list of rows."""
    s: Dict[str, Any] = {}
    for key, (scope, path, fields) in SETTING_SECTIONS.items():
        raw = single(scope, path)
        s[key] = None if raw is None else _pick(raw, fields)
    ntp = single("global", "system ntp")
    if ntp is not None and s.get("ntp") is not None:
        s["ntp"]["servers"] = len(ntp.get("ntpserver") or [])
    ha = single("global", "system ha")
    if ha is not None and s.get("ha") is not None:
        s["ha"]["monitor"] = " ".join(_quoted_names(ha.get("monitor")))
        s["ha"]["mgmt_interfaces"] = [str(m.get("interface", "")) for m in (ha.get("ha-mgmt-interfaces") or [])
                                      if isinstance(m, dict) and m.get("interface")]

    targets: Dict[str, Dict[str, str]] = {}
    for t in LOG_TARGETS:
        raw = single("global", f"log {t} setting")
        if raw is not None:
            enc_default = "disable" if t.startswith("syslogd") else "high"
            targets[t] = _pick(raw, {"status": "disable", "enc-algorithm": enc_default, "mode": "udp" if
                                     t.startswith("syslogd") else "", "reliable": "disable"})
    s["log_targets"] = targets or None

    comm = table("global", "system snmp community")
    users = table("global", "system snmp user")
    s["snmp_communities"] = None if comm is None else [_community(c) for c in comm]
    s["snmp_users"] = None if users is None else [
        {"name": str(u.get("name", "")), "status": _scalar(u.get("status"), "enable"),
         "security_level": _scalar(u.get("security-level"), "no-auth-no-priv")} for u in users]

    zones = table("vdom", "system zone")
    s["zones"] = None if zones is None else {str(z.get("name")): _scalar(z.get("intrazone")) for z in zones}
    ldap = table("vdom", "user ldap")
    s["ldap"] = None if ldap is None else {
        str(x.get("name")): {"secure": _scalar(x.get("secure"), "disable"), "port": _scalar(x.get("port"), "389")}
        for x in ldap}
    portals = table("vdom", "vpn ssl web portal")
    s["ssl_portals"] = None if portals is None else {
        str(p.get("name")): {"tunnel": _scalar(p.get("tunnel-mode"), "disable"), "web": _scalar(p.get("web-mode"), "disable")}
        for p in portals}
    return s


def _community(c: Dict[str, Any]) -> Dict[str, Any]:
    """Never keep the community name: it is the SNMP v1/v2c password."""
    hosts = [h for h in (c.get("hosts") or []) if isinstance(h, dict)]
    ips = [_scalar(h.get("ip"), "0.0.0.0 0.0.0.0") for h in hosts]
    return {"id": str(c.get("id", "")), "status": _scalar(c.get("status"), "enable"),
            "v1": _scalar(c.get("query-v1-status"), "enable"), "v2c": _scalar(c.get("query-v2c-status"), "enable"),
            "hosts": len(hosts), "any_host": not ips or any(i in ("0.0.0.0 0.0.0.0", "0.0.0.0/0") for i in ips)}


def _profiles_build(table: Callable[[str, str], Optional[List[Dict[str, Any]]]]) -> Optional[Dict[str, Any]]:
    ips, dns, grp = table("vdom", "ips sensor"), table("vdom", "dnsfilter profile"), table("vdom", "firewall profile-group")
    if ips is None and dns is None and grp is None:
        return None
    return {
        "ips": None if ips is None else {str(x.get("name")): {"botnet": _scalar(x.get("scan-botnet-connections"), "disable")}
                                         for x in ips},
        "dnsfilter": None if dns is None else {str(x.get("name")): {"block_botnet": _scalar(x.get("block-botnet"), "disable")}
                                               for x in dns},
        "groups": None if grp is None else {str(x.get("name")): {f: _scalar(x.get(f)) for f in PROFILE_FIELDS
                                                                 if f != "profile-group"} for x in grp},
    }


_ACC_GROUPS = ("secfabgrp", "ftviewgrp", "authgrp", "sysgrp", "netgrp", "loggrp", "fwgrp", "vpngrp", "utmgrp",
               "wanoptgrp", "wifi")


def _accprofiles(rows: Optional[List[Dict[str, Any]]]) -> Optional[Dict[str, Dict[str, Any]]]:
    if rows is None:
        return None
    out = {}
    for r in rows:
        perms = [_scalar(r.get(g), "none") for g in _ACC_GROUPS]
        out[str(r.get("name"))] = {"scope": _scalar(r.get("scope"), "vdom"),
                                   "write": any(p in ("read-write", "custom") for p in perms)}
    return out


def _admin(name: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    return {"name": name, "accprofile": _scalar(raw.get("accprofile")), "trusthosts": _trusthosts_admin(raw),
            "two_factor": _scalar(raw.get("two-factor"), "disable"), "remote_auth": _scalar(raw.get("remote-auth"), "disable"),
            "wildcard": _scalar(raw.get("wildcard"), "disable")}


def _licenses(raw: Any) -> Optional[Dict[str, Dict[str, Any]]]:
    """monitor/license/status: {service: {status, expires, ...}}. Only status and expiry are kept."""
    res = (raw or {}).get("results") if isinstance(raw, dict) else None
    if not isinstance(res, dict):
        return None
    out = {}
    for svc, v in res.items():
        if not isinstance(v, dict) or "status" not in v:
            continue
        exp = v.get("expires")
        try:
            exp = int(exp) if exp else None
        except (TypeError, ValueError):
            exp = None
        out[svc] = {"status": str(v.get("status")), "expires": exp // 1000 if exp and exp > 10**11 else exp}
    return out


def _object_refs(snap: Dict[str, Any], root: fgtconf.Block) -> Dict[str, int]:
    """Reference counts for object names only - never keep arbitrary config values (secrets)."""
    counts = fgtconf.reference_counts(root)
    names = (set(snap["addresses"]) | set(snap["addrgrps"]) | set(snap["services"])
             | set(snap["servicegrps"]) | set(snap["vips"]) | set(snap["vipgrps"]))
    return {n: counts.get(n, 0) for n in sorted(names)}


# ---------------------------------------------------------------- from config file

def _settings(b: fgtconf.Block) -> Dict[str, Any]:
    return dict(b.settings)


def _flat(b: fgtconf.Block) -> Dict[str, Any]:
    """A config block as an API-shaped dict: values joined, nested tables as lists of rows."""
    d: Dict[str, Any] = {k: " ".join(v) for k, v in b.settings.items()}
    for path, sb in b.subs.items():
        d[path] = [dict(_flat(e), name=n, id=n) for n, e in sb.entries.items()] if sb.entries else _flat(sb)
    return d


def from_config(text: str, vdom: str = "root") -> Dict[str, Any]:
    root = fgtconf.parse(text)
    glob, vd = fgtconf.scopes(root, vdom)
    snap = empty_snapshot("config")
    hdr = fgtconf.header_info(text)
    gset = glob.sub("system global")
    snap["device"].update({
        "hostname": gset.get("hostname", "") or "",
        "version": hdr.get("version", ""), "build": hdr.get("build", ""),
        "model": hdr.get("model", ""), "vdom": vdom,
        "multi_vdom": fgtconf.is_multi_vdom(root),
    })
    snap["global"] = _global(_settings(gset), snap["device"]["version"])

    def single(scope: str, path: str) -> Dict[str, Any]:
        return _flat((glob if scope == "global" else vd).sub(path))

    def table(scope: str, path: str) -> List[Dict[str, Any]]:
        blk = (glob if scope == "global" else vd).sub(path)
        return [dict(_flat(e), name=n, id=n) for n, e in blk.entries.items()]

    snap["settings"] = _settings_build(single, table)
    snap["settings_source"] = "config"
    snap["profiles"] = _profiles_build(table)
    snap["accprofiles"] = _accprofiles(table("global", "system accprofile"))

    for pid, b in vd.sub("firewall policy").entries.items():
        snap["policies"].append(_policy(pid, _settings(b)))
    for n, b in vd.sub("firewall address").entries.items():
        snap["addresses"][n] = _address(n, _settings(b))
    for n, b in vd.sub("firewall addrgrp").entries.items():
        snap["addrgrps"][n] = _group(n, _settings(b))
    for n, b in vd.sub("firewall service custom").entries.items():
        snap["services"][n] = _service(n, _settings(b))
    for n, b in vd.sub("firewall service group").entries.items():
        snap["servicegrps"][n] = _group(n, _settings(b))
    for n, b in vd.sub("firewall vip").entries.items():
        snap["vips"][n] = _vip(n, _settings(b))
    for n, b in vd.sub("firewall vipgrp").entries.items():
        snap["vipgrps"][n] = _names(b.settings.get("member"))
    for n, b in vd.sub("system zone").entries.items():
        snap["zones"][n] = _names(b.settings.get("interface"))

    sdwan = vd.sub("system sdwan")
    if not sdwan.subs and not sdwan.settings:
        sdwan = vd.sub("system virtual-wan-link")
    zones: Dict[str, List[str]] = {z: [] for z in sdwan.sub("zone").entries}
    for _, m in sdwan.sub("members").entries.items():
        iface = m.get("interface")
        if iface:
            zones.setdefault(m.get("zone", "virtual-wan-link"), []).append(iface)
    snap["sdwan_zones"] = zones

    for n, b in vd.sub("firewall schedule onetime").entries.items():
        snap["schedules"]["onetime"][n] = _onetime(n, _settings(b))
    for n, b in vd.sub("firewall schedule group").entries.items():
        snap["schedules"]["groups"][n] = _names(b.settings.get("member"))

    ssl = vd.subs.get("vpn ssl settings")
    snap["sslvpn"] = _sslvpn(_settings(ssl)) if ssl is not None else None
    for n, b in vd.sub("vpn ipsec phase1-interface").entries.items():
        snap["ipsec_p1"][n] = _phase1(n, _settings(b))
    for n, b in vd.sub("vpn ipsec phase2-interface").entries.items():
        snap["ipsec_p2"][n] = _phase2(n, _settings(b))
    for pid, b in vd.sub("firewall local-in-policy").entries.items():
        snap["local_in"].append(_local_in(pid, _settings(b)))
    for _, b in vd.sub("router static").entries.items():
        r = _default_route(_settings(b))
        if r:
            snap["default_routes"].append(r)

    for n, b in glob.sub("system interface").entries.items():
        snap["interfaces"][n] = _interface(n, _settings(b))
    snap["admins"] = {n: _admin(n, _flat(b)) for n, b in glob.sub("system admin").entries.items()}
    snap["api_users"] = {}
    for n, b in glob.sub("system api-user").entries.items():
        th = [e.get("ipv4-trusthost", "") for e in b.sub("trusthost").entries.values()]
        th = [t for t in th if t and t not in ("0.0.0.0 0.0.0.0",)]
        snap["api_users"][n] = {"name": n, "accprofile": b.get("accprofile", ""), "trusthosts": th}

    snap["references"] = _object_refs(snap, root)
    snap["references_source"] = "config"
    return snap


# ---------------------------------------------------------------- from REST API

def from_api(data: Dict[str, Any], vdom: str = "root") -> Dict[str, Any]:
    """`data` is the dict produced by api.FortiGateAPI.collect_raw()."""
    snap = empty_snapshot("api")
    st = data.get("status") or {}
    res = st.get("results") or {}
    gl = (data.get("global") or {}).get("results") or {}
    snap["device"].update({
        "hostname": res.get("hostname") or gl.get("hostname", ""),
        "serial": st.get("serial", ""), "version": st.get("version", ""),
        "build": str(st.get("build", "")), "model": res.get("model_name") or res.get("model", ""),
        "vdom": vdom, "multi_vdom": gl.get("vdom-mode", "no-vdom") not in ("no-vdom", ""),
    })
    snap["global"] = _global(gl, snap["device"]["version"]) if data.get("global") is not None else {}
    cfg = data.get("cfg") or {}

    def single(scope: str, path: str) -> Optional[Dict[str, Any]]:
        r = (cfg.get(path) or {}).get("results") if isinstance(cfg.get(path), dict) else None
        if isinstance(r, list):  # some versions wrap singletons in a list
            r = r[0] if r and isinstance(r[0], dict) else None
        return r if isinstance(r, dict) else None

    def table(scope: str, path: str) -> Optional[List[Dict[str, Any]]]:
        src = data.get("zone") if path == "system zone" else cfg.get(path)
        r = src.get("results") if isinstance(src, dict) else None
        return [x for x in r if isinstance(x, dict)] if isinstance(r, list) else None

    if cfg:
        snap["settings"] = _settings_build(single, table)
        snap["settings_source"] = "api"
        snap["profiles"] = _profiles_build(table)
        snap["accprofiles"] = _accprofiles(table("global", "system accprofile"))
        missing = sorted(p for p in API_SETTING_PATHS if cfg.get(p) is None and not p.startswith("log fortianalyzer")
                         and not p.startswith("log syslogd"))
        if missing:
            snap["notes"].append("Token could not read: " + ", ".join(missing) +
                                 ". Best-practice items that depend on them are marked 'Not assessed'.")
    snap["licenses"] = _licenses(data.get("license"))

    def rows(key: str) -> List[Dict[str, Any]]:
        r = (data.get(key) or {}).get("results")
        return r if isinstance(r, list) else []

    meta_refs: Dict[str, int] = {}
    meta_total = meta_seen = 0

    def note_ref(row: Dict[str, Any]) -> None:
        nonlocal meta_total, meta_seen
        meta_total += 1
        if "q_ref" in row:
            meta_seen += 1
            try:
                meta_refs[row["name"]] = int(row["q_ref"])
            except (TypeError, ValueError):
                pass

    for p in rows("policy"):
        snap["policies"].append(_policy(p.get("policyid"), p))
    for a in rows("address"):
        snap["addresses"][a["name"]] = _address(a["name"], a)
        note_ref(a)
    for g in rows("addrgrp"):
        snap["addrgrps"][g["name"]] = _group(g["name"], g)
        note_ref(g)
    for s in rows("service_custom"):
        snap["services"][s["name"]] = _service(s["name"], s)
        note_ref(s)
    for g in rows("service_group"):
        snap["servicegrps"][g["name"]] = _group(g["name"], g)
        note_ref(g)
    for v in rows("vip"):
        snap["vips"][v["name"]] = _vip(v["name"], v)
        note_ref(v)
    for g in rows("vipgrp"):
        snap["vipgrps"][g["name"]] = _names(g.get("member"))
        note_ref(g)
    for z in rows("zone"):
        snap["zones"][z["name"]] = _names(z.get("interface"))
    sd = (data.get("sdwan") or {}).get("results") or {}
    if isinstance(sd, dict):
        zones: Dict[str, List[str]] = {z.get("name"): [] for z in sd.get("zone", []) if isinstance(z, dict)}
        for m in sd.get("members", []) or []:
            if m.get("interface"):
                zones.setdefault(m.get("zone") or "virtual-wan-link", []).append(m["interface"])
        snap["sdwan_zones"] = zones
    for i in rows("interface"):
        snap["interfaces"][i["name"]] = _interface(i["name"], i)
    for s in rows("sched_onetime"):
        snap["schedules"]["onetime"][s["name"]] = _onetime(s["name"], s)
    for g in rows("sched_group"):
        snap["schedules"]["groups"][g["name"]] = _names(g.get("member"))

    ssl = (data.get("vpn_ssl") or {}).get("results")
    snap["sslvpn"] = _sslvpn(ssl) if isinstance(ssl, dict) else None
    for p1 in rows("phase1"):
        snap["ipsec_p1"][p1["name"]] = _phase1(p1["name"], p1)
    for p2 in rows("phase2"):
        snap["ipsec_p2"][p2["name"]] = _phase2(p2["name"], p2)
    for li in rows("local_in"):
        snap["local_in"].append(_local_in(li.get("policyid"), li))
    for r in rows("router_static"):
        d = _default_route(r)
        if d:
            snap["default_routes"].append(d)

    if data.get("admin") is not None:
        snap["admins"] = {a["name"]: _admin(a["name"], a) for a in rows("admin")}
    if data.get("api_user") is not None:
        snap["api_users"] = {}
        for u in rows("api_user"):
            th = []
            for t in u.get("trusthost", []) or []:
                v = t.get("ipv4-trusthost", "") if isinstance(t, dict) else ""
                if v and v != "0.0.0.0 0.0.0.0":
                    th.append(v)
            snap["api_users"][u["name"]] = {"name": u["name"], "accprofile": _scalar(u.get("accprofile")),
                                            "trusthosts": th}

    hits: Dict[str, Dict[str, int]] = {}
    for h in rows("policy_stats"):
        pid = h.get("policyid")
        if pid is None:
            continue
        e = hits.setdefault(str(pid), {"hit_count": 0, "bytes": 0, "last_used": 0, "first_used": 0})
        e["hit_count"] += int(h.get("hit_count") or 0)
        e["bytes"] += int(h.get("bytes") or 0)
        e["last_used"] = max(e["last_used"], int(h.get("last_used") or 0))
        fu = int(h.get("first_used") or 0)
        if fu and (not e["first_used"] or fu < e["first_used"]):
            e["first_used"] = fu
    if data.get("policy_stats") is not None:
        snap["hits"] = hits
        snap["usage_source"] = "counters"

    ui = (data.get("webui_state") or {}).get("results") or {}
    reboot = ui.get("utc_last_reboot")
    if reboot:
        reboot = int(reboot)
        snap["counter_since"] = reboot // 1000 if reboot > 10**11 else reboot

    if meta_total and meta_seen == meta_total:
        snap["references"] = meta_refs
        snap["references_source"] = "q_ref"
    elif data.get("backup_text"):
        snap["references"] = _object_refs(snap, fgtconf.parse(data["backup_text"]))
        snap["references_source"] = "backup"
    else:
        snap["notes"].append("Object reference counts not available with this token: unused-object check only "
                             "counts references from policies and groups.")
    for k in ("admin", "api_user"):
        if data.get(k) is None:
            snap["notes"].append(f"Token cannot read system {k.replace('_', '-')}: admin access checks are partial.")
    if data.get("config_events") is not None:
        snap["change_log"] = data["config_events"]
    snap["notes"].extend(data.get("errors", []))
    return snap
