"""Device-hardening, logging and inspection checks from the FortiGate best-practice baseline.

Sources: CIS FortiGate benchmark (7.0.x v1.4.0 numbering), Fortinet's FortiOS hardening guide and
administrator best practices, and the Canadian Centre for Cyber Security advisory AL25-005.
Every check reads only the snapshot. A setting the snapshot does not have (older snapshot, or an
API token without permission) is skipped, never assumed, and `evaluated()` reports which checks ran.
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Any, Dict, List, Optional, Set

from . import exposure
from .catalog import CHECKS, INTRODUCED_0_4, finding, label, q
from .model import PROFILE_FIELDS, version_tuple
from .resolve import Resolver

PERMIT = ("accept", "ipsec")
FACTORY_CERTS = {"", "Fortinet_Factory", "Fortinet_Factory_Backup", "self-sign", "Fortinet_SSL"}
_ISDB_BAD = re.compile(r"tor[-_.]|malicious|scanner|botnet", re.I)
_PROFILE_NEEDS = (("ips-sensor", "IPS"), ("av-profile", "antivirus"), ("dnsfilter-profile", "DNS filter"),
                  ("application-list", "application control"))
LICENSE_NAMES = {"forticare": "FortiCare support", "antivirus": "Antivirus", "ips": "IPS", "web_filtering": "Web filtering",
                 "appctrl": "Application control", "antispam": "Anti-spam", "industrial_db": "Industrial security",
                 "botnet_ip": "Botnet IP", "botnet_domain": "Botnet domain", "mobile_malware": "Mobile malware",
                 "blacklist_certificates": "Malicious certificates", "malicious_urls": "Malicious URLs",
                 "outbreak_prevention": "Outbreak prevention", "sdwan_network_monitor": "SD-WAN monitoring",
                 "fortiguard_ai_sandbox": "AI sandbox", "iot_detection": "IoT detection", "dlp": "DLP"}


def _settings(snap: Dict[str, Any], key: str) -> Optional[Any]:
    return (snap.get("settings") or {}).get(key)


def _int(v: Any, default: int) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _g(lines: List[str]) -> List[str]:
    return ["config system global"] + [f"    {ln}" for ln in lines] + ["end"]


# ---------------------------------------------------------------- system global and system settings

def check_system(snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    g = snap.get("global") or {}
    tls = g.get("admin-https-ssl-versions")
    if tls is not None:
        old = [v for v in tls.split() if v in ("sslv3", "tlsv1-0", "tlsv1-1")]
        if old:
            out.append(finding("ADMIN_WEAK_TLS", obj="system global", detail=f"admin-https-ssl-versions is {tls}.",
                               cli=_g(["set admin-https-ssl-versions tlsv1-2 tlsv1-3"]), cli_scope="global"))
    if "admin-lockout-duration" in g:  # absent in snapshots from rulescope 0.3 or earlier
        if g.get("ssl-static-key-ciphers") == "enable":
            out.append(finding("STATIC_KEY_CIPHERS", obj="system global", detail="ssl-static-key-ciphers is enable.",
                               cli=_g(["set ssl-static-key-ciphers disable"]), cli_scope="global"))
        th, du = _int(g.get("admin-lockout-threshold"), 3), _int(g.get("admin-lockout-duration"), 60)
        if th > 5 or du < 300:
            out.append(finding("ADMIN_LOCKOUT_WEAK", obj="system global",
                detail=f"Admins are locked out after {th} failed attempts for {du} seconds"
                       + (" (the default)." if (th, du) == (3, 60) else "."),
                cli=_g([f"set admin-lockout-threshold {min(th, 3)}", "set admin-lockout-duration 900"]), cli_scope="global"))
        mgmt = {kw for i in snap["interfaces"].values() for kw in i.get("allowaccess", [])}
        default_ports = [f"{name} admin on {port}" for kw, name, key, port in (("https", "HTTPS", "admin-sport", "443"),
                                                                                 ("ssh", "SSH", "admin-ssh-port", "22"))
                         if kw in mgmt and str(g.get(key)) == port]
        if default_ports:
            out.append(finding("ADMIN_DEFAULT_PORTS", obj="system global",
                detail=f"{' and '.join(default_ports)}, the default port{'s' if len(default_ports) > 1 else ''}.",
                cli=_g(["set admin-sport 8443", "set admin-ssh-port 2222"]), cli_scope="global", cli_safe=False))
        if g.get("pre-login-banner") == "disable":
            out.append(finding("NO_LOGIN_BANNER", obj="system global", detail="pre-login-banner is disable.",
                               cli=_g(["set pre-login-banner enable"]), cli_scope="global"))
        if g.get("gui-display-hostname") == "enable":
            out.append(finding("HOSTNAME_ON_LOGIN", obj="system global", detail="gui-display-hostname is enable.",
                               cli=_g(["set gui-display-hostname disable"]), cli_scope="global"))
        if g.get("private-data-encryption") == "disable":
            out.append(finding("NO_PRIVATE_DATA_ENCRYPTION", obj="system global",
                detail="private-data-encryption is disable. Enabling it prompts for a 32-digit hex key on the CLI; "
                       "store the key safely, because backups cannot be restored without it.",
                cli=_g(["set private-data-encryption enable"]), cli_scope="global", cli_safe=False))

    ai = _settings(snap, "auto_install")
    if ai:
        on = [k for k in ("auto-install-config", "auto-install-image") if ai.get(k) == "enable"]
        if on:
            out.append(finding("USB_AUTO_INSTALL", obj="system auto-install", detail=f"{' and '.join(on)} enabled.",
                cli=["config system auto-install", "    set auto-install-config disable",
                     "    set auto-install-image disable", "end"], cli_scope="global"))
    ntp = _settings(snap, "ntp")
    if ntp and ntp.get("ntpsync") == "disable":
        out.append(finding("NTP_DISABLED", obj="system ntp", detail="ntpsync is disable.",
                           cli=["config system ntp", "    set ntpsync enable", "end"], cli_scope="global"))
    pp = _settings(snap, "password_policy")
    if pp and (pp.get("status") == "disable" or "admin-password" not in (pp.get("apply-to") or "")):
        detail = ("Password policy is disabled." if pp.get("status") == "disable"
                  else f"Password policy applies to {pp.get('apply-to') or 'nothing'}, not admin passwords.")
        out.append(finding("NO_PASSWORD_POLICY", obj="system password-policy", detail=detail,
            cli=["config system password-policy", "    set status enable", "    set apply-to admin-password",
                 "    set minimum-length 12", "    set min-lower-case-letter 1", "    set min-upper-case-letter 1",
                 "    set min-number 1", "    set min-non-alphanumeric 1", "end"], cli_scope="global"))
    au = _settings(snap, "autoupdate")
    if au and au.get("status") == "disable":
        out.append(finding("FORTIGUARD_UPDATES_OFF", obj="system autoupdate schedule",
            detail="Scheduled FortiGuard updates are disabled.",
            cli=["config system autoupdate schedule", "    set status enable", "end"],
            cli_scope="global"))
    return out


# ---------------------------------------------------------------- accounts

def check_accounts(snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    admins = snap.get("admins")
    if admins is not None:
        for a in admins.values():
            if "two_factor" not in a or a.get("remote_auth") == "enable" or a.get("wildcard") == "enable":
                continue
            if a.get("two_factor") in ("disable", ""):
                out.append(finding("ADMIN_NO_MFA", obj=a["name"],
                    detail=f"Admin '{a['name']}' ({a.get('accprofile') or '?'}) signs in with a password only."))
        supers = sorted(a["name"] for a in admins.values() if a.get("accprofile") == "super_admin")
        if len(supers) > 3:
            out.append(finding("MANY_SUPER_ADMINS", obj="system admin",
                detail=f"{len(supers)} super_admin accounts: {', '.join(supers)}."))
    for u in (snap.get("api_users") or {}).values():
        if u.get("accprofile") == "super_admin":
            out.append(finding("APIUSER_SUPER_ADMIN", obj=u["name"],
                detail=f"API user '{u['name']}' uses the super_admin profile."))
    for name, srv in (_settings(snap, "ldap") or {}).items():
        if srv.get("secure") == "disable":
            out.append(finding("LDAP_INSECURE", obj=name,
                detail=f"LDAP server '{name}' is queried on port {srv.get('port') or 389} with secure disable.",
                cli=["config user ldap", f"    edit {q(name)}", "        set secure ldaps", "        set port 636",
                     '        set ca-cert "<CA certificate of the directory>"', "    next", "end"], cli_safe=False))
    return out


# ---------------------------------------------------------------- SNMP and HA

def check_snmp_ha(snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    agent, comms, users = _settings(snap, "snmp_agent"), _settings(snap, "snmp_communities"), _settings(snap, "snmp_users")
    if agent and agent.get("status") == "enable":
        ifs = sorted(n for n, i in snap["interfaces"].items() if "snmp" in i.get("allowaccess", []))
        reach = f"SNMP is allowed on {', '.join(ifs)}" if ifs else "no interface allows SNMP access"
        for c in comms or []:
            versions = [v for v in ("v1", "v2c") if c.get(v) == "enable"]
            if c.get("status") != "enable" or not versions:
                continue
            src = "any address" if c.get("any_host") else f"{c.get('hosts')} configured host{'s' if c.get('hosts') != 1 else ''}"
            out.append(finding("SNMP_V2C", obj=f"SNMP community {c.get('id')}",
                severity="medium" if c.get("any_host") and ifs else "low",
                detail=f"Community #{c.get('id')} answers SNMP {'/'.join(versions)} from {src}; {reach}.",
                cli=["config system snmp community", f"    edit {c.get('id')}", "        set status disable", "    next", "end"],
                cli_scope="global", cli_safe=False))
        for u in users or []:
            if u.get("status") == "enable" and u.get("security_level") != "auth-priv":
                out.append(finding("SNMP_V3_NOPRIV", obj=f"SNMP user {u.get('name')}",
                    detail=f"SNMPv3 user '{u.get('name')}' uses security-level {u.get('security_level')}."))
    ha = _settings(snap, "ha")
    if ha and ha.get("mode") not in ("standalone", "", None):
        if not ha.get("monitor"):
            out.append(finding("HA_NO_MONITOR", obj="system ha", detail=f"HA mode {ha['mode']} with no monitored interfaces.",
                cli=["config system ha", '    set monitor "<wan interface>" "<lan interface>"', "end"],
                cli_scope="global", cli_safe=False))
        if ha.get("ha-mgmt-status") != "enable":
            out.append(finding("HA_NO_MGMT", obj="system ha", detail="ha-mgmt-status is disable."))
    return out


# ---------------------------------------------------------------- logging

def check_logging(snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    ev = _settings(snap, "eventfilter")
    if ev and ev.get("event") == "disable":
        out.append(finding("EVENT_LOG_OFF", obj="log eventfilter", detail="event is disable in log eventfilter.",
                           cli=["config log eventfilter", "    set event enable", "end"]))
    targets = _settings(snap, "log_targets")
    if targets is not None:
        on = {t: v for t, v in targets.items() if v.get("status") == "enable"}
        complete = "fortianalyzer" in targets and "syslogd" in targets
        if not on and complete:
            out.append(finding("NO_CENTRAL_LOG", obj="log settings",
                detail="No FortiAnalyzer, FortiAnalyzer Cloud, FortiGuard cloud logging or syslog target is enabled."))
        for t, v in on.items():
            if t.startswith("fortianalyzer") and v.get("enc-algorithm") in ("low", "disable"):
                out.append(finding("LOG_UNENCRYPTED", obj=f"log {t} setting",
                    detail=f"{t} uses enc-algorithm {v.get('enc-algorithm')}.",
                    cli=[f"config log {t} setting", "    set enc-algorithm high", "end"], cli_scope="global", cli_safe=False))
            elif t.startswith("syslogd") and v.get("enc-algorithm") in ("disable", ""):
                out.append(finding("LOG_UNENCRYPTED", obj=f"log {t} setting", severity="info",
                    detail=f"{t} sends logs in clear text (mode {v.get('mode') or 'udp'})."))
    return out


# ---------------------------------------------------------------- security profiles on internet-bound rules

def _internet_bound(snap: Dict[str, Any], r: Resolver, wan: Set[str]) -> List[Dict[str, Any]]:
    out = []
    for p in snap["policies"]:
        if p["status"] != "enable" or p["action"] not in PERMIT:
            continue
        src_if, dst_if = r.interfaces(p["srcintf"]), r.interfaces(p["dstintf"])
        to_wan = dst_if is None or bool(set(dst_if) & wan)
        from_inside = src_if is None or not set(src_if) <= wan
        if to_wan and from_inside:
            out.append(p)
    return out


def effective_profiles(p: Dict[str, Any], groups: Optional[Dict[str, Dict[str, str]]]) -> Optional[Dict[str, str]]:
    """Profiles that really apply to a rule; None if the rule uses a profile group we could not read."""
    if p.get("utm-status") != "enable":
        return {}
    if p.get("profile-type") == "group" or (p.get("profile-group") and not any(p.get(f) for f, _ in _PROFILE_NEEDS)):
        g = (groups or {}).get(p.get("profile-group") or "")
        return None if g is None else {k: v for k, v in g.items() if v}
    return {f: p[f] for f in PROFILE_FIELDS if p.get(f)}


def check_profiles(snap: Dict[str, Any], r: Resolver, wan: Set[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not wan:
        return out
    prof = snap.get("profiles") or {}
    ips_used: Dict[str, List[int]] = {}
    dns_used: Dict[str, List[int]] = {}
    for p in _internet_bound(snap, r, wan):
        eff = effective_profiles(p, prof.get("groups"))
        if not eff:
            continue  # no profiles at all is NO_UTM_WAN; unknown profile group is skipped
        if eff.get("ips-sensor"):
            ips_used.setdefault(eff["ips-sensor"], []).append(p["policyid"])
        if eff.get("dnsfilter-profile"):
            dns_used.setdefault(eff["dnsfilter-profile"], []).append(p["policyid"])
        missing = [name for f, name in _PROFILE_NEEDS if not eff.get(f)]
        if missing:
            sets = [f'        set {f} "default"' for f, name in _PROFILE_NEEDS if name in missing]
            fnd = finding("PROFILE_GAPS", policyid=p["policyid"],
                detail=f"{label(p)} -> {','.join(p['dstintf'])}: no {', '.join(missing)}.",
                cli=["config firewall policy", f"    edit {p['policyid']}", "        set utm-status enable"] + sets
                + ["    next", "end"], cli_safe=False)
            fnd["missing"] = missing
            out.append(fnd)
    for sensor, pids in sorted(ips_used.items()):
        s = (prof.get("ips") or {}).get(sensor)
        if s and s.get("botnet") == "disable":
            out.append(finding("IPS_NO_BOTNET", obj=sensor,
                detail=f"IPS sensor '{sensor}' (used by {', '.join('#' + str(x) for x in pids[:6])}"
                       f"{' and more' if len(pids) > 6 else ''}) has scan-botnet-connections disable.",
                cli=["config ips sensor", f"    edit {q(sensor)}", "        set scan-botnet-connections block", "    next", "end"],
                cli_safe=False))
    for prof_name, pids in sorted(dns_used.items()):
        d = (prof.get("dnsfilter") or {}).get(prof_name)
        if d and d.get("block_botnet") == "disable":
            out.append(finding("DNS_NO_BOTNET", obj=prof_name,
                detail=f"DNS filter '{prof_name}' (used by {', '.join('#' + str(x) for x in pids[:6])}"
                       f"{' and more' if len(pids) > 6 else ''}) has block-botnet disable.",
                cli=["config dnsfilter profile", f"    edit {q(prof_name)}", "        set block-botnet enable", "    next", "end"],
                cli_safe=False))
    return out


def profile_usage(snap: Dict[str, Any], r: Resolver, wan: Set[str]) -> Dict[str, Any]:
    """Counts used by the best-practice evidence."""
    rules = _internet_bound(snap, r, wan) if wan else []
    groups = (snap.get("profiles") or {}).get("groups")
    effs = [effective_profiles(p, groups) for p in rules]
    return {"rules": len(rules), "with_ips": sum(1 for e in effs if e and e.get("ips-sensor")),
            "with_dns": sum(1 for e in effs if e and e.get("dnsfilter-profile")),
            "with_any": sum(1 for e in effs if e)}


# ---------------------------------------------------------------- rule base additions

def isdb_source_is_known_bad(p: Dict[str, Any]) -> bool:
    # Redaction removes names after preserving the classification used by this check.
    if "_redacted_isdb_bad_source" in p:
        return p["_redacted_isdb_bad_source"]
    names = [v for f in ("internet-service-src-name", "internet-service-src-group", "internet-service-src-custom",
                         "internet-service-src-custom-group") for v in p.get(f, [])]
    return any(_ISDB_BAD.search(n) for n in names) or bool(p.get("internet-service-src-id"))


def isdb_deny_rules(snap: Dict[str, Any], r: Resolver, wan: Set[str]) -> List[Dict[str, Any]]:
    out = []
    for p in snap["policies"]:
        if p["status"] != "enable" or p["action"] != "deny" or p.get("internet-service-src") != "enable":
            continue
        src_if = r.interfaces(p["srcintf"])
        if src_if is not None and not set(src_if) & wan:
            continue
        if isdb_source_is_known_bad(p):
            out.append(p)
    return out


def check_isdb(snap: Dict[str, Any], r: Resolver, wan: Set[str], exp_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    broad = sorted({x["policyid"] for x in exp_rows if x["kind"] == "Rule" and x["source_kind"] in ("any", "geo")})
    if not wan or not broad:
        return []
    order = {p["policyid"]: i for i, p in enumerate(snap["policies"])}
    first = min(order[pid] for pid in broad)
    denies = isdb_deny_rules(snap, r, wan)
    if any(order[p["policyid"]] < first for p in denies):
        return []
    shown = ", ".join(f"#{x}" for x in broad[:6]) + (" and more" if len(broad) > 6 else "")
    below = f" Deny rule #{denies[0]['policyid']} exists but sits below the first inbound rule." if denies else ""
    wan_if = sorted(wan)[0]
    return [finding("NO_ISDB_DENY", obj="firewall policy",
        detail=f"{len(broad)} rule{'s' if len(broad) != 1 else ''} publish services to the whole internet ({shown}) "
               f"with no deny rule above them for Tor, scanner or malicious-server sources.{below}",
        cli=["config firewall policy", "    edit 0", '        set name "deny-known-bad-sources"', f"        set srcintf {q(wan_if)}",
             '        set dstintf "any"', "        set internet-service-src enable",
             '        set internet-service-src-name "Tor-Exit.Node" "Tor-Relay.Node" "Malicious-Malicious.Server" "Scanner-Scanner"',
             '        set dstaddr "all"', "        set action deny", '        set schedule "always"', '        set service "ALL"',
             "        set logtraffic all", "    next", "end",
             f"(then move it above policy {snap['policies'][first]['policyid']}; ISDB names differ between FortiOS versions)"],
        cli_safe=False)]


def check_zones(snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for z, mode in sorted((_settings(snap, "zones") or {}).items()):
        if mode == "allow":
            members = snap.get("zones", {}).get(z, [])
            out.append(finding("ZONE_INTRAZONE_ALLOW", obj=z,
                detail=f"Zone {z} ({', '.join(members) or 'no interfaces'}) has intrazone allow.",
                cli=["config system zone", f"    edit {q(z)}", "        set intrazone deny", "    next", "end"], cli_safe=False))
    return out


# ---------------------------------------------------------------- VPN additions and subscriptions

def check_vpn_extra(snap: Dict[str, Any], r: Resolver, wan: Set[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    ssl = snap.get("sslvpn") or {}
    if not exposure.sslvpn_listening(snap, r, wan):
        return out
    if "servercert" in ssl and ssl.get("servercert") in FACTORY_CERTS:
        out.append(finding("SSLVPN_FACTORY_CERT", obj="vpn ssl settings",
            detail=f"servercert is {ssl.get('servercert') or 'the default'}."))
    portals = _settings(snap, "ssl_portals")
    vt = version_tuple(snap["device"].get("version"))
    used = sorted(p["policyid"] for p in snap["policies"] if "ssl.root" in p["srcintf"] and p["status"] == "enable")
    tunnel = sorted(n for n, p in (portals or {}).items() if p.get("tunnel") == "enable")
    if vt and vt < (7, 6, 3) and used and tunnel:
        out.append(finding("SSLVPN_TUNNEL_MODE", obj="vpn ssl settings",
            detail=f"Policies {', '.join('#' + str(x) for x in used[:6])} accept SSL-VPN users and portal"
                   f"{'s' if len(tunnel) > 1 else ''} {', '.join(tunnel)} offer tunnel mode."))
    return out


def check_licenses(snap: Dict[str, Any], now: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for svc, v in sorted((snap.get("licenses") or {}).items()):
        name = LICENSE_NAMES.get(svc, svc.replace("_", " ").capitalize())
        st, exp = str(v.get("status", "")).lower(), v.get("expires")
        when = _dt.datetime.fromtimestamp(exp, _dt.timezone.utc).strftime("%Y-%m-%d") if exp else None
        if "expired" in st:
            out.append(finding("LICENSE_EXPIRED", obj=name, detail=f"{name} expired" + (f" on {when}." if when else ".")))
        elif exp and st in ("licensed", "valid", "registered") and 0 <= exp - now <= 30 * 86400:
            out.append(finding("LICENSE_EXPIRED", obj=name, severity="low",
                               detail=f"{name} expires on {when} (in {(exp - now) // 86400} days)."))
    return out


# ---------------------------------------------------------------- what was evaluated

def evaluated(snap: Dict[str, Any], fw: Optional[Dict[str, Any]] = None) -> Set[str]:
    """Check ids whose inputs were present, so comparisons and the baseline never treat 'not read' as 'passed'."""
    g = snap.get("global") or {}
    s = snap.get("settings") or {}
    prof = snap.get("profiles") or {}
    ok = set(CHECKS) - INTRODUCED_0_4
    has = lambda k: s.get(k) is not None  # noqa: E731
    pairs = {
        "ADMIN_WEAK_TLS": g.get("admin-https-ssl-versions") is not None,
        "USB_AUTO_INSTALL": has("auto_install"), "NTP_DISABLED": has("ntp"),
        "NO_PASSWORD_POLICY": has("password_policy"), "FORTIGUARD_UPDATES_OFF": has("autoupdate"),
        "ADMIN_NO_MFA": any("two_factor" in a for a in (snap.get("admins") or {}).values()),
        "MANY_SUPER_ADMINS": snap.get("admins") is not None, "APIUSER_SUPER_ADMIN": snap.get("api_users") is not None,
        "SNMP_V2C": has("snmp_agent") and has("snmp_communities"), "SNMP_V3_NOPRIV": has("snmp_agent") and has("snmp_users"),
        "EVENT_LOG_OFF": has("eventfilter"), "NO_CENTRAL_LOG": has("log_targets"), "LOG_UNENCRYPTED": has("log_targets"),
        "PROFILE_GAPS": True, "IPS_NO_BOTNET": prof.get("ips") is not None, "DNS_NO_BOTNET": prof.get("dnsfilter") is not None,
        "NO_ISDB_DENY": True, "ZONE_INTRAZONE_ALLOW": has("zones"), "LDAP_INSECURE": has("ldap"),
        "HA_NO_MONITOR": has("ha"), "HA_NO_MGMT": has("ha"),
        "SSLVPN_FACTORY_CERT": "servercert" in (snap.get("sslvpn") or {"servercert": ""}),
        "SSLVPN_TUNNEL_MODE": has("ssl_portals"), "LICENSE_EXPIRED": snap.get("licenses") is not None,
    }
    for c in ("STATIC_KEY_CIPHERS", "ADMIN_LOCKOUT_WEAK", "ADMIN_DEFAULT_PORTS", "NO_LOGIN_BANNER", "HOSTNAME_ON_LOGIN",
              "NO_PRIVATE_DATA_ENCRYPTION"):
        pairs[c] = "admin-lockout-duration" in g
    if fw:
        known = fw["lifecycle"]["status"] != "unknown"
        for c in ("FIRMWARE_EOS", "FIRMWARE_EOES", "FIRMWARE_EOES_SOON"):
            pairs[c] = known
        for c in ("FIRMWARE_KEV", "FIRMWARE_CVE"):
            pairs[c] = bool(fw["advisories"]["checked"])
    ok |= {c for c, v in pairs.items() if v}
    return ok


def check_all(snap: Dict[str, Any], r: Resolver, wan: Set[str], exp_rows: List[Dict[str, Any]], now: int) -> List[Dict[str, Any]]:
    return (check_system(snap) + check_accounts(snap) + check_snmp_ha(snap) + check_logging(snap)
            + check_profiles(snap, r, wan) + check_isdb(snap, r, wan, exp_rows) + check_zones(snap)
            + check_vpn_extra(snap, r, wan) + check_licenses(snap, now))
