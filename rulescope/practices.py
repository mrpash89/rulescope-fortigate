"""FortiGate best-practice baseline: 37 practices from Fortinet, CIS and the Canadian Cyber Centre.

Each practice gets a status with the evidence behind it:
  pass     the configuration meets the practice
  partial  some of it is met (the evidence says what is missing)
  fail     the configuration contradicts it (linked findings explain where)
  manual   cannot be decided from a configuration; the evidence says what to verify
  na       not applicable to this device (for example no SSL-VPN, no HA)
  unknown  the data was not available (older snapshot, token without permission, advisories off)
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from . import exposure, hardening
from .model import version_tuple
from .resolve import Resolver


def model_version(snap: Dict[str, Any]) -> Optional[Tuple[int, int, int]]:
    return version_tuple(snap["device"].get("version"))

STATUS_LABEL = {"pass": "Pass", "partial": "Partial", "fail": "Fail", "manual": "Manual check",
                "na": "Not applicable", "unknown": "Not assessed"}
STATUS_ORDER = ["fail", "partial", "unknown", "manual", "pass", "na"]
DOMAINS = ["Management access", "System hardening", "Accounts", "Firewall policy", "Security profiles", "VPN",
           "Logging", "Firmware", "Availability"]
SOURCES = {
    "CIS": "CIS FortiGate benchmark (7.0.x v1.4.0; 7.4.x v1.0.1)",
    "Fortinet hardening": "Fortinet, FortiOS Best Practices: Hardening",
    "Fortinet tip": "Fortinet Community, Hardening best practices: secure network and devices (2025)",
    "Fortinet admin": "Fortinet Community, System administrator best practices for FortiGate",
    "Fortinet SSL-VPN": "Fortinet Community, Changes on SSL VPN modes starting from v7.6.3",
    "Cyber Centre": "Canadian Centre for Cyber Security, AL25-005 (April 2025)",
}


class Ctx:
    def __init__(self, snap: Dict[str, Any], result: Dict[str, Any], wan: Set[str]):
        self.snap, self.result, self.wan = snap, result, wan
        self.r = Resolver(snap)
        self.ev = set(result.get("evaluated") or [])
        self.by: Dict[str, List[Dict[str, Any]]] = {}
        for f in result["findings"]:
            self.by.setdefault(f["check"], []).append(f)
        self.g = snap.get("global") or {}
        self.s = snap.get("settings") or {}

    def f(self, *checks: str) -> List[Dict[str, Any]]:
        return [x for c in checks for x in self.by.get(c, [])]

    def sev(self, *checks: str, levels: Tuple[str, ...] = ("high", "medium")) -> List[Dict[str, Any]]:
        return [x for x in self.f(*checks) if x["severity"] in levels]

    def known(self, *checks: str) -> bool:
        return all(c in self.ev for c in checks)


R = Tuple[str, str]  # (status, evidence)


def _detail(fs: List[Dict[str, Any]], n: int = 2) -> str:
    uniq: List[str] = []
    for f in fs:
        d = f["detail"].rstrip(".")
        if d not in uniq:
            uniq.append(d)
    return "; ".join(uniq[:n]) + (f"; and {len(uniq) - n} more" if len(uniq) > n else "") + "."


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


# ---------------------------------------------------------------- management access

def p_mgmt_wan(c: Ctx) -> R:
    if not c.wan:
        return "unknown", "No internet-facing interface was identified."
    fs = c.f("ADMIN_WAN")
    if c.sev("ADMIN_WAN"):
        return "fail", _detail(c.sev("ADMIN_WAN"))
    if fs:
        return "partial", "Admin access is enabled on an internet-facing interface but blocked by a local-in policy: " + _detail(fs)
    return "pass", f"No HTTPS, HTTP, SSH or Telnet admin access on {', '.join(sorted(c.wan))}."


def p_mgmt_proto(c: Ctx) -> R:
    fs = c.f("ADMIN_TELNET", "ADMIN_HTTP")
    if fs:
        return "fail", _detail(fs, 3)
    return "pass", "No interface allows Telnet or HTTP management."


def p_trusthosts(c: Ctx) -> R:
    admins, api = c.snap.get("admins"), c.snap.get("api_users")
    if admins is None:
        return "unknown", "Admin accounts could not be read with this token."
    fs = c.f("ADMIN_NO_TRUSTHOST", "APIUSER_NO_TRUSTHOST")
    if fs:
        return "fail", _detail(fs, 3)
    return "pass", f"{_plural(len(admins), 'admin')} and {_plural(len(api or {}), 'API user')}, all restricted by trusted hosts."


def p_local_in(c: Ctx) -> R:
    if not c.wan:
        return "unknown", "No internet-facing interface was identified."
    rows = [x for x in c.result.get("exposure", []) if x["kind"] == "Management"
            and x["service"].split(" (")[0] in ("HTTPS admin", "HTTP admin", "SSH admin", "Telnet admin")]
    n_li = len([x for x in c.snap.get("local_in", []) if x.get("status") == "enable"])
    if not rows:
        return "pass", f"No admin service listens on internet-facing interfaces ({_plural(n_li, 'local-in policy')} configured)."
    open_rows = [x for x in rows if not str(x["source"]).startswith("blocked")]
    if not open_rows:
        return "pass", "Every admin service on internet-facing interfaces is dropped by a local-in policy."
    if not c.f("ADMIN_NO_TRUSTHOST") and c.snap.get("admins") is not None:
        return "partial", (f"{', '.join(sorted({x['external'] for x in open_rows}))} reachable; only trusted hosts restrict "
                           "who can log in, and the login page itself stays exposed to exploits.")
    return "fail", f"{', '.join(sorted({x['external'] for x in open_rows}))} reachable from the internet without a local-in restriction."


def p_ports(c: Ctx) -> R:
    if not c.known("ADMIN_DEFAULT_PORTS"):
        return "unknown", "Admin port settings were not read."
    if c.f("ADMIN_DEFAULT_PORTS"):
        return "fail", _detail(c.f("ADMIN_DEFAULT_PORTS"))
    return "pass", f"HTTPS admin on {c.g.get('admin-sport')}, SSH admin on {c.g.get('admin-ssh-port')} (or not enabled)."


def p_admin_tls(c: Ctx) -> R:
    if not c.known("ADMIN_WEAK_TLS"):
        return "unknown", "admin-https-ssl-versions is not set and its default for this FortiOS version is not verified."
    if c.f("ADMIN_WEAK_TLS"):
        return "fail", _detail(c.f("ADMIN_WEAK_TLS"))
    return "pass", f"admin-https-ssl-versions: {c.g.get('admin-https-ssl-versions')}."


def p_timeout(c: Ctx) -> R:
    if not c.g:
        return "unknown", "System global settings were not read."
    t = int(str(c.g.get("admintimeout", "5")) or 5)
    if t <= 5:
        return "pass", f"admintimeout is {t} minutes."
    if t <= 15:
        return "partial", f"admintimeout is {t} minutes; Fortinet recommends 5."
    return "fail", f"admintimeout is {t} minutes."


def p_banner(c: Ctx) -> R:
    if not c.known("NO_LOGIN_BANNER"):
        return "unknown", "Banner settings were not read."
    pre, post = c.g.get("pre-login-banner") == "enable", c.g.get("post-login-banner") == "enable"
    hidden = c.g.get("gui-display-hostname") != "enable"
    ev = (f"Pre-login banner {'on' if pre else 'off'}, post-login banner {'on' if post else 'off'}, "
          f"hostname {'hidden' if hidden else 'shown'} on the login page.")
    return ("pass" if pre and hidden else "partial" if pre or hidden else "fail"), ev


# ---------------------------------------------------------------- system hardening

def p_crypto(c: Ctx) -> R:
    if not c.g:
        return "unknown", "System global settings were not read."
    if c.f("WEAK_CRYPTO"):
        return "fail", "strong-crypto is disable" + ("; static-key ciphers also allowed." if c.f("STATIC_KEY_CIPHERS") else ".")
    if not c.known("STATIC_KEY_CIPHERS"):
        return "unknown", "strong-crypto is on; the static-key cipher setting was not read."
    if c.f("STATIC_KEY_CIPHERS"):
        return "partial", "strong-crypto is on, but ssl-static-key-ciphers is enable."
    return "pass", "strong-crypto on, static-key TLS ciphers off."


def _simple(check: str, missing: str, ok: str) -> Callable[[Ctx], R]:
    def ev(c: Ctx) -> R:
        if not c.known(check):
            return "unknown", missing
        fs = c.f(check)
        return ("fail", _detail(fs)) if fs else ("pass", ok)
    return ev


def p_pde(c: Ctx) -> R:
    if not c.known("NO_PRIVATE_DATA_ENCRYPTION"):
        return "unknown", "private-data-encryption was not read."
    if c.f("NO_PRIVATE_DATA_ENCRYPTION"):
        return "fail", "private-data-encryption is disable, so backups protect secrets with the built-in key only."
    return "pass", "private-data-encryption is enable. Confirm backups are also stored encrypted (manual)."


def p_time(c: Ctx) -> R:
    ntp, dns = c.s.get("ntp"), c.s.get("dns")
    if ntp is None:
        return "unknown", "NTP settings were not read."
    if c.f("NTP_DISABLED"):
        return "fail", "NTP synchronization is disabled."
    tz = c.g.get("timezone") or "default"
    servers = (f"{ntp.get('servers')} custom server(s)" if ntp.get("type") == "custom" else "FortiGuard NTP")
    dns_txt = (f"DNS {dns.get('primary') or 'FortiGuard default'}" + (f", {dns['secondary']}" if dns and dns.get("secondary") else "")
               + (f" over {dns.get('protocol')}" if dns and dns.get("protocol") not in ("", "cleartext") else "")) if dns else "DNS not read"
    return "pass", f"NTP on ({servers}); timezone {tz} (confirm it matches the site); {dns_txt}."


def p_snmp(c: Ctx) -> R:
    agent, comms = c.s.get("snmp_agent"), c.s.get("snmp_communities")
    if agent is None or comms is None:
        return "unknown", "SNMP settings were not read."
    if agent.get("status") != "enable":
        return "pass", "SNMP agent is disabled."
    if c.f("SNMP_V2C"):
        return "fail", _detail(c.f("SNMP_V2C"))
    if c.f("SNMP_V3_NOPRIV"):
        return "partial", _detail(c.f("SNMP_V3_NOPRIV"))
    users = c.s.get("snmp_users") or []
    return "pass", f"No v1/v2c community answers queries; {_plural(len(users), 'SNMPv3 user')} with auth-priv."


# ---------------------------------------------------------------- accounts

def p_default_admin(c: Ctx) -> R:
    if c.snap.get("admins") is None:
        return "unknown", "Admin accounts could not be read with this token."
    if c.f("DEFAULT_ADMIN"):
        return "fail", "The account 'admin' exists. Its password cannot be checked from the configuration."
    return "pass", "No account named 'admin'."


def p_lockout(c: Ctx) -> R:
    if not c.known("ADMIN_LOCKOUT_WEAK"):
        return "unknown", "Lockout settings were not read."
    th, du = c.g.get("admin-lockout-threshold"), c.g.get("admin-lockout-duration")
    if c.f("ADMIN_LOCKOUT_WEAK"):
        return "fail", f"Threshold {th} attempts, lockout {du} seconds; CIS asks for 3 and 900."
    return "pass", f"Threshold {th} attempts, lockout {du} seconds."


def p_password(c: Ctx) -> R:
    pp = c.s.get("password_policy")
    if pp is None:
        return "unknown", "The password policy was not read."
    if c.f("NO_PASSWORD_POLICY"):
        return "fail", _detail(c.f("NO_PASSWORD_POLICY"))
    return "pass", (f"Enabled for {pp.get('apply-to')}: minimum length {pp.get('minimum-length')}, "
                    f"upper {pp.get('min-upper-case-letter')}, lower {pp.get('min-lower-case-letter')}, "
                    f"digits {pp.get('min-number')}, symbols {pp.get('min-non-alphanumeric')}.")


def p_mfa(c: Ctx) -> R:
    admins = c.snap.get("admins")
    if admins is None or not c.known("ADMIN_NO_MFA"):
        return "unknown", "Admin two-factor settings were not read."
    if c.f("ADMIN_NO_MFA"):
        names = [f["object"] for f in c.f("ADMIN_NO_MFA")]
        return "fail", f"{_plural(len(names), 'local admin')} without two-factor: {', '.join(names[:6])}."
    remote = [a["name"] for a in admins.values() if a.get("remote_auth") == "enable" or a.get("wildcard") == "enable"]
    if remote:
        return "partial", (f"Local admins use two-factor; {_plural(len(remote), 'remote admin')} ({', '.join(remote[:4])}) "
                           "depend on the RADIUS/LDAP/SAML server for MFA. Verify it there.")
    return "pass", f"All {_plural(len(admins), 'admin')} use two-factor authentication."


def p_least(c: Ctx) -> R:
    admins = c.snap.get("admins")
    if admins is None:
        return "unknown", "Admin accounts could not be read with this token."
    if c.f("APIUSER_SUPER_ADMIN"):
        return "fail", _detail(c.f("APIUSER_SUPER_ADMIN"))
    supers = [a["name"] for a in admins.values() if a.get("accprofile") == "super_admin"]
    if c.f("MANY_SUPER_ADMINS"):
        return "partial", _detail(c.f("MANY_SUPER_ADMINS"))
    return "manual", (f"{_plural(len(admins), 'admin')}, {len(supers)} with super_admin. "
                      "Confirm each account belongs to one person and shared logins are not used.")


# ---------------------------------------------------------------- firewall policy

def p_breadth(c: Ctx) -> R:
    fs = c.f("ANY_ANY", "OUTBOUND_UNRESTRICTED", "SERVICE_ALL", "EXPOSED_ALL_PORTS")
    if fs:
        rules = sorted({f["policyid"] for f in fs if f["policyid"] is not None})
        return "fail", (f"{_plural(len(rules), 'accept rule')} allow all services or all addresses: "
                        f"{', '.join('#' + str(x) for x in rules[:8])}{' and more' if len(rules) > 8 else ''}.")
    if not c.result.get("policy_coverage_complete"):
        return "unknown", "Policy matching criteria were incomplete; broad-match checks could not be fully assessed."
    return "pass", "No accept rule uses service ALL with unrestricted addresses."


def p_unused(c: Ctx) -> R:
    hard = c.f("SHADOW_DEAD", "REDUNDANT", "EXPIRED_SCHEDULE")
    usage = c.f("UNUSED")
    soft = c.f("STALE", "DISABLED")
    n = len({f["policyid"] for f in hard + usage})
    if hard or usage:
        return "fail", (f"{_plural(n, 'rule')} can be removed (unused, redundant, shadowed or expired)"
                        + ("" if c.snap.get("hits") is not None else "; usage data was not available, so zero-hit rules are not counted") + ".")
    if c.snap.get("hits") is None:
        return "unknown", "No usage data: zero-hit rules could not be identified (use the API or --usage)."
    if soft:
        return "partial", f"{_plural(len(soft), 'rule')} stale or disabled."
    if not c.result.get("policy_coverage_complete"):
        return "unknown", "Recent usage is available, but redundancy and shadow coverage could not be fully assessed."
    return "pass", "Every enabled rule has recent hits and none is redundant or shadowed."


def p_logging_rules(c: Ctx) -> R:
    acc = [p for p in c.snap["policies"] if p["status"] == "enable" and p["action"] in ("accept", "ipsec")]
    if c.f("NO_LOG"):
        return "fail", f"{_plural(len(c.f('NO_LOG')), 'accept rule')} with logging disabled."
    utm = [p for p in acc if p.get("logtraffic") == "utm"]
    if utm:
        return "partial", f"{_plural(len(utm), 'accept rule')} log security events only (logtraffic utm); CIS asks for all sessions."
    return "pass", f"All {_plural(len(acc), 'accept rule')} log all sessions."


def p_isdb(c: Ctx) -> R:
    if c.f("NO_ISDB_DENY"):
        return "fail", _detail(c.f("NO_ISDB_DENY"))
    denies = hardening.isdb_deny_rules(c.snap, c.r, c.wan) if c.wan else []
    if denies:
        return "pass", f"Deny rule{'s' if len(denies) > 1 else ''} {', '.join('#' + str(p['policyid']) for p in denies[:4])} drop known-bad sources."
    return "na", "Nothing is published to the whole internet, so the implicit deny already covers inbound traffic."


def p_intrazone(c: Ctx) -> R:
    zones = c.s.get("zones")
    if zones is None:
        return "unknown", "Zone settings were not read."
    if not zones:
        return "na", "No zones are configured."
    if c.f("ZONE_INTRAZONE_ALLOW"):
        return "fail", _detail(c.f("ZONE_INTRAZONE_ALLOW"))
    return "pass", f"{_plural(len(zones), 'zone')}, none with intrazone allow."


# ---------------------------------------------------------------- security profiles

def p_ips(c: Ctx) -> R:
    if not c.wan:
        return "unknown", "No internet-facing interface was identified."
    no_ips = c.f("EXPOSED_NO_IPS") + c.f("NO_UTM_WAN") + [f for f in c.f("PROFILE_GAPS") if "IPS" in f.get("missing", [])]
    u = hardening.profile_usage(c.snap, c.r, c.wan)
    if no_ips:
        rules = sorted({f["policyid"] for f in no_ips if f["policyid"] is not None})
        return "fail", (f"{_plural(len(rules), 'internet-facing rule')} without IPS: {', '.join('#' + str(x) for x in rules[:8])}"
                        f"{' and more' if len(rules) > 8 else ''}.")
    return "pass", f"IPS on {u['with_ips']} of {_plural(u['rules'], 'internet-bound rule')} and on every inbound rule."


def p_profiles(c: Ctx) -> R:
    if not c.wan:
        return "unknown", "No internet-facing interface was identified."
    if c.f("NO_UTM_WAN"):
        return "fail", f"{_plural(len(c.f('NO_UTM_WAN')), 'internet-bound rule')} with no security profile at all."
    gaps = c.f("PROFILE_GAPS")
    if gaps:
        return "partial", _detail(gaps, 3)
    u = hardening.profile_usage(c.snap, c.r, c.wan)
    return "pass", f"All {_plural(u['rules'], 'internet-bound rule')} carry IPS, antivirus, DNS filter and application control."


def p_botnet(c: Ctx) -> R:
    if not c.wan:
        return "unknown", "No internet-facing interface was identified."
    if not (c.known("IPS_NO_BOTNET") or c.known("DNS_NO_BOTNET")):
        return "unknown", "IPS sensors and DNS filter profiles were not read."
    u = hardening.profile_usage(c.snap, c.r, c.wan)
    ips, dns = c.f("IPS_NO_BOTNET"), c.f("DNS_NO_BOTNET")
    gaps = []
    if ips or not u["with_ips"]:
        gaps.append("IPS botnet blocking" + ("" if u["with_ips"] else " (no IPS sensor on internet-bound rules)"))
    if dns or not u["with_dns"]:
        gaps.append("DNS filter C&C blocking" + ("" if u["with_dns"] else " (no DNS filter on internet-bound rules)"))
    extra = (" " + _detail(ips + dns)) if ips or dns else ""
    if len(gaps) == 2:
        return "fail", f"Missing {gaps[0]} and {gaps[1]}.{extra}"
    if gaps:
        return "partial", f"Missing {gaps[0]}.{extra}"
    return "pass", "IPS sensors block botnet connections and DNS filters block C&C domains on internet-bound rules."


# ---------------------------------------------------------------- VPN

def _ssl_on(c: Ctx) -> bool:
    return bool(exposure.sslvpn_listening(c.snap, c.r, c.wan))


def p_ssl_exposed(c: Ctx) -> R:
    if not _ssl_on(c):
        return "pass", "SSL-VPN is disabled or does not listen on internet-facing interfaces."
    if c.sev("SSLVPN_EXPOSED"):
        return "fail", _detail(c.f("SSLVPN_EXPOSED"))
    if c.f("SSLVPN_EXPOSED"):
        return "partial", _detail(c.f("SSLVPN_EXPOSED"))
    return "pass", "SSL-VPN accepts connections only from specific source addresses."


def p_ssl_tls(c: Ctx) -> R:
    if not _ssl_on(c):
        return "na", "SSL-VPN is not in use."
    if c.f("SSLVPN_WEAK_TLS"):
        return "fail", _detail(c.f("SSLVPN_WEAK_TLS"))
    return "pass", f"ssl-min-proto-ver is {(c.snap.get('sslvpn') or {}).get('ssl_min_proto')}."


def p_ssl_cert(c: Ctx) -> R:
    if not _ssl_on(c):
        return "na", "SSL-VPN is not in use."
    if not c.known("SSLVPN_FACTORY_CERT"):
        return "unknown", "The SSL-VPN certificate setting was not read."
    if c.f("SSLVPN_FACTORY_CERT"):
        return "fail", _detail(c.f("SSLVPN_FACTORY_CERT"))
    return "pass", f"Portal certificate: {(c.snap.get('sslvpn') or {}).get('servercert')}."


def p_ssl_tunnel(c: Ctx) -> R:
    if not _ssl_on(c):
        return "pass", "SSL-VPN is not in use."
    if c.f("SSLVPN_TUNNEL_MODE"):
        return "fail", _detail(c.f("SSLVPN_TUNNEL_MODE"))
    vt = model_version(c.snap)
    if vt and vt >= (7, 6, 3):
        return "pass", "FortiOS 7.6.3 and later no longer offer SSL-VPN tunnel mode."
    if not c.known("SSLVPN_TUNNEL_MODE"):
        return "unknown", "SSL-VPN portal settings were not read."
    if not any("ssl.root" in p["srcintf"] and p["status"] == "enable" for p in c.snap["policies"]):
        return "pass", "No firewall policy accepts SSL-VPN users, so no one depends on tunnel mode (consider disabling the portal)."
    return "pass", "SSL-VPN users are served without tunnel mode."


def p_ipsec(c: Ctx) -> R:
    p1 = c.snap.get("ipsec_p1") or {}
    if not p1:
        return "na", "No IPsec tunnels are configured."
    if c.sev("VPN_WEAK_CRYPTO") or c.f("VPN_AGGRESSIVE_PSK"):
        return "fail", _detail(c.sev("VPN_WEAK_CRYPTO") + c.f("VPN_AGGRESSIVE_PSK"))
    psk = [n for n, x in p1.items() if x.get("authmethod") == "psk"]
    weak = c.f("VPN_WEAK_CRYPTO", "VPN_NO_PFS")
    if weak or psk:
        parts = ([_detail(weak)] if weak else []) + ([f"{len(psk)} of {_plural(len(p1), 'tunnel')} authenticate with a pre-shared key."] if psk else [])
        return "partial", " ".join(parts)
    return "pass", f"{_plural(len(p1), 'tunnel')} with strong proposals and certificate authentication."


# ---------------------------------------------------------------- logging, firmware, availability

def p_event_log(c: Ctx) -> R:
    if not c.known("EVENT_LOG_OFF"):
        return "unknown", "Event log settings were not read."
    if c.f("EVENT_LOG_OFF"):
        return "fail", "Event logging is disabled."
    return "pass", "Event logging is enabled."


def p_central_log(c: Ctx) -> R:
    targets = c.s.get("log_targets")
    if targets is None:
        return "unknown", "Log target settings were not read."
    if c.f("NO_CENTRAL_LOG"):
        return "fail", "Logs are kept only on the FortiGate."
    on = [t for t, v in targets.items() if v.get("status") == "enable"]
    if not on:
        return "unknown", "Some log targets could not be read."
    if c.f("LOG_UNENCRYPTED"):
        return "partial", f"Logging to {', '.join(on)}; " + _detail(c.f("LOG_UNENCRYPTED"))
    return "pass", f"Logging to {', '.join(on)}, encrypted in transit."


def p_change_review(c: Ctx) -> R:
    log = c.snap.get("change_log")
    if log is not None:
        return "pass", (f"The configuration change log was read ({_plural(len(log), 'event')}); the report lists recent changes "
                        "with who made them.")
    return "manual", ("Not visible in a config backup. Run rulescope collect or fleet on a schedule to get change reports "
                      "with who changed what, and alerts on risky changes.")


def p_firmware(c: Ctx) -> R:
    fw = c.result.get("firmware") or {}
    lc = fw.get("lifecycle") or {}
    adv = fw.get("advisories") or {}
    if lc.get("status") in (None, "unknown"):
        return "unknown", f"FortiOS version {lc.get('version') or 'unknown'} is not in the lifecycle table."
    bad = c.f("FIRMWARE_EOS", "FIRMWARE_KEV") + c.sev("FIRMWARE_CVE", levels=("high",))
    life = (f"End of support {lc['eos']}" + (" (passed)" if lc["status"] == "eos" else f", in {lc['days_to_eos']} days"))
    cnt = adv.get("counts") or {}
    vul = (f"NVD lists {_plural(cnt.get('total', 0), 'CVE')} for {lc['version']} ({cnt.get('kev', 0)} actively exploited, "
           f"{cnt.get('critical', 0)} critical)" if adv.get("checked") else "known vulnerabilities not checked (run with --advisories online)")
    if bad:
        return "fail", f"FortiOS {lc['version']}: {life}; {vul}."
    if c.f("FIRMWARE_EOES", "FIRMWARE_EOES_SOON", "FIRMWARE_CVE") or not adv.get("checked"):
        return "partial", f"FortiOS {lc['version']}: {life}; {vul}."
    return "pass", f"FortiOS {lc['version']}: {life}; {vul}."


def p_updates(c: Ctx) -> R:
    au, lic = c.s.get("autoupdate"), c.snap.get("licenses")
    if au is None and lic is None:
        return "unknown", "Update schedule and licenses were not read."
    fs = c.f("FORTIGUARD_UPDATES_OFF", "LICENSE_EXPIRED")
    if [x for x in fs if x["severity"] in ("high", "medium")]:
        return "fail", _detail(fs, 3)
    if fs:
        return "partial", _detail(fs, 3)
    lic_txt = "license status not available from a config backup" if lic is None else "no subscription expired"
    return "pass", f"Scheduled FortiGuard updates are on{'' if au else ' (schedule not read)'}; {lic_txt}."


def p_ha(c: Ctx) -> R:
    ha = c.s.get("ha")
    if ha is None:
        return "unknown", "HA settings were not read."
    if ha.get("mode") in ("standalone", "", None):
        return "na", "Standalone unit. HA is a business decision about the cost of downtime."
    if c.f("HA_NO_MONITOR"):
        return "fail", _detail(c.f("HA_NO_MONITOR"))
    if c.f("HA_NO_MGMT"):
        return "partial", f"HA {ha['mode']} monitors {ha.get('monitor')}, but has no reserved management interface."
    return "pass", f"HA {ha['mode']} monitors {ha.get('monitor')} with a reserved management interface."


# id, domain, practice, sources, related checks, evaluator
PRACTICES: List[Tuple[str, str, str, str, List[str], Callable[[Ctx], R]]] = [
    ("BP01", "Management access", "No admin services on internet-facing interfaces", "CIS 1.3 · Fortinet admin · Cyber Centre",
     ["ADMIN_WAN"], p_mgmt_wan),
    ("BP02", "Management access", "Admin over HTTPS and SSH only, never HTTP or Telnet", "CIS 2.4.5 · Fortinet admin",
     ["ADMIN_TELNET", "ADMIN_HTTP"], p_mgmt_proto),
    ("BP03", "Management access", "Trusted hosts on every admin and API account", "CIS 2.4.2 · Fortinet admin",
     ["ADMIN_NO_TRUSTHOST", "APIUSER_NO_TRUSTHOST"], p_trusthosts),
    ("BP04", "Management access", "Local-in policies limit who can reach the FortiGate", "CIS 2.4.6 · Fortinet tip",
     ["ADMIN_WAN"], p_local_in),
    ("BP05", "Management access", "Admin ports moved off 443 and 22", "CIS 2.4.7 · Fortinet admin",
     ["ADMIN_DEFAULT_PORTS"], p_ports),
    ("BP06", "Management access", "Admin GUI accepts TLS 1.2 or later only", "CIS 2.1.10 · Fortinet admin",
     ["ADMIN_WEAK_TLS"], p_admin_tls),
    ("BP07", "Management access", "Short admin idle timeout", "CIS 2.4.4 · Fortinet admin", ["LONG_ADMIN_TIMEOUT"], p_timeout),
    ("BP08", "Management access", "Login banners; hostname hidden on the login page", "CIS 2.1.1, 2.1.2 · CIS 7.4 2.1.13",
     ["NO_LOGIN_BANNER", "HOSTNAME_ON_LOGIN"], p_banner),
    ("BP09", "System hardening", "strong-crypto on, static-key TLS ciphers off", "CIS 2.1.8, 2.1.9 · Fortinet hardening",
     ["WEAK_CRYPTO", "STATIC_KEY_CIPHERS"], p_crypto),
    ("BP10", "System hardening", "USB firmware and config auto-install off", "CIS 2.1.7 · Fortinet hardening",
     ["USB_AUTO_INSTALL"], _simple("USB_AUTO_INSTALL", "USB auto-install settings were not read.",
                                   "USB auto-install of configuration and firmware is disabled.")),
    ("BP11", "System hardening", "Private data encryption key set, backups encrypted", "Fortinet hardening",
     ["NO_PRIVATE_DATA_ENCRYPTION"], p_pde),
    ("BP12", "System hardening", "NTP time sync, correct timezone, trusted DNS servers", "CIS 1.1, 2.1.3, 2.1.4 · Fortinet tip",
     ["NTP_DISABLED"], p_time),
    ("BP13", "System hardening", "SNMPv3 only, limited to trusted hosts", "CIS 2.3.1, 2.3.2 · Fortinet hardening",
     ["SNMP_V2C", "SNMP_V3_NOPRIV"], p_snmp),
    ("BP14", "Accounts", "Default admin account renamed or removed", "CIS 2.4.1 · Fortinet admin", ["DEFAULT_ADMIN"], p_default_admin),
    ("BP15", "Accounts", "Lockout threshold and duration set", "CIS 2.2.2 · Fortinet admin", ["ADMIN_LOCKOUT_WEAK"], p_lockout),
    ("BP16", "Accounts", "Password policy enforced", "CIS 2.2.1", ["NO_PASSWORD_POLICY"], p_password),
    ("BP17", "Accounts", "MFA for administrators", "Fortinet admin · Fortinet tip", ["ADMIN_NO_MFA"], p_mfa),
    ("BP18", "Accounts", "Least-privilege admin profiles, one account per person", "CIS 2.4.3 · Fortinet admin",
     ["APIUSER_SUPER_ADMIN", "MANY_SUPER_ADMINS"], p_least),
    ("BP19", "Firewall policy", "No service ALL; explicit addresses instead of all", "CIS 3.2 · Fortinet tip",
     ["ANY_ANY", "OUTBOUND_UNRESTRICTED", "SERVICE_ALL", "EXPOSED_ALL_PORTS"], p_breadth),
    ("BP20", "Firewall policy", "Unused policies reviewed regularly", "CIS 3.1",
     ["UNUSED", "STALE", "REDUNDANT", "SHADOW_DEAD", "EXPIRED_SCHEDULE", "DISABLED"], p_unused),
    ("BP21", "Firewall policy", "Logging on every policy", "CIS 3.4 · Fortinet tip", ["NO_LOG"], p_logging_rules),
    ("BP22", "Firewall policy", "Deny Tor, malicious and scanner IPs with ISDB", "CIS 3.3 · Fortinet tip", ["NO_ISDB_DENY"], p_isdb),
    ("BP23", "Firewall policy", "Intra-zone traffic not allowed by default", "CIS 1.2", ["ZONE_INTRAZONE_ALLOW"], p_intrazone),
    ("BP24", "Security profiles", "IPS on policies", "CIS 4.1.2 · Fortinet tip", ["EXPOSED_NO_IPS", "NO_UTM_WAN", "PROFILE_GAPS"], p_ips),
    ("BP25", "Security profiles", "AV, DNS filter and application control on policies", "CIS 4.2.2, 4.3.3, 4.4.4",
     ["NO_UTM_WAN", "PROFILE_GAPS"], p_profiles),
    ("BP26", "Security profiles", "Botnet detection and C&C domain blocking", "CIS 4.1.1, 4.3.1",
     ["IPS_NO_BOTNET", "DNS_NO_BOTNET"], p_botnet),
    ("BP27", "VPN", "SSL-VPN off when unused, limited to trusted IPs", "Cyber Centre", ["SSLVPN_EXPOSED"], p_ssl_exposed),
    ("BP28", "VPN", "SSL-VPN limited to TLS 1.2 or later", "CIS 6.1.2", ["SSLVPN_WEAK_TLS"], p_ssl_tls),
    ("BP29", "VPN", "Trusted CA certificate on the VPN portal", "CIS 6.1.1", ["SSLVPN_FACTORY_CERT"], p_ssl_cert),
    ("BP30", "VPN", "SSL-VPN tunnel mode replaced by IPsec", "Fortinet SSL-VPN", ["SSLVPN_TUNNEL_MODE"], p_ssl_tunnel),
    ("BP31", "VPN", "Strong IPsec ciphers; certificates over PSK", "Fortinet tip",
     ["VPN_WEAK_CRYPTO", "VPN_AGGRESSIVE_PSK", "VPN_NO_PFS"], p_ipsec),
    ("BP32", "Logging", "Event logging on", "CIS 7.1.1 · Fortinet tip", ["EVENT_LOG_OFF"], p_event_log),
    ("BP33", "Logging", "Central logging to FortiAnalyzer or syslog, encrypted in transit", "CIS 7.2.1, 7.3.1",
     ["NO_CENTRAL_LOG", "LOG_UNENCRYPTED"], p_central_log),
    ("BP34", "Logging", "Review for unauthorized configuration changes", "Cyber Centre", [], p_change_review),
    ("BP35", "Firmware", "Supported, current firmware; PSIRT advisories followed", "CIS 2.1.6 · Fortinet hardening · Cyber Centre",
     ["FIRMWARE_EOS", "FIRMWARE_EOES", "FIRMWARE_EOES_SOON", "FIRMWARE_KEV", "FIRMWARE_CVE"], p_firmware),
    ("BP36", "Firmware", "FortiGuard databases updated on time", "CIS 4.2.1 · Fortinet hardening",
     ["FORTIGUARD_UPDATES_OFF", "LICENSE_EXPIRED"], p_updates),
    ("BP37", "Availability", "HA with monitored interfaces and a reserved management interface", "CIS 2.5.1, 2.5.2, 2.5.3",
     ["HA_NO_MONITOR", "HA_NO_MGMT"], p_ha),
]


def evaluate(snap: Dict[str, Any], result: Dict[str, Any], wan: Set[str]) -> Dict[str, Any]:
    c = Ctx(snap, result, wan)
    items = []
    for pid, domain, title, sources, related, fn in PRACTICES:
        try:
            status, evidence = fn(c)
        except (KeyError, ValueError, TypeError) as e:  # never let one practice break the report
            status, evidence = "unknown", f"Could not be evaluated ({type(e).__name__})."
        linked = sorted({f["check"] for f in c.f(*related)})
        items.append({"id": pid, "domain": domain, "title": title, "sources": sources, "status": status,
                      "evidence": evidence, "checks": linked})
    counts = {s: sum(1 for i in items if i["status"] == s) for s in STATUS_LABEL}
    assessed = sum(counts[s] for s in ("pass", "partial", "fail"))
    return {"items": items, "counts": counts, "total": len(items), "assessed": assessed,
            "passed": counts["pass"], "percent": round(100 * counts["pass"] / assessed) if assessed else 0}
