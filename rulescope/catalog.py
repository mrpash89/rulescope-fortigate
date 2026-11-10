"""Check catalog: definitions, score areas, effort, compliance mapping, and finding helpers.

Everything a reader of the report sees about a check (title, why, recommendation,
compliance references) lives here, so wording can be reviewed in one place.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .safety import clean

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEV_LABEL = {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

# area id: (label, weight in overall score)
AREAS: Dict[str, tuple] = {
    "exposure": ("Internet exposure", 0.25),
    "rules": ("Rule base", 0.20),
    "device": ("Device hardening", 0.25),
    "monitoring": ("Logging & inspection", 0.15),
    "vpn": ("VPN", 0.10),
    "objects": ("Objects", 0.05),
}
AREA_ALIASES = {"admin": "device"}  # area ids used by rulescope 0.3 and earlier

# id: (severity, area, title, why it matters, recommendation)
CHECKS: Dict[str, tuple] = {
    # ---- internet exposure
    "EXPOSED_RISKY": ("high", "exposure", "Risky service reachable from the internet",
        "A service that is routinely brute-forced or exploited (remote desktop, file sharing, databases, "
        "remote management, industrial protocols) is reachable from the internet.",
        "Remove the inbound rule, or put the service behind VPN with MFA. If it must stay public, "
        "restrict the source to known addresses and apply an IPS profile."),
    "EXPOSED_ALL_PORTS": ("high", "exposure", "Inbound rule exposes all ports",
        "Every port of the destination is reachable from the internet, including services nobody intended to publish.",
        "Replace service ALL with the specific ports that must be published."),
    "EXPOSED_NO_IPS": ("medium", "exposure", "Internet-facing rule without IPS",
        "Traffic from the internet reaches an internal service without intrusion prevention.",
        "Apply an IPS sensor (and SSL inspection where possible) to every inbound rule."),
    "ADMIN_WAN": ("high", "exposure", "Management exposed on internet-facing interface",
        "The admin GUI/SSH listens on a WAN interface. FortiOS management interfaces are a recurring target of critical CVEs.",
        "Remove management from WAN interfaces; manage over VPN or a dedicated management network. "
        "If unavoidable, restrict with local-in policies and trusted hosts."),
    "SSLVPN_EXPOSED": ("medium", "exposure", "SSL-VPN portal open to the whole internet",
        "The SSL-VPN service is one of the most attacked FortiGate components and accepts connections from any address.",
        "Restrict source addresses (geo or known ranges), enforce MFA, keep firmware patched against "
        "FortiGuard PSIRT advisories, and plan migration to IPsec/IKEv2 dial-up, which Fortinet recommends over SSL-VPN tunnel mode."),
    # ---- rule base
    "SHADOW_CONFLICT": ("high", "rules", "Deny rule never applies",
        "An earlier accept rule matches all of this rule's traffic, so the block it was written for is not enforced.",
        "Move this deny rule above the accept rule that shadows it, or narrow the accept rule."),
    "ANY_ANY": ("high", "rules", "Any-to-any accept rule",
        "Source, destination and service are all unrestricted. Between these interfaces the firewall enforces nothing.",
        "Replace with rules for the specific networks and services that are actually used (hit counts and logs show what)."),
    "OUTBOUND_UNRESTRICTED": ("medium", "rules", "Unrestricted outbound internet access",
        "Internal hosts can reach any internet destination on any port. Malware command-and-control and data "
        "exfiltration face no egress control.",
        "Limit outbound services to what is needed (web, DNS, NTP, mail relays) and apply application control, "
        "web and DNS filtering to the rule."),
    "SERVICE_ALL": ("medium", "rules", "Accept rule allows all services",
        "The rule permits every protocol and port between its sources and destinations.",
        "Restrict the service to the ports in use; FortiView or traffic logs for this policy ID show them."),
    "SHADOW_DEAD": ("medium", "rules", "Accept rule can never match",
        "An earlier deny rule matches all of this rule's traffic. The rule is dead and misleads anyone reading the policy.",
        "Disable it, or move it above the deny rule if the access is actually needed."),
    "UNUSED": ("medium", "rules", "Accept rule has zero hits",
        "No traffic matched this rule in the measured period. Unused permits are attack surface with no benefit.",
        "Disable, observe for a full business cycle, then delete."),
    "NO_ISDB_DENY": ("low", "rules", "No deny rule for known-malicious internet sources",
        "Services are published to the whole internet, but no policy above them drops Tor exit nodes, scanners and "
        "known malicious servers, which FortiGuard's Internet Service Database identifies for free.",
        "Add a deny policy from the WAN interfaces with internet-service-src set to the Tor, scanner and malicious-server "
        "entries, and move it above the inbound rules."),
    "ZONE_INTRAZONE_ALLOW": ("low", "rules", "Zone allows traffic between its interfaces without a policy",
        "With intrazone allow, hosts on different interfaces of the zone reach each other with no policy, logging "
        "or inspection.",
        "Set intrazone deny and write explicit policies for the traffic that must cross between the zone's interfaces."),
    "REDUNDANT": ("low", "rules", "Redundant rule",
        "An earlier rule with the same action already matches all of this rule's traffic.",
        "Disable, observe for a full business cycle, then delete."),
    "UNUSED_DENY": ("low", "rules", "Deny rule has zero hits",
        "No traffic matched this deny rule in the measured period.",
        "Confirm the rule is still intended; explicit denies are sometimes kept on purpose."),
    "STALE": ("low", "rules", "Rule has not matched traffic recently",
        "The rule has hits, but none within the stale window.",
        "Confirm with the rule owner whether the access is still required."),
    "EXPIRED_SCHEDULE": ("low", "rules", "Rule uses an expired schedule",
        "The rule's one-time schedule has ended, so the rule can never match again.",
        "Delete the rule (and the schedule) or extend the schedule if the access is still needed."),
    "DISABLED": ("info", "rules", "Disabled rule",
        "Disabled rules clutter the policy and are easy to re-enable by mistake.",
        "Delete once confirmed unneeded."),
    "NO_NAME": ("info", "rules", "Rule has no name or comment",
        "Nobody can tell why the rule exists or who owns it.",
        "Give every rule a name and a comment with owner and ticket reference."),
    # ---- logging & inspection
    "NO_LOG": ("medium", "monitoring", "Accept rule does not log traffic",
        "Allowed sessions through this rule leave no trace for investigation or SIEM.",
        "Set logtraffic to 'all' (or at least 'utm')."),
    "NO_UTM_WAN": ("medium", "monitoring", "Internet-bound accept rule without security profiles",
        "Traffic to the internet is allowed without AV, web filter, IPS or application control.",
        "Apply at least IPS and application control; add web/DNS filtering for user traffic."),
    "EVENT_LOG_OFF": ("medium", "monitoring", "Event logging disabled",
        "Admin logins, configuration changes, VPN and system events are not logged, so an intrusion or a bad change "
        "leaves no trail.",
        "Enable event logging (log eventfilter: event enable)."),
    "NO_CENTRAL_LOG": ("medium", "monitoring", "No central logging",
        "Logs stay only on the FortiGate, where they are lost on failure, rotate quickly and can be deleted by an "
        "attacker who gains admin access.",
        "Send logs to FortiAnalyzer, FortiAnalyzer Cloud or a syslog/SIEM server."),
    "FORTIGUARD_UPDATES_OFF": ("medium", "monitoring", "Scheduled FortiGuard updates disabled",
        "Antivirus, IPS and application signatures stop updating, so security profiles miss current threats.",
        "Enable the autoupdate schedule (frequency automatic)."),
    "LICENSE_EXPIRED": ("medium", "monitoring", "FortiGuard or FortiCare subscription expired or expiring",
        "When a FortiGuard service expires its signatures and ratings stop updating, while the profiles that rely on "
        "them still look applied.",
        "Renew the subscription before the expiry date; check the FortiGuard licenses page."),
    "PROFILE_GAPS": ("low", "monitoring", "Internet-bound rule missing security profiles",
        "The rule inspects traffic with some profiles but not IPS, antivirus, DNS filter or application control, "
        "which the CIS benchmark expects on internet-bound policies.",
        "Add the missing profiles to the rule (or to its profile group)."),
    "IPS_NO_BOTNET": ("low", "monitoring", "IPS sensor does not block botnet connections",
        "Connections from infected internal hosts to known botnet command-and-control servers are not blocked.",
        "Set scan-botnet-connections block on the IPS sensors used by internet-bound rules."),
    "DNS_NO_BOTNET": ("low", "monitoring", "DNS filter does not block botnet C&C domains",
        "Infected hosts can resolve the domains of known command-and-control servers.",
        "Enable block-botnet on the DNS filter profiles in use."),
    "LOG_UNENCRYPTED": ("low", "monitoring", "Logs sent without encryption",
        "Log traffic crosses the network in clear text and can be read or altered in transit.",
        "Use enc-algorithm high for FortiAnalyzer; use reliable (TCP) syslog with TLS where the SIEM supports it."),
    # ---- device hardening (admin access, accounts, system settings, firmware)
    "FIRMWARE_EOS": ("high", "device", "FortiOS version is past end of support",
        "Fortinet no longer publishes security fixes for this branch, so every vulnerability found from now on stays open.",
        "Upgrade to a supported branch, following Fortinet's upgrade path tool (docs.fortinet.com/upgrade-tool)."),
    "FIRMWARE_KEV": ("high", "device", "Firmware has an actively exploited vulnerability",
        "CISA lists this vulnerability as exploited in the wild, and this FortiOS version is affected.",
        "Upgrade to a fixed version now and follow the FortiGuard PSIRT advisory, including any post-upgrade checks "
        "for compromise."),
    "FIRMWARE_CVE": ("medium", "device", "Firmware has a known high-severity vulnerability",
        "The National Vulnerability Database lists this FortiOS version as affected by a high or critical vulnerability.",
        "Upgrade to a fixed version; the linked FortiGuard advisory lists fixed builds and workarounds."),
    "ADMIN_TELNET": ("high", "device", "Telnet management enabled",
        "Telnet sends admin credentials in clear text.",
        "Remove telnet from allowaccess."),
    "APIUSER_NO_TRUSTHOST": ("high", "device", "REST API user without trusted hosts",
        "A stolen API token is usable from anywhere.",
        "Restrict the API user to the IPs of the systems that use the token."),
    "FIRMWARE_EOES": ("medium", "device", "FortiOS version is past end of engineering support",
        "Fortinet no longer commits to producing fixes for this branch; end of support follows.",
        "Plan the upgrade to a current branch before the end-of-support date."),
    "ADMIN_NO_MFA": ("medium", "device", "Administrator without multi-factor authentication",
        "A guessed, phished or reused password is enough to take over the firewall.",
        "Assign FortiToken (or another two-factor method) to every local administrator, or authenticate admins "
        "against a RADIUS/SAML server that enforces MFA."),
    "APIUSER_SUPER_ADMIN": ("medium", "device", "REST API user has super_admin rights",
        "Whoever holds this token can change any setting, including admins and firmware.",
        "Bind the API user to a custom profile with only the permissions its integration needs (read-only for auditing)."),
    "ADMIN_NO_TRUSTHOST": ("medium", "device", "Administrator without trusted hosts",
        "This admin account can log in from any source address.",
        "Set trusthost entries to the management networks."),
    "WEAK_CRYPTO": ("medium", "device", "Strong crypto disabled",
        "Management and VPN sessions may negotiate weak ciphers and protocols.",
        "Enable strong-crypto in system global."),
    "ADMIN_WEAK_TLS": ("medium", "device", "Admin GUI accepts TLS older than 1.2",
        "TLS 1.0 and 1.1 are deprecated and allow downgrade attacks on admin sessions.",
        "Set admin-https-ssl-versions to tlsv1-2 tlsv1-3."),
    "LDAP_INSECURE": ("medium", "device", "LDAP server queried without TLS",
        "User and admin passwords checked against this server cross the network in clear text.",
        "Set secure ldaps (port 636) or starttls, with the directory's CA certificate."),
    "SNMP_V2C": ("medium", "device", "SNMP v1/v2c community enabled",
        "SNMP v1/v2c authenticates with a community string sent in clear text and gives no encryption.",
        "Move monitoring to SNMPv3 with auth-priv, limit it to the monitoring servers, and disable the community."),
    "ADMIN_HTTP": ("low", "device", "Plain HTTP management enabled",
        "HTTP management is unencrypted; with HTTPS redirect it is only an extra listening port.",
        "Remove http from allowaccess."),
    "DEFAULT_ADMIN": ("low", "device", "Default 'admin' account exists",
        "The well-known account name is the first target of password-guessing.",
        "Create named admin accounts and delete or rename 'admin'."),
    "LONG_ADMIN_TIMEOUT": ("low", "device", "Long admin idle timeout",
        "Unattended admin sessions stay logged in.",
        "Set admintimeout to 15 minutes or less (Fortinet recommends 5)."),
    "ADMIN_LOCKOUT_WEAK": ("low", "device", "Weak admin lockout",
        "Short lockouts or many allowed attempts let attackers keep guessing admin passwords.",
        "Lock out after 3 failed attempts for at least 15 minutes (CIS: threshold 3, duration 900)."),
    "NO_PASSWORD_POLICY": ("low", "device", "No admin password policy",
        "Administrators can set short or simple passwords.",
        "Enable the password policy for admin passwords with a minimum length of 12 and mixed character classes."),
    "MANY_SUPER_ADMINS": ("low", "device", "Many super_admin accounts",
        "Every super_admin account can do anything on the device; each extra one widens the target.",
        "Keep super_admin to a few named people and give everyone else a scoped admin profile."),
    "STATIC_KEY_CIPHERS": ("low", "device", "Static-key TLS ciphers allowed",
        "RSA key-exchange ciphers have no forward secrecy: a stolen private key decrypts recorded sessions.",
        "Set ssl-static-key-ciphers disable in system global."),
    "USB_AUTO_INSTALL": ("low", "device", "USB auto-install enabled",
        "Anyone with physical access can load a configuration or firmware image from a USB drive at boot.",
        "Disable auto-install-config and auto-install-image."),
    "NO_PRIVATE_DATA_ENCRYPTION": ("low", "device", "Private data encryption disabled",
        "Passwords and keys in configuration backups are protected only by a key built into FortiOS.",
        "Enable private-data-encryption with a key you store safely; backups then need that key to restore."),
    "NTP_DISABLED": ("low", "device", "Time synchronization disabled",
        "Wrong clocks break log correlation, certificate checks and time-based two-factor tokens.",
        "Enable NTP (FortiGuard or internal NTP servers)."),
    "SNMP_V3_NOPRIV": ("low", "device", "SNMPv3 user without authentication and encryption",
        "The SNMPv3 user does not use both authentication and privacy, so it is no better than v2c.",
        "Set security-level auth-priv with SHA-256 or better and AES."),
    "HA_NO_MONITOR": ("low", "device", "HA cluster does not monitor interfaces",
        "If a link fails on the primary unit the cluster does not fail over, and traffic stops.",
        "Add the critical interfaces to the HA monitor list."),
    "FIRMWARE_EOES_SOON": ("low", "device", "FortiOS end of engineering support is near",
        "Fortinet stops committing to fixes for this branch soon; end of support follows 18 months later.",
        "Schedule the upgrade to a current branch now; large upgrades need several hops and testing."),
    "ADMIN_DEFAULT_PORTS": ("info", "device", "Admin services on default ports",
        "Default admin ports are the first ones scanned. Changing them is a minor measure, not a substitute for "
        "restricting access.",
        "Move HTTPS and SSH admin to non-default ports (admin-sport, admin-ssh-port)."),
    "NO_LOGIN_BANNER": ("info", "device", "No login banner",
        "A pre-login banner states that access is restricted and monitored, which some jurisdictions and audits expect.",
        "Enable pre-login-banner (and edit the admin login disclaimer replacement message)."),
    "HOSTNAME_ON_LOGIN": ("info", "device", "Hostname shown on the login page",
        "The login page tells anyone who reaches it which device and site they found.",
        "Set gui-display-hostname disable."),
    "HA_NO_MGMT": ("info", "device", "HA cluster without reserved management interface",
        "Without a reserved management interface, each cluster unit cannot be managed or monitored individually.",
        "Configure ha-mgmt-status enable with a dedicated management interface."),
    # ---- VPN
    "VPN_WEAK_CRYPTO": ("medium", "vpn", "IPsec tunnel allows weak cryptography",
        "The tunnel accepts deprecated ciphers, hashes or Diffie-Hellman groups that do not protect traffic against a capable attacker.",
        "Use AES-GCM or AES-256 with SHA-256 or better, and DH group 14 or higher (19/20/21 preferred), on both peers."),
    "VPN_AGGRESSIVE_PSK": ("medium", "vpn", "IKEv1 aggressive mode with pre-shared key",
        "Aggressive mode exposes a hash of the pre-shared key that can be cracked offline.",
        "Move the tunnel to IKEv2 (or at least main mode), and use certificates or a long random PSK."),
    "SSLVPN_WEAK_TLS": ("medium", "vpn", "SSL-VPN allows TLS older than 1.2",
        "TLS 1.0 and 1.1 are deprecated and allow downgrade attacks.",
        "Set ssl-min-proto-ver tls1-2 (or tls1-3)."),
    "SSLVPN_FACTORY_CERT": ("low", "vpn", "SSL-VPN uses the factory certificate",
        "Users are trained to click through certificate warnings, which makes interception attacks easy.",
        "Install a certificate from a trusted CA for the portal name and set it as servercert."),
    "SSLVPN_TUNNEL_MODE": ("low", "vpn", "SSL-VPN tunnel mode in use",
        "Fortinet removes SSL-VPN tunnel mode from FortiOS 7.6.3 and recommends IPsec (IKEv2) dial-up instead; "
        "users must move before the device can be upgraded past 7.6.2 without losing remote access.",
        "Plan the migration of remote users to IPsec dial-up with FortiClient, then disable SSL-VPN."),
    "VPN_NO_PFS": ("low", "vpn", "IPsec phase 2 without perfect forward secrecy",
        "Without PFS, compromise of one key exposes traffic protected by later keys.",
        "Enable pfs with DH group 14 or higher on the phase 2 selectors."),
    # ---- objects
    "UNUSED_OBJECT": ("low", "objects", "Unreferenced object",
        "The object is not referenced anywhere in the configuration.",
        "Delete it. FortiOS refuses to delete objects that are still referenced, so this is safe to attempt."),
}

# Checks scored relative to rule base / object count instead of absolute counts.
RATIO_CHECKS = {
    "UNUSED": "policies", "UNUSED_DENY": "policies", "STALE": "policies", "REDUNDANT": "policies",
    "SHADOW_DEAD": "policies", "EXPIRED_SCHEDULE": "policies", "DISABLED": "policies", "NO_NAME": "policies",
    "NO_LOG": "policies", "NO_UTM_WAN": "policies", "SERVICE_ALL": "policies", "PROFILE_GAPS": "policies",
    "UNUSED_OBJECT": "objects",
}

# Findings that mean a rule can be removed - used for the "cleanup potential" metric.
REMOVABLE_CHECKS = {"UNUSED", "REDUNDANT", "SHADOW_DEAD", "EXPIRED_SCHEDULE", "DISABLED"}

# How much work a fix takes. quick: one setting, no change window needed; change: needs review or a change
# window because it can affect traffic, access or monitoring; project: an upgrade, migration or purchase.
EFFORT_LABEL = {"quick": "Quick fix", "change": "Change window", "project": "Project"}
_QUICK = {"WEAK_CRYPTO", "STATIC_KEY_CIPHERS", "ADMIN_WEAK_TLS", "LONG_ADMIN_TIMEOUT", "ADMIN_LOCKOUT_WEAK",
          "NO_PASSWORD_POLICY", "USB_AUTO_INSTALL", "NTP_DISABLED", "NO_LOGIN_BANNER", "HOSTNAME_ON_LOGIN",
          "EVENT_LOG_OFF", "FORTIGUARD_UPDATES_OFF", "NO_LOG", "ADMIN_TELNET", "ADMIN_HTTP", "SSLVPN_WEAK_TLS",
          "IPS_NO_BOTNET", "DNS_NO_BOTNET", "UNUSED_OBJECT", "DISABLED", "EXPIRED_SCHEDULE", "NO_NAME"}
_PROJECT = {"FIRMWARE_EOS", "FIRMWARE_EOES", "FIRMWARE_EOES_SOON", "FIRMWARE_KEV", "FIRMWARE_CVE", "NO_CENTRAL_LOG",
            "LICENSE_EXPIRED", "SSLVPN_TUNNEL_MODE", "SSLVPN_FACTORY_CERT", "ANY_ANY", "OUTBOUND_UNRESTRICTED"}
EFFORT: Dict[str, str] = {c: ("quick" if c in _QUICK else "project" if c in _PROJECT else "change") for c in CHECKS}

# Checks added in 0.4: comparisons with older results skip them so they do not show up as "new".
INTRODUCED_0_4 = {
    "NO_ISDB_DENY", "ZONE_INTRAZONE_ALLOW", "EVENT_LOG_OFF", "NO_CENTRAL_LOG", "FORTIGUARD_UPDATES_OFF",
    "LICENSE_EXPIRED", "PROFILE_GAPS", "IPS_NO_BOTNET", "DNS_NO_BOTNET", "LOG_UNENCRYPTED", "FIRMWARE_EOS",
    "FIRMWARE_KEV", "FIRMWARE_CVE", "FIRMWARE_EOES", "ADMIN_NO_MFA", "APIUSER_SUPER_ADMIN", "ADMIN_WEAK_TLS",
    "LDAP_INSECURE", "SNMP_V2C", "ADMIN_LOCKOUT_WEAK", "NO_PASSWORD_POLICY", "MANY_SUPER_ADMINS",
    "STATIC_KEY_CIPHERS", "USB_AUTO_INSTALL", "NO_PRIVATE_DATA_ENCRYPTION", "NTP_DISABLED", "SNMP_V3_NOPRIV",
    "HA_NO_MONITOR", "FIRMWARE_EOES_SOON", "ADMIN_DEFAULT_PORTS", "NO_LOGIN_BANNER", "HOSTNAME_ON_LOGIN",
    "HA_NO_MGMT", "SSLVPN_FACTORY_CERT", "SSLVPN_TUNNEL_MODE",
}

# ---------------------------------------------------------------- compliance mapping
# Indicative mapping that helps auditors find the relevant control; it is not a certification.
# CIS titles are paraphrased; the numbering follows the CIS FortiGate 7.0.x benchmark v1.4.0.

_ISO, _PCI, _NIST, _CIS = "ISO 27001:2022", "PCI DSS 4.0", "NIST SP 800-53 r5", "CIS FortiGate 7.0.x v1.4.0"

CONTROL_NAMES = {
    _CIS: {
        "1.2": "Intra-zone traffic is not always allowed", "1.3": "Management services disabled on WAN ports",
        "2.1.1": "Pre-login banner set", "2.1.4": "Time synchronized with NTP",
        "2.1.6": "Current, supported firmware", "2.1.7": "USB auto-install disabled", "2.1.8": "Strong crypto enabled",
        "2.1.9": "Static-key TLS ciphers disabled", "2.1.10": "Admin GUI limited to TLS 1.2 or later",
        "2.2.1": "Password policy enabled", "2.2.2": "Admin lockout configured", "2.3.1": "Only SNMPv3 enabled",
        "2.3.2": "SNMP limited to trusted hosts", "2.4.1": "Default admin account renamed or removed",
        "2.4.2": "Trusted hosts on admin accounts", "2.4.3": "Least-privilege admin profiles",
        "2.4.4": "Admin idle timeout", "2.4.5": "Encrypted admin access only", "2.4.7": "Default admin ports changed",
        "2.5.2": "HA monitors interfaces", "2.5.3": "HA reserved management interface",
        "3.1": "Unused policies reviewed", "3.2": "Policies do not use service ALL",
        "3.3": "Traffic from Tor, malicious and scanner IPs denied", "3.4": "Logging on all policies",
        "4.1.1": "IPS detects botnet connections", "4.1.2": "IPS profile on policies",
        "4.2.1": "Antivirus definitions updated automatically", "4.2.2": "Antivirus profile on policies",
        "4.3.1": "DNS filter blocks botnet C&C domains", "4.3.3": "DNS filter profile on policies",
        "4.4.4": "Application control on policies", "6.1.1": "Trusted certificate on the SSL-VPN portal",
        "6.1.2": "SSL-VPN limited to TLS 1.2 or later", "7.1.1": "Event logging enabled",
        "7.2.1": "Log transmission to FortiAnalyzer encrypted", "7.3.1": "Centralized logging and reporting",
    },
    _ISO: {
        "A.5.16": "Identity management", "A.5.17": "Authentication information", "A.8.2": "Privileged access rights",
        "A.8.5": "Secure authentication", "A.8.7": "Protection against malware",
        "A.8.8": "Management of technical vulnerabilities", "A.8.9": "Configuration management",
        "A.8.13": "Information backup", "A.8.14": "Redundancy of information processing facilities",
        "A.8.15": "Logging", "A.8.16": "Monitoring activities", "A.8.17": "Clock synchronization",
        "A.8.20": "Networks security", "A.8.21": "Security of network services", "A.8.22": "Segregation of networks",
        "A.8.23": "Web filtering", "A.8.24": "Use of cryptography",
    },
    _PCI: {
        "1.2.1": "Configuration standards for NSC rulesets are defined, implemented and maintained",
        "1.2.5": "Allowed services, protocols and ports are identified, approved and have a business need",
        "1.2.6": "Security features are implemented for insecure services, protocols and ports in use",
        "1.2.7": "NSC configurations are reviewed at least once every six months",
        "1.3.1": "Inbound traffic to the CDE is restricted",
        "1.3.2": "Outbound traffic from the CDE is restricted",
        "1.4.2": "Inbound traffic from untrusted to trusted networks is restricted",
        "2.2.2": "Vendor default accounts are managed",
        "2.2.7": "Non-console administrative access is encrypted with strong cryptography",
        "4.2.1": "Strong cryptography protects transmissions over open, public networks",
        "5.3.1": "Anti-malware mechanisms are kept current via automatic updates",
        "6.3.3": "Critical security patches are installed within one month of release",
        "7.2.2": "Access is assigned by job function with least privileges",
        "8.3.2": "Strong cryptography protects authentication factors in transmission and storage",
        "8.3.4": "Invalid authentication attempts are limited",
        "8.3.6": "Passwords meet minimum length and complexity",
        "8.4.1": "MFA for non-console administrative access",
        "8.2.8": "Sessions idle more than 15 minutes require re-authentication",
        "10.2.1": "Audit logs are enabled and active",
        "10.3.3": "Audit logs are promptly backed up to a central log server",
        "10.6.1": "System clocks are synchronized",
        "11.5.1": "Intrusion-detection/prevention techniques detect or prevent intrusions",
        "12.3.4": "Hardware and software technologies are reviewed, including end-of-life plans",
    },
    _NIST: {
        "AC-2": "Account Management", "AC-4": "Information Flow Enforcement", "AC-6": "Least Privilege",
        "AC-7": "Unsuccessful Logon Attempts", "AC-8": "System Use Notification", "AC-12": "Session Termination",
        "AC-17": "Remote Access", "AU-2": "Event Logging", "AU-6": "Audit Record Review, Analysis, and Reporting",
        "AU-8": "Time Stamps", "AU-9": "Protection of Audit Information", "AU-12": "Audit Record Generation",
        "CM-6": "Configuration Settings", "CM-7": "Least Functionality",
        "IA-2": "Identification and Authentication (Organizational Users)", "IA-5": "Authenticator Management",
        "RA-5": "Vulnerability Monitoring and Scanning", "SA-22": "Unsupported System Components",
        "SC-7": "Boundary Protection", "SC-8": "Transmission Confidentiality and Integrity",
        "SC-13": "Cryptographic Protection", "SC-17": "Public Key Infrastructure Certificates",
        "SC-28": "Protection of Information at Rest", "SI-2": "Flaw Remediation",
        "SI-3": "Malicious Code Protection", "SI-4": "System Monitoring",
    },
}


def _m(cis: List[str], iso: List[str], pci: List[str], nist: List[str]) -> Dict[str, List[str]]:
    return {_CIS: cis, _ISO: iso, _PCI: pci, _NIST: nist}


_HYGIENE = _m(["3.1"], ["A.8.9", "A.8.20"], ["1.2.5", "1.2.7"], ["CM-6", "CM-7"])
_BREADTH = _m(["3.2"], ["A.8.20", "A.8.22"], ["1.2.5", "1.3.1", "1.3.2"], ["AC-4", "SC-7", "CM-7"])
_INBOUND = _m([], ["A.8.20", "A.8.21", "A.8.22"], ["1.2.6", "1.3.1", "1.4.2"], ["SC-7", "CM-7", "AC-17"])
_VPNCRYPTO = _m([], ["A.8.24"], ["4.2.1"], ["SC-8", "SC-13"])
_PROFILES = _m(["4.1.2", "4.2.2", "4.3.3", "4.4.4"], ["A.8.7", "A.8.16", "A.8.23"], ["11.5.1"], ["SI-3", "SI-4"])
_ADMINCRYPTO = _m([], ["A.8.5", "A.8.24"], ["2.2.7"], ["SC-8", "CM-7"])
_FIRMWARE = _m(["2.1.6"], ["A.8.8"], ["6.3.3", "12.3.4"], ["SA-22", "SI-2"])
_VULN = _m(["2.1.6"], ["A.8.8"], ["6.3.3"], ["SI-2", "RA-5"])
_PRIV = _m(["2.4.3"], ["A.8.2"], ["7.2.2"], ["AC-6"])

COMPLIANCE: Dict[str, Dict[str, List[str]]] = {
    "EXPOSED_RISKY": _INBOUND, "EXPOSED_ALL_PORTS": dict(_INBOUND, **{_CIS: ["3.2"]}),
    "EXPOSED_NO_IPS": _m(["4.1.2"], ["A.8.7", "A.8.16"], ["11.5.1"], ["SI-3", "SI-4"]),
    "ADMIN_WAN": _m(["1.3"], ["A.8.2", "A.8.20"], ["1.4.2"], ["AC-17", "SC-7"]),
    "SSLVPN_EXPOSED": _m([], ["A.8.20", "A.8.21"], ["1.4.2"], ["AC-17", "SC-7"]),
    "SHADOW_CONFLICT": _m([], ["A.8.9", "A.8.20"], ["1.2.1", "1.2.7"], ["AC-4", "CM-6", "SC-7"]),
    "ANY_ANY": _BREADTH, "SERVICE_ALL": _BREADTH,
    "OUTBOUND_UNRESTRICTED": _m(["3.2"], ["A.8.20", "A.8.23"], ["1.2.5", "1.3.2"], ["SC-7", "CM-7"]),
    "SHADOW_DEAD": _HYGIENE, "UNUSED": _HYGIENE, "REDUNDANT": _HYGIENE, "UNUSED_DENY": _HYGIENE, "STALE": _HYGIENE,
    "EXPIRED_SCHEDULE": _HYGIENE, "DISABLED": _m(["3.1"], ["A.8.9"], ["1.2.7"], ["CM-6"]),
    "NO_NAME": _m([], ["A.8.9"], ["1.2.5"], ["CM-6"]),
    "NO_ISDB_DENY": _m(["3.3"], ["A.8.20"], ["1.4.2"], ["SC-7"]),
    "ZONE_INTRAZONE_ALLOW": _m(["1.2"], ["A.8.22"], ["1.2.1"], ["AC-4", "SC-7"]),
    "NO_LOG": _m(["3.4"], ["A.8.15", "A.8.16"], ["10.2.1"], ["AU-2", "AU-12"]),
    "NO_UTM_WAN": _PROFILES, "PROFILE_GAPS": _PROFILES,
    "IPS_NO_BOTNET": _m(["4.1.1"], ["A.8.7", "A.8.16"], ["11.5.1"], ["SI-3", "SI-4"]),
    "DNS_NO_BOTNET": _m(["4.3.1"], ["A.8.7", "A.8.23"], ["11.5.1"], ["SI-3", "SI-4"]),
    "EVENT_LOG_OFF": _m(["7.1.1"], ["A.8.15"], ["10.2.1"], ["AU-2", "AU-12"]),
    "NO_CENTRAL_LOG": _m(["7.3.1"], ["A.8.15", "A.8.16"], ["10.3.3"], ["AU-6", "AU-9"]),
    "LOG_UNENCRYPTED": _m(["7.2.1"], ["A.8.15", "A.8.24"], [], ["AU-9", "SC-8"]),
    "FORTIGUARD_UPDATES_OFF": _m(["4.2.1"], ["A.8.7"], ["5.3.1"], ["SI-3"]),
    "LICENSE_EXPIRED": _m([], ["A.8.7"], ["5.3.1", "11.5.1"], ["SI-3"]),
    "FIRMWARE_EOS": _FIRMWARE, "FIRMWARE_EOES": _FIRMWARE, "FIRMWARE_EOES_SOON": _FIRMWARE,
    "FIRMWARE_KEV": _VULN, "FIRMWARE_CVE": _VULN,
    "ADMIN_TELNET": _m(["2.4.5"], ["A.8.5", "A.8.24"], ["2.2.7", "1.2.6"], ["SC-8", "CM-7"]),
    "ADMIN_HTTP": _m(["2.4.5"], ["A.8.5", "A.8.24"], ["2.2.7"], ["SC-8", "CM-7"]),
    "APIUSER_NO_TRUSTHOST": _m(["2.4.2"], ["A.8.2", "A.8.5"], [], ["AC-17"]),
    "ADMIN_NO_TRUSTHOST": _m(["2.4.2"], ["A.8.2", "A.8.5"], [], ["AC-17"]),
    "DEFAULT_ADMIN": _m(["2.4.1"], ["A.5.16", "A.8.2"], ["2.2.2"], ["AC-2"]),
    "WEAK_CRYPTO": _m(["2.1.8"], ["A.8.24"], ["2.2.7"], ["SC-8", "SC-13"]),
    "STATIC_KEY_CIPHERS": _m(["2.1.9"], ["A.8.24"], ["2.2.7", "4.2.1"], ["SC-8", "SC-13"]),
    "ADMIN_WEAK_TLS": _m(["2.1.10"], ["A.8.24"], ["2.2.7"], ["SC-8", "SC-13"]),
    "LONG_ADMIN_TIMEOUT": _m(["2.4.4"], ["A.8.5"], ["8.2.8"], ["AC-12"]),
    "ADMIN_NO_MFA": _m([], ["A.8.5"], ["8.4.1"], ["IA-2"]),
    "APIUSER_SUPER_ADMIN": _PRIV, "MANY_SUPER_ADMINS": _PRIV,
    "ADMIN_LOCKOUT_WEAK": _m(["2.2.2"], ["A.8.5"], ["8.3.4"], ["AC-7"]),
    "NO_PASSWORD_POLICY": _m(["2.2.1"], ["A.5.17"], ["8.3.6"], ["IA-5"]),
    "ADMIN_DEFAULT_PORTS": _m(["2.4.7"], ["A.8.9"], [], ["CM-6", "CM-7"]),
    "NO_LOGIN_BANNER": _m(["2.1.1"], [], [], ["AC-8"]),
    "HOSTNAME_ON_LOGIN": _m([], ["A.8.9"], [], ["CM-7"]),
    "USB_AUTO_INSTALL": _m(["2.1.7"], ["A.8.9"], [], ["CM-7"]),
    "NO_PRIVATE_DATA_ENCRYPTION": _m([], ["A.8.13", "A.8.24"], [], ["SC-28"]),
    "NTP_DISABLED": _m(["2.1.4"], ["A.8.17"], ["10.6.1"], ["AU-8"]),
    "SNMP_V2C": _m(["2.3.1", "2.3.2"], ["A.8.21"], ["2.2.7"], ["CM-7", "SC-8"]),
    "SNMP_V3_NOPRIV": _m(["2.3.1"], ["A.8.21", "A.8.24"], ["2.2.7"], ["SC-8"]),
    "LDAP_INSECURE": _m([], ["A.8.5", "A.8.24"], ["8.3.2"], ["SC-8", "IA-5"]),
    "HA_NO_MONITOR": _m(["2.5.2"], ["A.8.14"], [], []),
    "HA_NO_MGMT": _m(["2.5.3"], ["A.8.14"], [], []),
    "VPN_WEAK_CRYPTO": _VPNCRYPTO, "VPN_AGGRESSIVE_PSK": _VPNCRYPTO, "VPN_NO_PFS": _VPNCRYPTO,
    "SSLVPN_WEAK_TLS": _m(["6.1.2"], ["A.8.24"], ["4.2.1"], ["SC-8", "SC-13"]),
    "SSLVPN_FACTORY_CERT": _m(["6.1.1"], ["A.8.24"], ["4.2.1"], ["SC-17", "SC-8"]),
    "SSLVPN_TUNNEL_MODE": _m([], ["A.8.8"], ["12.3.4"], ["SA-22"]),
    "UNUSED_OBJECT": _m([], ["A.8.9"], ["1.2.7"], ["CM-6"]),
}


def compliance_refs(check: str) -> List[str]:
    out = []
    for fw, ids in COMPLIANCE.get(check, {}).items():
        out += [f"{fw} {i}" for i in ids]
    return out


# ---------------------------------------------------------------- helpers

def finding(cid: str, *, policyid: Optional[int] = None, obj: Optional[str] = None,
            detail: str = "", cli: Optional[List[str]] = None, cli_scope: str = "vdom",
            cli_safe: bool = True, severity: Optional[str] = None, url: Optional[str] = None) -> Dict[str, Any]:
    sev, area, title, why, rec = CHECKS[cid]
    f = {"check": cid, "severity": severity or sev, "area": area, "category": AREAS[area][0],
         "title": title, "why": why, "recommendation": rec, "policyid": policyid, "uuid": None,
         "object": clean(obj), "detail": clean(detail), "cli": cli or [], "cli_scope": cli_scope, "cli_safe": cli_safe,
         "effort": EFFORT[cid]}
    if url:
        f["url"] = url
    return f


def q(s: str) -> str:
    """A quoted FortiOS CLI value. Control characters are removed first, so a name can never end the line."""
    s = clean(str(s))
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def label(p: Dict[str, Any]) -> str:
    return f"#{p['policyid']}" + (f" '{p['name']}'" if p.get("name") else "")


def disable_cli(p: Dict[str, Any], reason: str, today: str) -> List[str]:
    comment = (p.get("comments") or "").strip()
    note = f"rulescope {today}: {reason}"
    comment = (comment + " | " + note) if comment else note
    return ["config firewall policy", f"    edit {p['policyid']}", "        set status disable",
            f"        set comments {q(comment[:1023])}", "    next", "end"]


def step_down(sev: str) -> str:
    return {"high": "medium", "medium": "low", "low": "info", "info": "info"}[sev]
