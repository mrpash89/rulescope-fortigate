# Changelog

All notable changes to rulescope. Versions follow `MAJOR.MINOR.PATCH`; the newest is at the top.

## Unreleased

### Added
- Randomized tests (`tests/test_fuzz.py`): hostile configs built from random fragments go through the
  parser and every output. Deterministic, standard library only, part of the normal test run.
- `SECURITY.md`, `CONTRIBUTING.md` and this changelog.
- Demo website (`website/`): a landing page plus live sample output from synthetic configs, built by
  `website/build.py` as static files, with a Caddy config and a nightly rebuild timer.

### Fixed
- Invisible characters that the fixed list in 0.4.1 missed are now replaced with `?` when a config is
  read: the Arabic letter mark (a direction character), zero-width characters, the soft hyphen, the
  byte order mark and every other Unicode format character. Found by the randomized tests.
- A policy entry whose ID is not a number no longer stops the audit with an error. FortiOS never
  writes such entries, so they are ignored and the report says how many were.
- A hostname that is a Windows device name (`nul`, `con`, `com1`, ...) or ends with a dot gets a safe
  snapshot folder name.
- The rulescope source no longer contains literal invisible characters; they are written as escapes,
  and a test keeps it that way.

## 0.4.2 (2026-11-10)

Contributor fixes on top of 0.4.1. Thanks to user01010111 (#6, #7, #8, #9, #11) and
Oliver Timme (#10).

### Changed: check these when you upgrade
- **Snapshot schema 4.** Snapshots saved by earlier versions still load, but their redundancy, shadow
  and broad-match results show as "coverage unknown" until you collect again (#9).
- **Exit code 4** from `collect` and `fleet` when alerts could not be delivered. They are kept on disk
  and sent again with the next run (#10).
- **`--redact` cannot be combined with `--save-snapshot`**, and with `--baseline` it needs a snapshot,
  not a findings JSON, so both reports share one mapping (#8).
- `collect` and `audit --save-snapshot` now prune old snapshots (#10).
- Practices whose input could not be read show as "Not assessed" instead of passing (#10).

### Added
- GitHub Actions CI: tests on Python 3.9 to 3.15 on Linux and on macOS, a 10,000-policy benchmark,
  package build and installed-package test, optional draft release (#11).
- Change tracking also covers local-in policies, zones and VIP groups, with alerts for removed or
  disabled deny rules, reordered inbound rules and changed objects behind inbound rules (#10).
- The dashboard shows the alerts of the last 7 days and delivery failures (#10).
- A note in the report when the device has security policies (NGFW policy-based mode), proxy
  policies, `policy6` or IPv6 virtual IPs, which are not analyzed (#10).
- Cached vulnerability data older than 30 days is flagged in the report (#10).
- Redaction also covers custom VDOM names and Internet Service names, and removes imported usage
  file names (#8).
- Two firewalls with the same hostname keep separate snapshot histories; inventory names that map
  to the same folder are rejected (#10).

### Fixed
- Remediation scripts: a block whose commands contain control characters is withheld, and a
  multi-VDOM script selects the VDOM with a quoted name or withholds the VDOM-scoped blocks (#6).
- A snapshot with a policy ID that is not an integer is rejected, and policy IDs are escaped in the
  inventory table (#7).
- Rules with ZTNA tags, IPv6 Internet Services, vendor-MAC matching or negated internet services are
  left out of redundancy and shadow detection instead of being matched wrongly (#9, #10).
- Redirects are never followed for NVD and webhook requests (#10).
- Exposure: a source covering a /8 or more of public space counts as unrestricted; a local-in deny
  counts as protection only when it is always active and matches the interface; routes to a named
  address are not read as default routes (#10).
- Zero-hit rules are disabled by a live command only when the counters cover at least
  `--stale-days` (#10).
- Restored the fixes of 2026-11-08 that the 0.4.1 merge overwrote: IPv6 hosts for the API and
  syslog, log searches that report 0% keep polling, both values of a changed secret are masked,
  snapshot names in UTC.
- Tests check file modes on POSIX only; Windows has no POSIX permission bits.

## 0.4.1 (2026-11-10)

Security release. Configs, snapshots and API data are treated as hostile input.

### Changed: check these when you upgrade
- **Live runs need a certificate check.** Get the fingerprint once with `rulescope cert --host ...`
  and pass `--pin-sha256` (inventory key `pin_sha256`), or use `--ca-file`. `--insecure` still works
  and prints a warning.
- Line breaks inside config values are flattened to spaces when a config is read.
- Reports and fleet pages are written with mode 640, snapshots with mode 600; the systemd units set
  `UMask=0027`.

### Added
- `rulescope cert --host` prints the SHA-256 fingerprint of the certificate a device presents.
- `--pin-sha256`: the pinned certificate is checked on every connection before the token is sent.
- `--webhook-file` and the `RULESCOPE_WEBHOOK` environment variable, so the webhook URL stays out of
  the process list.

### Fixed
- A crafted object name or comment could add statements to a remediation script. Control characters
  never survive reading, every risky line is commented out line by line, and a final guard disables
  any line that is not a statement rulescope generates.
- CSV cells that a spreadsheet would run as a formula get a `'` prefix.
- Terminal escape codes and direction characters are removed from console and syslog output; one
  alert is always one syslog line.
- A crafted hostname such as `..` could write a snapshot outside the output folder.
- Report links must be `https://`; the local vulnerability cache is validated when it is read.
- Fleet workers on the same FortiOS version share one vulnerability lookup; cache writes are atomic.
- The change log also masks `pwd`, `passphrase` and SNMP community values.

## 0.4.0 (2026-11-08)

- Best-practice baseline: 37 practices with evidence, CIS mapping and effort tags.
- 35 new checks: device hardening, logging, security profiles, firmware.
- FortiOS lifecycle dates and known vulnerabilities from the NIST NVD with CISA KEV, with a cache.
- Quick wins, hardening-drift alerts, five palettes in light and dark.
- Apache-2.0 license.

## 0.3

- Report redesign and dark mode.
- Internet-facing interface detection with reasons and overrides (`--wan`, `--not-wan`).

## 0.2

- Fleet mode and dashboard.
- Change tracking with attribution, alerts by webhook and syslog.
- Usage import, redaction.
