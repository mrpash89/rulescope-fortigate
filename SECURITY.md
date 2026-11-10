# Security policy

rulescope reads firewall configurations that may come from anyone, holds an API token, and writes
scripts that people paste onto firewalls. Security problems in it are taken seriously.

## Reporting a vulnerability

**Do not open a public issue or pull request for a security problem.**

Report it privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**, or go to
<https://github.com/mrpash89/rulescope-fortigate/security/advisories/new>.
Only the maintainer can see the report.

Please include:

- the rulescope version (`rulescope --version`) and the Python version
- what an attacker needs (a crafted config backup, a position on the network, a local account, ...)
- the smallest input or steps that show the problem
- what happens, and what you expected

Never attach a real firewall configuration, API token or report. Build a small synthetic config that
shows the problem, or use `--redact`.

## What to expect

rulescope has one maintainer. Reports are read as soon as possible. A confirmed problem is fixed in a
patch release, described in [CHANGELOG.md](CHANGELOG.md), and you are credited unless you prefer not
to be.

## Supported versions

Only the latest release gets security fixes. Upgrade before reporting if you can.

## In scope

- Text from a config, snapshot, usage file or API answer that becomes something that acts: a
  statement in a remediation script, a spreadsheet formula, a terminal control sequence, markup or a
  link in a report, a syslog line, a file path.
- Anything that sends the API token, the NVD key or a webhook URL to a host you did not configure,
  or that skips the certificate check.
- Reports, snapshots or tokens readable by other local users on Linux or macOS.
- A wrong "clean" result: a risky rule or setting that rulescope reads but does not report. Open a
  normal issue for these unless the detail would help an attacker.
- The demo website, rulescope.mrpash.com: anything that lets a visitor change what it serves or
  reach the machine behind it. The site is static files built from synthetic configs.

## Out of scope

- Weaknesses of the firewall being audited. Those are findings, not rulescope vulnerabilities.
- `--insecure`. It disables the certificate check on purpose and says so.
- File permissions on Windows. Windows has no POSIX permission bits, so files there get the
  permissions of the folder they are written to.
- Attacks that need root or the rulescope service account on the machine that runs it.

## How rulescope defends itself

The README section "Security of rulescope itself" describes the defenses. `tests/test_fuzz.py` and the
hostile-input tests in `tests/test_rulescope.py` check them on every change.
