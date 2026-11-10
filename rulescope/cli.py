"""Command-line entry point.

  rulescope cert    --host 192.168.1.99      (certificate fingerprint for --pin-sha256)
  rulescope audit   --host 192.168.1.99 --token-file ~/.rulescope-token --pin-sha256 <fp> --html report.html
  rulescope audit   --config backup.conf --usage hits.csv --html report.html --csv findings.csv
  rulescope collect --host 192.168.1.99 --token-file ~/.rulescope-token --pin-sha256 <fp> --diff
  rulescope analyze snapshots/FGT/20261031-230000.json --baseline snapshots/FGT/20261001-230000.json --html r.html
  rulescope diff    --dir snapshots/FGT --html changes.html
  rulescope fleet   --inventory fleet.ini --out /var/www/rulescope --snapshots /var/lib/rulescope/snapshots
  rulescope firmware 7.4.3 7.2.10 --advisories online     (lifecycle and known CVEs for any version; fills the cache)
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import __version__, checks, diff, firmware, fleet, notify, report, source
from .api import ApiError, cert_fingerprint
from .catalog import SEVERITY_ORDER
from .redact import redact
from .safety import clean_tree, write_restricted
from .ui import PALETTES


def _snapshot_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    token = None
    if not getattr(args, "config", None):
        if args.token:
            print("warning: --token leaves the token in shell history; prefer --token-file or RULESCOPE_TOKEN.",
                  file=sys.stderr)
        token = source.read_token(args.token_file, None, args.token)
        if args.insecure and not args.pin_sha256:
            print("warning: --insecure disables certificate checks; anyone on the network path can capture the API "
                  "token. Use --pin-sha256 (get it with: rulescope cert --host ...) or --ca-file.", file=sys.stderr)
    try:
        return source.take_snapshot(host=args.host, config=getattr(args, "config", None), port=args.port,
                                    vdom=args.vdom, token=token, insecure=args.insecure, ca_file=args.ca_file,
                                    pin_sha256=args.pin_sha256,
                                    timeout=args.timeout, with_backup=not args.no_backup,
                                    with_events=not args.no_events, usage=getattr(args, "usage", None),
                                    usage_since=getattr(args, "usage_since", None))
    except ApiError as e:
        raise SystemExit(f"API error: {e}")
    except (ConnectionError, ValueError, OSError) as e:
        raise SystemExit(str(e))


def _split(v: Optional[str]) -> List[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def apply_wan(snap: Dict[str, Any], wan: Optional[str], not_wan: Optional[str]) -> None:
    """Manual internet-facing interface list; stored in the snapshot so later diffs agree."""
    if wan:
        snap["wan_override"] = _split(wan)
    if not_wan:
        snap["wan_exclude"] = _split(not_wan)


def _add_wan(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("internet-facing interfaces (default: detected)")
    g.add_argument("--wan", help="Comma list of internet-facing interfaces/zones; replaces detection")
    g.add_argument("--not-wan", help="Comma list of interfaces that are NOT internet-facing (e.g. upstream internal links)")


def _advisor(args: argparse.Namespace) -> Optional[firmware.AdvisoryClient]:
    mode = getattr(args, "advisories", "off") or "off"
    if mode == "off":
        return None
    key = None
    if getattr(args, "nvd_api_key_file", None):
        with open(args.nvd_api_key_file, encoding="utf-8") as fh:
            key = fh.read().strip()
    key = key or os.environ.get("NVD_API_KEY")
    return firmware.AdvisoryClient(mode=mode, cache_dir=getattr(args, "cache_dir", None), api_key=key,
                                   timeout=getattr(args, "timeout", 30))


def _lifecycle(args: argparse.Namespace) -> Optional[Dict[str, Any]]:
    path = getattr(args, "lifecycle_file", None)
    if not path:
        return None
    try:
        return firmware.load_lifecycle(path)
    except (OSError, ValueError, KeyError) as e:
        raise SystemExit(f"lifecycle file: {e}")


def _add_firmware(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("firmware advisories")
    g.add_argument("--advisories", choices=["off", "cache", "online"], default="cache",
                   help="Known-vulnerability lookup in the NIST NVD: online (refresh daily), cache (default: use earlier "
                        "results only, no network) or off")
    g.add_argument("--nvd-api-key-file", help="File with an NVD API key (or set NVD_API_KEY); raises the rate limit")
    g.add_argument("--cache-dir", help="Advisory cache folder (default ~/.cache/rulescope/nvd)")
    g.add_argument("--lifecycle-file", help="JSON with FortiOS lifecycle dates that replace the built-in table")


def _write(path: str, text: str) -> None:
    """Reports describe a firewall's weaknesses: never readable by other users on this machine."""
    write_restricted(path, text)
    print(f"wrote {path}")


def _webhook(args: argparse.Namespace) -> Optional[str]:
    """Webhook URLs are secrets: prefer a file or RULESCOPE_WEBHOOK over the command line (visible in ps)."""
    if getattr(args, "webhook", None) and not getattr(args, "webhook_file", None):
        print("warning: --webhook shows the URL in the process list; prefer --webhook-file or RULESCOPE_WEBHOOK.",
              file=sys.stderr)
    try:
        return notify.webhook_url(getattr(args, "webhook", None), getattr(args, "webhook_file", None))
    except (OSError, ValueError) as e:
        raise SystemExit(f"webhook: {e}")


def _add_notify(p: argparse.ArgumentParser) -> None:
    p.add_argument("--webhook", help="POST risky-change alerts to this URL (prefer --webhook-file: the URL is a secret)")
    p.add_argument("--webhook-file", help="File containing the webhook URL (or set RULESCOPE_WEBHOOK)")
    p.add_argument("--syslog", help="Send risky-change alerts to host[:port] via UDP syslog")


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return clean_tree(json.load(fh))


def _outputs(snap: Dict[str, Any], args: argparse.Namespace) -> int:
    apply_wan(snap, args.wan, args.not_wan)
    baseline = None
    if args.baseline:
        b = _load_json(args.baseline)
        baseline = b if "findings" in b else source.load_snapshot(args.baseline)
        if "findings" not in baseline:
            apply_wan(baseline, args.wan, args.not_wan)
    redacted = False
    if args.redact:
        if baseline is not None and "findings" in baseline:
            raise SystemExit("--redact requires a snapshot baseline; findings JSON can contain original identifiers")
        snap, mapping = redact(snap)
        if baseline is not None:
            baseline, mapping = redact(baseline, mapping)
        redacted = True
        if args.redact_map:
            write_restricted(args.redact_map, json.dumps(mapping, indent=1, ensure_ascii=False), 0o600)
            print(f"wrote {args.redact_map}")
    adv_client = _advisor(args)
    adv = adv_client.lookup(snap["device"].get("version")) if adv_client else None
    result = checks.analyze(snap, stale_days=args.stale_days, baseline=baseline, advisories=adv,
                            lifecycle_table=_lifecycle(args))
    print(report.console_summary(result))
    print()
    if args.html:
        _write(args.html, report.html_report(result, snap, client=args.client, auditor=args.auditor, redacted=redacted,
                                             palette=args.palette))
    if args.json:
        _write(args.json, json.dumps(result, indent=1, ensure_ascii=False))
    if args.csv:
        _write(args.csv, report.findings_csv(result))
    if args.practices_csv:
        _write(args.practices_csv, report.practices_csv(result))
    if args.cli:
        _write(args.cli, report.remediation_cli(result))
    if args.fail_on:
        limit = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f["severity"]] <= limit for f in result["findings"]):
            return 2
    return 0


def _add_source(p: argparse.ArgumentParser, allow_config: bool = True) -> None:
    g = p.add_argument_group("source")
    g.add_argument("--host", help="FortiGate address, optionally host:port")
    if allow_config:
        g.add_argument("--config", help="Config backup file for offline analysis")
    g.add_argument("--port", type=int, default=443)
    g.add_argument("--vdom", default="root")
    g.add_argument("--token-file", help="File containing the REST API token")
    g.add_argument("--token", help="API token (prefer --token-file or RULESCOPE_TOKEN)")
    g.add_argument("--pin-sha256", help="Accept only the certificate with this SHA-256 fingerprint (self-signed "
                                        "FortiGate certificates; get it with: rulescope cert --host ...)")
    g.add_argument("--ca-file", help="CA bundle to verify the FortiGate certificate")
    g.add_argument("--insecure", action="store_true",
                   help="Skip TLS verification entirely (lab only: the token can be captured on the network)")
    g.add_argument("--timeout", type=int, default=30)
    g.add_argument("--no-backup", action="store_true", help="Do not read the config backup for reference counts")
    g.add_argument("--no-events", action="store_true", help="Do not read config-change events from the log")


def _add_usage(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("usage data")
    g.add_argument("--usage", help="Hit counts from CSV / FortiGate JSON / OpenSearch aggregation (see README)")
    g.add_argument("--usage-since", help="Start of the period the usage data covers (YYYY-MM-DD)")


def _add_outputs(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("output")
    g.add_argument("--html", help="Write the HTML audit report here")
    g.add_argument("--json", help="Write findings as JSON here")
    g.add_argument("--csv", help="Write findings as CSV (Excel-friendly) here")
    g.add_argument("--cli", help="Write the FortiOS remediation script here")
    g.add_argument("--practices-csv", help="Write the best-practice baseline (status and evidence) as CSV here")
    g.add_argument("--palette", choices=list(PALETTES), default="harbor",
                   help="Default color palette of the HTML report (readers can switch; light and dark each)")
    g.add_argument("--client", default="", help="Client name shown on the report")
    g.add_argument("--auditor", default="", help="Auditor name shown on the report")
    g.add_argument("--stale-days", type=int, default=90)
    g.add_argument("--baseline", help="Earlier snapshot or findings JSON: adds a 'progress since' section")
    g.add_argument("--redact", action="store_true", help="Pseudonymize names, IPs, hostname and serial in all outputs")
    g.add_argument("--redact-map", help="With --redact: write the pseudonym mapping here (keep it private)")
    g.add_argument("--fail-on", choices=["high", "medium", "low", "info"],
                   help="Exit 2 if any finding at or above this severity (for CI/cron)")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="rulescope", description="FortiGate rule base audit and change tracking.")
    ap.add_argument("--version", action="version", version=f"rulescope {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="Collect (API or backup file) and analyze in one step")
    _add_source(a)
    _add_usage(a)
    _add_wan(a)
    _add_outputs(a)
    _add_firmware(a)
    a.add_argument("--save-snapshot", metavar="DIR", help="Also store the snapshot for change tracking")

    c = sub.add_parser("collect", help="Take a snapshot for later analysis or diffing")
    _add_source(c)
    _add_usage(c)
    _add_wan(c)
    c.add_argument("--out", default="snapshots", help="Snapshot directory (default: ./snapshots)")
    c.add_argument("--diff", action="store_true", help="Print changes since the previous snapshot")
    _add_notify(c)

    n = sub.add_parser("analyze", help="Analyze a saved snapshot")
    n.add_argument("snapshot")
    _add_usage(n)
    _add_wan(n)
    _add_outputs(n)
    _add_firmware(n)

    d = sub.add_parser("diff", help="Show changes between two snapshots")
    d.add_argument("old", nargs="?")
    d.add_argument("new", nargs="?")
    d.add_argument("--dir", help="Diff the latest two snapshots in this directory")
    d.add_argument("--html", help="Write an HTML change report here")
    d.add_argument("--json", help="Write the diff as JSON here")
    d.add_argument("--palette", choices=list(PALETTES), default="harbor", help="Default color palette of the page")

    f = sub.add_parser("fleet", help="Audit every device in an inventory and build a dashboard")
    f.add_argument("--inventory", required=True, help="INI file listing devices (see README)")
    f.add_argument("--out", default="site", help="Output folder for the dashboard and reports")
    f.add_argument("--snapshots", default="snapshots", help="Snapshot folder (history for diffs and trends)")
    f.add_argument("--workers", type=int, default=6)
    f.add_argument("--stale-days", type=int, default=90)
    f.add_argument("--baseline-days", type=int, default=30, help="Compare each report with a snapshot this old")
    f.add_argument("--auditor", default="")
    _add_notify(f)
    f.add_argument("--palette", choices=list(PALETTES), default="harbor", help="Default color palette of the pages")
    _add_firmware(f)

    ce = sub.add_parser("cert", help="Show the SHA-256 fingerprint of a FortiGate's certificate, for --pin-sha256")
    ce.add_argument("--host", required=True, help="FortiGate address, optionally host:port")
    ce.add_argument("--port", type=int, default=443)
    ce.add_argument("--timeout", type=int, default=10)

    fw = sub.add_parser("firmware", help="Lifecycle and known vulnerabilities of FortiOS versions (fills the advisory cache)")
    fw.add_argument("versions", nargs="+", help="FortiOS versions, e.g. 7.4.3 7.2.10")
    fw.add_argument("--timeout", type=int, default=30)
    fw.add_argument("--json", help="Write the results as JSON here")
    _add_firmware(fw)

    args = ap.parse_args(argv)

    if getattr(args, "redact", False) and getattr(args, "save_snapshot", None):
        ap.error("--redact cannot be combined with --save-snapshot; use collect separately to save a private snapshot")

    if args.cmd == "audit":
        snap = _snapshot_from_args(args)
        apply_wan(snap, args.wan, args.not_wan)
        if args.save_snapshot:
            saved = source.save_snapshot(snap, args.save_snapshot)
            print(f"snapshot {saved}")
            source.prune(os.path.dirname(saved))
        return _outputs(snap, args)

    if args.cmd == "collect":
        hook = _webhook(args)
        snap = _snapshot_from_args(args)
        apply_wan(snap, args.wan, args.not_wan)
        path = source.save_snapshot(snap, args.out)
        print(f"snapshot {path}")
        sdir = os.path.dirname(path)
        files = source.list_snapshots(sdir)
        rc = 0
        if args.diff or hook or args.syslog:
            alerts: List[str] = []
            changes = 0
            if len(files) < 2:
                print("no previous snapshot to compare")
            else:
                res = diff.diff_snapshots(source.load_snapshot(files[-2]), snap)
                if args.diff:
                    print(diff.render_text(res))
                alerts = res["alerts"]
                changes = len(res["objects"]) + sum(map(len, res["policies"].values()))
            if hook or args.syslog:
                dev = snap["device"].get("hostname") or "fortigate"

                def send(todo: List[str]) -> None:
                    if hook:
                        notify.webhook(hook, dev, todo, changes)
                    if args.syslog:
                        notify.syslog(args.syslog, dev, todo)

                # not a .json name: every *.json in this folder is a snapshot
                err = notify.deliver(os.path.join(sdir, "pending-alerts.list"), send, alerts)
                if err:
                    print(f"warning: alerts not delivered ({err}); they are kept and sent with the next run",
                          file=sys.stderr)
                    rc = 4
        source.prune(sdir)  # hourly snapshots would otherwise grow without limit
        return rc

    if args.cmd == "analyze":
        try:
            snap = source.load_snapshot(args.snapshot)
        except ValueError as e:
            raise SystemExit(f"{args.snapshot}: {e}")
        if args.usage:
            from . import usage as usage_mod
            usage_mod.apply(snap, usage_mod.load(args.usage), args.usage,
                            usage_mod.to_epoch(args.usage_since) if args.usage_since else None)
            args.usage = None
        return _outputs(snap, args)

    if args.cmd == "diff":
        if args.dir:
            old_p, new_p = diff.latest_two(args.dir)
        elif args.old and args.new:
            old_p, new_p = args.old, args.new
        else:
            raise SystemExit("Give two snapshot files or --dir.")
        res = diff.diff_snapshots(source.load_snapshot(old_p), source.load_snapshot(new_p))
        print(diff.render_text(res))
        if args.html:
            _write(args.html, diff.render_html(res, args.palette))
        if args.json:
            _write(args.json, json.dumps(res, indent=1, ensure_ascii=False))
        return 1 if not res["empty"] else 0

    if args.cmd == "fleet":
        try:
            devices = fleet.load_inventory(args.inventory)
        except (OSError, ValueError) as e:
            raise SystemExit(f"inventory: {e}")
        summary = fleet.run(devices, args.out, args.snapshots, workers=args.workers, stale_days=args.stale_days,
                            baseline_days=args.baseline_days, auditor=args.auditor, webhook=_webhook(args),
                            syslog_target=args.syslog, advisor=_advisor(args), lifecycle=_lifecycle(args),
                            palette=args.palette)
        for r in summary["devices"]:
            if r["status"] == "ok":
                print(f"{r['name']:24} {r['grade']} {r['score']:3d}  high={r['sev']['high']} "
                      f"changes={r.get('changes', 0)} alerts={len(r.get('alerts', []))}")
            else:
                print(f"{r['name']:24} ERROR {r.get('error')}")
            if r.get("notify_error"):
                print(f"{r['name']:24} warning: alerts not delivered ({r['notify_error']}); kept for the next run",
                      file=sys.stderr)
        print(f"wrote {os.path.join(args.out, 'index.html')}")
        if any(r["status"] != "ok" for r in summary["devices"]):
            return 3
        return 4 if any(r.get("notify_error") for r in summary["devices"]) else 0

    if args.cmd == "cert":
        h, p = source.split_host_port(args.host, args.port)
        try:
            fp = cert_fingerprint(h, p, args.timeout)
        except OSError as e:
            raise SystemExit(f"Cannot reach {h}:{p}: {e}")
        print(f"SHA-256 fingerprint of the certificate at {h}:{p}:\n{fp}\n")
        print("Check it before trusting it: run this from a network path you trust (for example the management VLAN),")
        print("or compare with: openssl s_client -connect HOST:PORT </dev/null | openssl x509 -noout -fingerprint -sha256")
        print(f"Then use: --pin-sha256 {fp}")
        return 0

    if args.cmd == "firmware":
        client = _advisor(args)
        table = _lifecycle(args)
        today = _dt.date.today().isoformat()
        out = []
        for v in args.versions:
            fake = {"collected_at": today + "T00:00:00+00:00", "device": {"version": v}}
            fw_sum = firmware.summarize(fake, client.lookup(v) if client else None, table)
            out.append(fw_sum)
            lc, adv = fw_sum["lifecycle"], fw_sum["advisories"]
            print(f"FortiOS {lc['version'] or v}: branch {lc['branch'] or '?'}, status {lc['status']}"
                  + (f", engineering support until {lc['eoes']}, support until {lc['eos']}" if lc.get("eos") else ""))
            if adv.get("checked"):
                c = adv["counts"]
                print(f"  {c['total']} CVEs: {c['kev']} actively exploited (CISA KEV), {c['critical']} critical, {c['high']} high"
                      + (" [cache]" if adv.get("from_cache") else ""))
                for cv in adv["cves"][:15]:
                    print(f"  {'KEV ' if cv.get('kev') else '    '}{cv['id']:16} {cv.get('cvss') or '-':>4}  {cv.get('title', '')[:90]}")
                if len(adv["cves"]) > 15:
                    print(f"  ... {len(adv['cves']) - 15} more")
            elif adv.get("error"):
                print(f"  advisories: {adv['error']}")
        if args.json:
            _write(args.json, json.dumps(out, indent=1))
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
