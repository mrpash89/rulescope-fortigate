"""Snapshot acquisition and storage, shared by the CLI and fleet mode."""
from __future__ import annotations

import datetime as _dt
import glob
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from . import model
from . import usage as usage_mod
from .api import FortiGateAPI
from .safety import clean_tree, write_restricted


def split_host_port(host: str, port: int) -> Tuple[str, int]:
    """host, host:port, IPv6, [IPv6] or [IPv6]:port -> (host without brackets, port)."""
    m = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", host)
    if m:
        return m.group(1), int(m.group(2)) if m.group(2) else port
    m = re.fullmatch(r"(.+):(\d+)", host)
    if m and host.count(":") == 1:
        return m.group(1), int(m.group(2))
    return host, port


def write_private(path: str, text: str) -> None:
    """Write a file that only the owner can read, with no window where it is readable by others."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)  # an existing file keeps its old mode on O_CREAT; tighten it before writing
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def read_token(token_file: Optional[str] = None, token_env: Optional[str] = None,
               token: Optional[str] = None) -> Optional[str]:
    if token_file:
        with open(token_file, encoding="utf-8") as fh:
            return fh.read().strip()
    if token_env:
        return os.environ.get(token_env)
    return token or os.environ.get("RULESCOPE_TOKEN")


def take_snapshot(*, host: Optional[str] = None, config: Optional[str] = None, port: int = 443,
                  vdom: str = "root", token: Optional[str] = None, insecure: bool = False,
                  ca_file: Optional[str] = None, timeout: int = 30, with_backup: bool = True,
                  pin_sha256: Optional[str] = None,
                  with_events: bool = True, usage: Optional[str] = None,
                  usage_since: Optional[str] = None) -> Dict[str, Any]:
    if config:
        with open(config, encoding="utf-8", errors="replace") as fh:
            snap = model.from_config(fh.read(), vdom=vdom)
    else:
        if not host:
            raise ValueError("give a host (live API) or a config backup file")
        if not token:
            raise ValueError("no API token (token file, token environment variable or RULESCOPE_TOKEN)")
        h, p = split_host_port(host, port)
        api = FortiGateAPI(h, token, port=p, vdom=vdom, verify=not insecure, ca_file=ca_file, timeout=timeout,
                           pin_sha256=pin_sha256)
        snap = model.from_api(api.collect_raw(with_backup=with_backup, with_events=with_events), vdom=vdom)
    if usage:
        since = usage_mod.to_epoch(usage_since) if usage_since else None
        usage_mod.apply(snap, usage_mod.load(usage), usage, since)
    return snap


def safe_name(s: str) -> str:
    """A file or folder name from untrusted text: no separators, no leading dots ('..', hidden files)."""
    name = re.sub(r"[^A-Za-z0-9._-]", "_", s or "").lstrip(".")[:100]
    return name or "fortigate"


def device_dir(snap: Dict[str, Any], base: str, name: Optional[str] = None) -> str:
    if name:
        return os.path.join(base, safe_name(name))
    host = safe_name(snap["device"].get("hostname") or "fortigate")
    vd = snap["device"].get("vdom", "root")
    return os.path.join(base, host if vd == "root" else f"{host}_{safe_name(vd)}")


def save_snapshot(snap: Dict[str, Any], base: str, name: Optional[str] = None) -> str:
    d = device_dir(snap, base, name)
    os.makedirs(d, mode=0o700, exist_ok=True)
    while True:  # millisecond stamps keep names unique and in chronological sort order
        # UTC, so names keep sorting chronologically when local clocks go back (DST)
        stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d-%H%M%S-%f")[:-3]
        path = os.path.join(d, f"{stamp}.json")
        if not os.path.exists(path):
            break
    write_restricted(path, json.dumps(snap, indent=1, sort_keys=True), 0o600)
    return path


def load_snapshot(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return model.upgrade(clean_tree(json.load(fh)))


def list_snapshots(directory: str) -> List[str]:
    return sorted(glob.glob(os.path.join(directory, "*.json")))


def _stamp_epoch(path: str) -> Optional[float]:
    try:
        return (_dt.datetime.strptime(os.path.basename(path)[:15], "%Y%m%d-%H%M%S")
                .replace(tzinfo=_dt.timezone.utc).timestamp())
    except ValueError:
        return None


def pick_baseline(directory: str, current: str, min_age_days: int) -> Optional[str]:
    """Most recent snapshot at least min_age_days older than `current`; else the oldest one.
    Ages come from file names, so no snapshot has to be parsed."""
    files = [f for f in list_snapshots(directory) if f != current]
    if not files:
        return None
    cur = _stamp_epoch(current)
    if cur is None:
        return files[0]
    cutoff = cur - min_age_days * 86400
    best = None
    for f in files:
        t = _stamp_epoch(f)
        if t is not None and t <= cutoff:
            best = f
    return best or files[0]


def prune(directory: str, keep_last: int = 48, keep_daily_days: int = 400) -> int:
    """Keep the newest `keep_last` snapshots, then one per day for `keep_daily_days`. Returns files removed."""
    files = list_snapshots(directory)
    keep = set(files[-keep_last:])
    seen_days = set()
    now = _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)
    removed = 0
    for f in reversed(files):
        if f in keep:
            continue
        day = os.path.basename(f)[:8]
        try:
            age = (now - _dt.datetime.strptime(day, "%Y%m%d")).days
        except ValueError:
            continue
        if day not in seen_days and age <= keep_daily_days:
            seen_days.add(day)
            continue
        os.remove(f)
        removed += 1
    return removed
