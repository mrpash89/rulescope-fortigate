"""Change notifications: generic JSON webhook (Slack/Mattermost/Teams-workflow style 'text') and syslog."""
from __future__ import annotations

import datetime as _dt
import json
import socket
import urllib.request
from typing import Any, Dict, List, Optional

from .safety import clean


def webhook(url: str, device: str, alerts: List[str], changes: int, report_link: Optional[str] = None,
            timeout: int = 10) -> None:
    device, alerts = clean(device), [clean(a) for a in alerts]
    text = f"rulescope: {len(alerts)} risky change(s) on {device}\n" + "\n".join(f"- {a}" for a in alerts)
    if report_link:
        text += f"\n{report_link}"
    payload: Dict[str, Any] = {"text": text, "device": device, "alerts": alerts, "changes": changes}
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        r.read()


def syslog(target: str, device: str, alerts: List[str]) -> None:
    """RFC 5424 over UDP, facility local0, severity warning. target = host, host:port, IPv6 or [IPv6]:port."""
    from .source import split_host_port
    host, port = split_host_port(target, 514)
    family, _, _, _, addr = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
    ts = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    me = socket.gethostname()
    device = clean(device).replace(" ", "_")
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        for a in alerts:
            a = clean(a).replace(chr(34), chr(39))  # one alert = one syslog line, no forged lines
            msg = f"<132>1 {ts} {me} rulescope - change - device={device} alert=\"{a}\""
            s.sendto(msg.encode()[:2048], addr)
