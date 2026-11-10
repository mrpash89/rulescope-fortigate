"""Read-only FortiOS REST API collector (stdlib only, no requests dependency).

Use a REST API admin bound to a read-only admin profile and restricted to the
auditor's IP with trusted hosts. Nothing here ever writes to the device.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import http.client
import json
import re
import socket
import ssl
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from .usage import to_epoch


class ApiError(Exception):
    def __init__(self, status: int, path: str, detail: str = ""):
        self.status, self.path = status, path
        hint = {
            401: "token rejected - check the token and that this machine's IP is in the API user's trusted hosts",
            403: "token lacks permission for this object",
            404: "endpoint not available on this FortiOS version",
            405: "method not allowed on this FortiOS version",
        }.get(status, "")
        super().__init__(f"HTTP {status} on {path}" + (f": {hint}" if hint else "") + (f" ({detail})" if detail else ""))


_SECRET_RE = re.compile(r"([\w.-]*(?:passw|passphrase|pwd|psk|secret|key|token|private|community)[\w.-]*)\[[^\]]*\]",
                        re.I)


def _sanitize(s: Any, limit: int) -> str:
    s = _SECRET_RE.sub(r"\1[***]", str(s or ""))
    return s if len(s) <= limit else s[:limit - 3] + "..."


def _event_time(e: Dict[str, Any]) -> int:
    for k in ("eventtime", "itime"):
        if e.get(k):
            try:
                return to_epoch(e[k])
            except ValueError:
                pass
    date, tm, tz = e.get("date"), e.get("time"), str(e.get("tz") or "+0000")
    if date and tm:
        if re.fullmatch(r"[+-]\d{4}", tz):
            tz = tz[:3] + ":" + tz[3:]
        try:
            return int(_dt.datetime.fromisoformat(f"{date}T{tm}{tz}").timestamp())
        except ValueError:
            return 0
    return 0


def normalize_event(e: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "time": _event_time(e), "user": str(e.get("user", "")), "ui": str(e.get("ui", "")),
        "action": str(e.get("action", "")), "cfgpath": str(e.get("cfgpath", "")), "cfgobj": str(e.get("cfgobj", "")),
        "cfgattr": _sanitize(e.get("cfgattr", ""), 400), "msg": _sanitize(e.get("msg", ""), 300),
    }


class CertificatePinError(ConnectionError):
    pass


def normalize_pin(pin: str) -> str:
    """'AB:CD:...' or 'abcd...' -> 64 lowercase hex characters."""
    p = re.sub(r"[\s:]", "", pin or "").lower()
    if p.startswith("sha256/") or p.startswith("sha256:"):
        p = p[7:]
    if not re.fullmatch(r"[0-9a-f]{64}", p):
        raise ValueError("--pin-sha256 must be the 64-hex-digit SHA-256 fingerprint of the FortiGate certificate")
    return p


def cert_fingerprint(host: str, port: int = 443, timeout: int = 10) -> str:
    """SHA-256 fingerprint of the certificate the device presents (for --pin-sha256)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


class FortiGateAPI:
    """verify=True checks the certificate against the system CAs (or ca_file); pin_sha256 instead accepts
    exactly one certificate, checked on every connection before the token is sent; verify=False and no pin
    disables checking (only for a lab: anyone on the path could capture the token)."""

    def __init__(self, host: str, token: str, port: int = 443, vdom: str = "root",
                 verify: bool = True, ca_file: Optional[str] = None, timeout: int = 30,
                 pin_sha256: Optional[str] = None):
        self.base = f"https://{host}:{port}"
        self.token, self.vdom, self.timeout = token, vdom, timeout
        self.pin = normalize_pin(pin_sha256) if pin_sha256 else None
        if verify and not self.pin:
            self.ctx = ssl.create_default_context(cafile=ca_file)
        else:
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def _connect(self) -> http.client.HTTPConnection:
        u = urllib.parse.urlsplit(self.base)
        if u.scheme == "http":  # only used by the test suite
            conn: http.client.HTTPConnection = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=self.timeout)
            conn.connect()
            return conn
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=self.timeout, context=self.ctx)
        conn.connect()
        if self.pin:
            der = conn.sock.getpeercert(binary_form=True)  # type: ignore[union-attr]
            got = hashlib.sha256(der or b"").hexdigest()
            if got != self.pin:
                conn.close()
                raise CertificatePinError(f"{self.base} presented certificate SHA-256 {got}, expected {self.pin}. "
                                          "The token was not sent. If the certificate was replaced on purpose, "
                                          "update --pin-sha256 (rulescope cert --host ...).")
        return conn

    def _request(self, method: str, path: str, params: Optional[Dict[str, str]] = None,
                 body: Optional[Dict[str, Any]] = None, raw: bool = False) -> Any:
        target = f"/api/v2/{path}" + ("?" + urllib.parse.urlencode(params) if params else "")
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        try:
            conn = self._connect()
        except CertificatePinError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as e:
            raise ConnectionError(f"Cannot reach {self.base}: {e}") from None
        try:
            conn.request(method, target, body=data, headers=headers)
            r = conn.getresponse()
            payload = r.read()
        except (OSError, http.client.HTTPException) as e:
            raise ConnectionError(f"Cannot reach {self.base}: {e}") from None
        finally:
            conn.close()
        if r.status >= 300:
            raise ApiError(r.status, path, payload[:200].decode(errors="replace").strip())
        if raw:
            return payload.decode(errors="replace")
        return json.loads(payload)

    def get(self, path: str, vdom_scoped: bool = True, **params: str) -> Any:
        if vdom_scoped:
            params.setdefault("vdom", self.vdom)
        return self._request("GET", path, params)

    def backup(self) -> Optional[str]:
        """Full config text, used only in memory for reference counting. Endpoint differs by version."""
        attempts = [
            ("GET", {"scope": "global"}, None),
            ("POST", None, {"destination": "file", "scope": "global"}),
            ("POST", None, {"scope": "global"}),
        ]
        for method, params, body in attempts:
            try:
                text = self._request(method, "monitor/system/config/backup", params, body, raw=True)
            except ApiError:
                continue
            if "config system global" in text or text.lstrip().startswith("#config-version"):
                return text
        return None

    def config_events(self, rows: int = 1000) -> Tuple[Optional[List[Dict[str, Any]]], str]:
        """Configuration-change events (who changed what) from the system event log: disk first, then memory."""
        last_err = ""
        for source in ("disk", "memory"):
            path = f"log/{source}/event/system"
            params = {"rows": str(rows), "vdom": self.vdom}
            try:
                resp = self._request("GET", path, params)
                tries = 0
                while (isinstance(resp, dict) and resp.get("session_id") and tries < 10
                       and float(resp.get("completed", 100) or 100) < 100):
                    time.sleep(0.5)
                    tries += 1
                    resp = self._request("GET", path, {**params, "session_id": str(resp["session_id"])})
            except ApiError as e:
                last_err = str(e)
                continue
            results = resp.get("results", []) if isinstance(resp, dict) else []
            events = [normalize_event(e) for e in results if isinstance(e, dict) and e.get("cfgpath")]
            if events or source == "memory":
                events.sort(key=lambda e: e["time"], reverse=True)
                return events[:500], source
        return None, last_err

    def collect_raw(self, with_backup: bool = True, with_events: bool = True) -> Dict[str, Any]:
        """Pull everything the analyzer needs. Optional objects that fail are recorded, not fatal."""
        out: Dict[str, Any] = {"errors": []}
        out["status"] = self.get("monitor/system/status")      # fail fast on auth problems
        out["policy"] = self.get("cmdb/firewall/policy")

        optional = {
            "global": ("cmdb/system/global", False, False),
            "address": ("cmdb/firewall/address", True, True),
            "addrgrp": ("cmdb/firewall/addrgrp", True, True),
            "service_custom": ("cmdb/firewall.service/custom", True, True),
            "service_group": ("cmdb/firewall.service/group", True, True),
            "vip": ("cmdb/firewall/vip", True, True),
            "vipgrp": ("cmdb/firewall/vipgrp", True, True),
            "zone": ("cmdb/system/zone", True, False),
            "sdwan": ("cmdb/system/sdwan", True, False),
            "interface": ("cmdb/system/interface", False, False),
            "admin": ("cmdb/system/admin", False, False),
            "api_user": ("cmdb/system/api-user", False, False),
            "sched_onetime": ("cmdb/firewall.schedule/onetime", True, False),
            "sched_group": ("cmdb/firewall.schedule/group", True, False),
            "vpn_ssl": ("cmdb/vpn.ssl/settings", True, False),
            "phase1": ("cmdb/vpn.ipsec/phase1-interface", True, False),
            "phase2": ("cmdb/vpn.ipsec/phase2-interface", True, False),
            "local_in": ("cmdb/firewall/local-in-policy", True, False),
            "router_static": ("cmdb/router/static", True, False),
            "policy_stats": ("monitor/firewall/policy", True, False),
            "webui_state": ("monitor/web-ui/state", False, False),
        }
        quiet = {"admin", "api_user", "webui_state", "sdwan", "sched_onetime", "sched_group", "phase2"}
        exposure_inputs = {"vpn_ssl", "phase1", "local_in", "router_static"}
        for key, (path, scoped, meta) in optional.items():
            try:
                out[key] = self.get(path, vdom_scoped=scoped, **({"with_meta": "1"} if meta else {}))
            except ApiError as e:
                out[key] = None
                if key in exposure_inputs:
                    out["errors"].append(f"Could not read {path} ({e.status}); exposure checks may be incomplete.")
                elif key not in quiet:
                    out["errors"].append(str(e))

        # hardening settings for the best-practice checks; unreadable ones stay None (reported once as a note)
        from .model import API_SETTING_PATHS
        out["cfg"] = {}
        for cpath, (path, scoped) in API_SETTING_PATHS.items():
            try:
                out["cfg"][cpath] = self.get(path, vdom_scoped=scoped)
            except ApiError:
                out["cfg"][cpath] = None
        try:
            out["license"] = self.get("monitor/license/status", vdom_scoped=False)
        except ApiError:
            out["license"] = None

        have_qref = all(
            all("q_ref" in row for row in ((out.get(k) or {}).get("results") or []))
            for k in ("address", "addrgrp", "service_custom", "service_group", "vip", "vipgrp"))
        out["backup_text"] = self.backup() if (with_backup and not have_qref) else None
        if with_events:
            events, info = self.config_events()
            out["config_events"] = events
            if events is None:
                out["errors"].append(f"Config change log not readable ({info}); change attribution unavailable.")
        return out
