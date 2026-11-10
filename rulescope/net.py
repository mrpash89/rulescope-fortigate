"""HTTP plumbing shared by the FortiGate collector, the NVD client and the webhook (stdlib only).

Two rules apply to every request rulescope sends:

* Redirects are never followed. urllib would repeat the request, including the API token or key
  header, against whatever host the answer names, even over plain HTTP.
* A FortiGate with a self-signed certificate can be pinned by the SHA-256 fingerprint of that
  certificate instead of switching verification off.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import re
import ssl
import urllib.request
from typing import Any, Optional


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None  # the caller then gets the 3xx answer as an HTTPError


def normalize_pin(pin: str) -> str:
    """'AB:CD:..', 'SHA256 Fingerprint=AB:CD:..', 'sha256/abcd..' or plain hex -> 64 lowercase hex digits."""
    text = (pin or "").strip().rsplit("=", 1)[-1].strip().lower()
    for prefix in ("sha256/", "sha256:"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    digits = re.sub(r"[\s:]", "", text)
    if not re.fullmatch(r"[0-9a-f]{64}", digits):
        raise ValueError("certificate pin must be the SHA-256 fingerprint of the certificate (64 hex digits); "
                         "get it with: rulescope cert --host ...")
    return digits


class PinMismatch(OSError):
    """The peer's certificate is not the pinned one."""


class _PinnedConnection(http.client.HTTPSConnection):
    pin = ""

    def connect(self) -> None:
        super().connect()
        der = self.sock.getpeercert(binary_form=True) or b""
        got = hashlib.sha256(der).hexdigest()
        if not hmac.compare_digest(got, self.pin):
            self.close()  # nothing has been sent yet: the token never reaches an unexpected peer
            raise PinMismatch(f"certificate does not match the pinned fingerprint (peer presented sha256 {got})")


class _PinnedHandler(urllib.request.HTTPSHandler):
    def __init__(self, context: ssl.SSLContext, pin: str):
        super().__init__(context=context)
        self._pin_ctx, self._pin = context, pin

    def https_open(self, req: Any) -> Any:
        pin = self._pin

        def factory(host: str, **kw: Any) -> _PinnedConnection:
            conn = _PinnedConnection(host, **kw)
            conn.pin = pin
            return conn

        return self.do_open(factory, req, context=self._pin_ctx)


def unverified_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def build_opener(context: Optional[ssl.SSLContext] = None, pin: Optional[str] = None) -> urllib.request.OpenerDirector:
    """An opener that never follows redirects. `pin` (normalized) checks the peer certificate's
    fingerprint on every connection; `context` is then only used to speak TLS."""
    handlers: list = [NoRedirect()]
    if pin:
        handlers.append(_PinnedHandler(context or unverified_context(), pin))
    elif context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def https_only(url: Any) -> str:
    """The URL if it is a plain https link, else ''. Used before a URL from fetched data becomes a link."""
    s = str(url or "")
    return s if s.lower().startswith("https://") and not any(c.isspace() for c in s) else ""
