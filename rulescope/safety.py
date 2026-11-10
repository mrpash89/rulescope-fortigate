"""Defenses for untrusted input.

Configs, API data and snapshots can come from anyone (a client emails a backup). Every name,
comment and value in them is untrusted and ends up in places that act on it: a FortiOS script
someone pastes onto a firewall, a spreadsheet, a terminal, syslog, an HTML page, a file path.

The rule: control characters never survive input (parser, API data, loaded JSON), and every
output re-checks for its own kind of injection (script lines, CSV formulas, URL schemes).
"""
from __future__ import annotations

import os
import re
import tempfile
import unicodedata
from typing import Any

# Line breaks and tabs become spaces; every other C0/C1 control, DEL and the Unicode
# direction/line-separator characters (used to make text display differently than it reads)
# become "?" so tampering stays visible.
_WS = re.compile(r"[\t\n\r\x0b\x0c\u2028\u2029\x85]")
_CTRL = re.compile(r"[\x00-\x08\x0e-\x1f\x7f-\x84\x86-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


# Unicode categories that never show as a character of their own: controls, format characters
# (direction marks, zero-width characters, soft hyphen, byte order mark) and line/paragraph separators.
_INVISIBLE = ("Cc", "Cf", "Zl", "Zp")


def _visible(s: str) -> str:
    """Replace every remaining invisible character. The list in _CTRL covers the common ones fast;
    this covers all of them, for whatever Unicode version this Python knows."""
    if s.isascii():
        return s
    return "".join("?" if unicodedata.category(c) in _INVISIBLE else c for c in s)


def clean(s: Any) -> Any:
    """One-line safe text. Non-strings are returned unchanged."""
    if not isinstance(s, str):
        return s
    return _visible(_CTRL.sub("?", _WS.sub(" ", s)))


def clean_tree(obj: Any) -> Any:
    """clean() every string (keys too) in nested dicts and lists."""
    if isinstance(obj, str):
        return clean(obj)
    if isinstance(obj, dict):
        return {clean(k): clean_tree(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [clean_tree(v) for v in obj]
    return obj


def clean_multiline(s: str) -> str:
    """Terminal output: keeps line breaks we produced, removes escape codes and other controls."""
    return "\n".join(_visible(_CTRL.sub("?", re.sub(r"[\t\r\x0b\x0c\u2028\u2029\x85]", " ", ln)))
                     for ln in s.split("\n"))


def csv_cell(v: Any) -> Any:
    """Stop spreadsheet formula injection: text that starts like a formula is prefixed with '."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r", "|", "%"):
        return "'" + v
    return v


def safe_url(u: Any) -> str:
    """Only https links go into reports."""
    return u if isinstance(u, str) and u.lower().startswith("https://") and not _CTRL.search(u) else ""


def write_restricted(path: str, text: str, mode: int = 0o640) -> None:
    """Atomic write; the file is never readable by other users (reports describe weaknesses)."""
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".rulescope-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def makedirs_restricted(path: str) -> None:
    os.makedirs(path, mode=0o750, exist_ok=True)
