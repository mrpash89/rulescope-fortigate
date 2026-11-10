"""Parser for FortiOS configuration backups (the `config / edit / set / next / end` format).

Handles quoted strings with escapes, values that span several lines (certificates,
replacement messages), nested `config` blocks inside entries, and multi-VDOM
backups where `config vdom` appears several times and must be merged.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

from .safety import clean

_TOKEN_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|([^\s"]+)|(\n)', re.DOTALL)
_UNESCAPE_RE = re.compile(r"\\(.)", re.DOTALL)
_HEADER_RE = re.compile(r"#config-version=([A-Za-z0-9]+)-(\d+\.\d+\.\d+)-FW-build(\d+)")


@dataclass
class Block:
    settings: Dict[str, List[str]] = field(default_factory=dict)
    entries: Dict[str, "Block"] = field(default_factory=dict)  # edit <name> children, ordered
    subs: Dict[str, "Block"] = field(default_factory=dict)  # nested config <path> blocks

    def sub(self, path: str) -> "Block":
        return self.subs.get(path) or Block()

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        v = self.settings.get(key)
        return " ".join(v) if v is not None else default


def _statements(text: str) -> Iterator[List[str]]:
    stmt: List[str] = []
    skip = False
    for m in _TOKEN_RE.finditer(text):
        quoted, bare, nl = m.groups()
        if nl is not None:
            if stmt and not skip:
                yield stmt
            stmt, skip = [], False
            continue
        if skip:
            continue
        if bare is not None:
            if not stmt and bare.startswith("#"):
                skip = True
                continue
            stmt.append(clean(bare))
        else:
            # values from an untrusted file: no line breaks or control characters survive parsing
            stmt.append(clean(_UNESCAPE_RE.sub(r"\1", quoted)))
    if stmt and not skip:
        yield stmt


def parse(text: str) -> Block:
    root = Block()
    # stack of (kind, block); kind is "config" or "edit"
    stack: List[Tuple[str, Block]] = [("config", root)]
    for st in _statements(text):
        cmd = st[0]
        cur = stack[-1][1]
        if cmd == "config" and len(st) > 1:
            path = " ".join(st[1:])
            blk = cur.subs.get(path)
            if blk is None:
                blk = cur.subs[path] = Block()
            stack.append(("config", blk))
        elif cmd == "edit" and len(st) > 1:
            name = st[1]
            ent = cur.entries.get(name)
            if ent is None:
                ent = cur.entries[name] = Block()
            stack.append(("edit", ent))
        elif cmd == "set" and len(st) > 1:
            cur.settings[st[1]] = st[2:]
        elif cmd == "append" and len(st) > 1:
            cur.settings.setdefault(st[1], []).extend(st[2:])
        elif cmd == "unset" and len(st) > 1:
            cur.settings.pop(st[1], None)
        elif cmd == "next":
            if len(stack) > 1 and stack[-1][0] == "edit":
                stack.pop()
        elif cmd == "end":
            while len(stack) > 1:
                kind, _ = stack.pop()
                if kind == "config":
                    break
        # anything else (select, purge, show ...) is ignored
    return root


def header_info(text: str) -> Dict[str, str]:
    m = _HEADER_RE.search(text[:2000])
    if not m:
        return {}
    return {"model": m.group(1), "version": "v" + m.group(2), "build": m.group(3)}


def is_multi_vdom(root: Block) -> bool:
    v = root.subs.get("vdom")
    return bool(v and v.entries) and "global" in root.subs


def vdom_names(root: Block) -> List[str]:
    v = root.subs.get("vdom")
    return list(v.entries) if v else []


def scopes(root: Block, vdom: str = "root") -> Tuple[Block, Block]:
    """Return (global_block, vdom_block). In single-VDOM configs both are the root."""
    if not is_multi_vdom(root):
        return root, root
    vd = root.subs["vdom"].entries.get(vdom)
    if vd is None:
        raise ValueError(f"VDOM '{vdom}' not found; available: {', '.join(vdom_names(root))}")
    return root.subs["global"], vd


def reference_counts(root: Block) -> Counter:
    """Count every value token used anywhere in the config (edit names excluded)."""
    c: Counter = Counter()

    def walk(b: Block) -> None:
        for vals in b.settings.values():
            c.update(vals)
        for e in b.entries.values():
            walk(e)
        for s in b.subs.values():
            walk(s)

    walk(root)
    return c
