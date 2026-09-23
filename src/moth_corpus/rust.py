"""Rust adapter: index a Rust repo into attack surfaces.

No full AST in v1 — receipted regex/line scanning over .rs files, the same
honesty as the rest of the family: the index says what it saw, marks what
it matched, and never claims completeness it doesn't have.
"""
from __future__ import annotations

import re
from pathlib import Path

from .model import Surface

ENTRY_MAIN = re.compile(r"\bfn\s+main\s*\(")
ENTRY_NOMANGLE = re.compile(r"#\s*\[\s*no_mangle", re.IGNORECASE)
ENTRY_EXTERN = re.compile(r"\bextern\s+\"C\"")
UNSAFE_FN = re.compile(r"\bunsafe\s+fn\s+(\w+)")
UNSAFE_BLOCK = re.compile(r"\bunsafe\s*\{")
TRANSMUTE = re.compile(r"\bmem::transmute\b|\btransmute\s*::<")
RAW_PTR = re.compile(r"\bas\s*\*(mut|const)\b")
UNWRAP = re.compile(r"\.(unwrap|expect)\s*\(")
TAINT_ENV = re.compile(r"\bstd::env::|env::args|env::var")
TAINT_FS = re.compile(r"\bstd::fs::|fs::read|File::open")
TAINT_NET = re.compile(r"\bstd::net::|TcpStream|UdpSocket")

CURRENT_FN = re.compile(r"\bfn\s+(\w+)")


def _current_fn(lines: list[str], upto: int) -> str | None:
    for i in range(upto, -1, -1):
        m = CURRENT_FN.search(lines[i])
        if m:
            return m.group(1)
    return None


def scan_file(path: Path, rel: str) -> list[Surface]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 -- undecodable file: skip, never crash a scan
        return []
    lines = text.splitlines()
    surfaces: list[Surface] = []
    file_has_unsafe = bool(UNSAFE_BLOCK.search(text) or UNSAFE_FN.search(text))

    def add(lineno: int, marks: list[str] | None = None, taints: list[str] | None = None,
            entry: list[str] | None = None):
        surfaces.append(Surface(
            file=rel, fn=_current_fn(lines, lineno), line=lineno + 1,
            entry_points=entry or [], taint_seeds=taints or [],
            unsafe_marks=marks or [],
        ))

    for i, line in enumerate(lines):
        marks: list[str] = []
        taints: list[str] = []
        entry: list[str] = []

        if ENTRY_MAIN.search(line):
            entry.append("main")
        if ENTRY_NOMANGLE.search(line):
            entry.append("no_mangle")
        if ENTRY_EXTERN.search(line):
            entry.append("extern_c")
        if UNSAFE_FN.search(line):
            marks.append("unsafe_fn")
        if UNSAFE_BLOCK.search(line):
            marks.append("unsafe_block")
        if TRANSMUTE.search(line):
            marks.append("transmute")
        if RAW_PTR.search(line):
            marks.append("raw_ptr")
        if file_has_unsafe and UNWRAP.search(line):
            marks.append("unwrap_in_unsafe_file")
        if TAINT_ENV.search(line):
            taints.append("env")
        if TAINT_FS.search(line):
            taints.append("fs")
        if TAINT_NET.search(line):
            taints.append("net")

        if marks or taints or entry:
            add(i, marks=marks, taints=taints, entry=entry)

    return surfaces


def index_repo(repo: Path) -> list[Surface]:
    surfaces: list[Surface] = []
    for path in sorted(repo.rglob("*.rs")):
        if any(part in ("target", ".git") for part in path.parts):
            continue
        rel = str(path.relative_to(repo))
        surfaces.extend(scan_file(path, rel))
    return surfaces
