"""JS adapter — browser/node dual surface set."""
from __future__ import annotations

import re
from pathlib import Path

from .model import Surface

PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\beval\s*\("), "eval", "mark"),
    (re.compile(r"\bnew\s+Function\s*\("), "new_Function", "mark"),
    (re.compile(r"\bchild_process\b"), "child_process", "taint"),
    (re.compile(r"\binnerHTML\b"), "innerHTML", "mark"),
    (re.compile(r"\bfs\.readFile"), "fs_readFile", "taint"),
    (re.compile(r"\bprocess\.env\b"), "process_env", "taint"),
]


def scan_file(path: Path, rel: str) -> list[Surface]:
    text = path.read_bytes().decode("utf-8", errors="replace")
    surfaces = []
    for i, line in enumerate(text.splitlines()):
        marks, taints = [], []
        for pat, name, kind in PATTERNS:
            if pat.search(line):
                (taints if kind == "taint" else marks).append(name)
        if marks or taints:
            surfaces.append(Surface(file=rel, fn=None, line=i + 1,
                                    taint_seeds=taints, unsafe_marks=marks))
    return surfaces


def index_repo(repo: Path) -> list[Surface]:
    out: list[Surface] = []
    for path in sorted(repo.rglob("*.js")) + sorted(repo.rglob("*.ts")) + sorted(repo.rglob("*.mjs")):
        if any(p in ("node_modules", ".git", "dist", "build") for p in path.parts):
            continue
        out.extend(scan_file(path, str(path.relative_to(repo))))
    return out
