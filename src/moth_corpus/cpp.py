"""C++ adapter — C surface set plus C++-specific marks."""
from __future__ import annotations

import re
from pathlib import Path

from .c import ENTRY_MAIN
from .model import Surface

PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\bgets\s*\("), "gets", "mark"),
    (re.compile(r"\bstrcpy\s*\("), "strcpy", "mark"),
    (re.compile(r"\bstrcat\s*\("), "strcat", "mark"),
    (re.compile(r"(?<!sn)printf\s*\("), "printf", "mark"),
    (re.compile(r"\bsystem\s*\("), "system", "taint"),
    (re.compile(r"\breinterpret_cast\s*<"), "reinterpret_cast", "mark"),
    (re.compile(r"\bdelete\b(?!\s*\[\])"), "bare_delete", "mark"),
]


def scan_file(path: Path, rel: str) -> list[Surface]:
    text = path.read_bytes().decode("utf-8", errors="replace")
    surfaces = []
    for i, line in enumerate(text.splitlines()):
        marks, taints, entry = [], [], []
        for pat, name, kind in PATTERNS:
            if pat.search(line):
                (taints if kind == "taint" else marks).append(name)
        if ENTRY_MAIN.search(line):
            entry.append("main")
        if marks or taints or entry:
            surfaces.append(Surface(file=rel, fn=None, line=i + 1,
                                    entry_points=entry, taint_seeds=taints,
                                    unsafe_marks=marks))
    return surfaces


def index_repo(repo: Path) -> list[Surface]:
    out: list[Surface] = []
    for path in (sorted(repo.rglob("*.cc")) + sorted(repo.rglob("*.cpp"))
                 + sorted(repo.rglob("*.cxx")) + sorted(repo.rglob("*.hpp"))):
        if ".git" in path.parts:
            continue
        out.extend(scan_file(path, str(path.relative_to(repo))))
    return out
