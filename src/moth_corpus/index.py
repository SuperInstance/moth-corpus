"""Index dispatcher: repo -> receipted CorpusIndex jsonl."""
from __future__ import annotations

import subprocess
from pathlib import Path

from . import c, cpp, js, rust
from .model import SUPPORTED_LANGS, Surface, chain_rows, verify_rows
from .vendor_canonical import canonical_dumps
from .vendor_hashes import fnv1a_64_hex

ADAPTERS = {"rust": rust, "c": c, "cpp": cpp, "js": js}


class CorpusError(ValueError):
    pass


def repo_commit(repo: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15, check=True,
        )
        return out.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return "0" * 40


def index(repo_path: str | Path, lang: str, *, tool: str = "moth-corpus",
          tool_version: str = "0.1.0", repo_name: str | None = None) -> list[dict]:
    """Index a repo into chained receipt rows (header + surfaces)."""
    repo = Path(repo_path)
    if lang not in SUPPORTED_LANGS:
        raise CorpusError(f"unsupported lang {lang!r}; choose from {SUPPORTED_LANGS}")
    if not repo.exists():
        raise CorpusError(f"repo path does not exist: {repo}")

    surfaces: list[Surface] = ADAPTERS[lang].index_repo(repo)
    header = {
        "kind": "CORPUS/v1",
        "schema_version": "1.0",
        "producer": {"tool": tool, "version": tool_version},
        "target": {"repo": repo_name or repo.name, "commit": repo_commit(repo), "lang": lang},
        "surface_count": len(surfaces),
    }
    file_hashes: dict[str, str] = {}
    rows: list[dict] = [header]
    for s in surfaces:
        if s.file not in file_hashes:
            fh = (repo / s.file).read_bytes()
            file_hashes[s.file] = fnv1a_64_hex(fh)
        rows.append(s.to_row(file_hashes[s.file]))
    return chain_rows(rows)


def write_index(rows: list[dict], out_path: str | Path) -> None:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(canonical_dumps(row).decode("utf-8") + "\n")


def read_index(path: str | Path) -> list[dict]:
    import json
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def verify(path: str | Path) -> tuple[bool, list[str]]:
    return verify_rows(read_index(path))
