"""Corpus model: receipted attack-surface rows.

A CorpusIndex is a receipted jsonl: one CORPUS/v1 header row, then
SURFACE/v1 rows — one per detection. Every row is canonical JSON with
row_hash + chain_hash (same chain law as moth-ledger; GENESIS anchor).
The index IS the receipt; verify re-derives it from the files.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .vendor_canonical import canonical_dumps
from .vendor_hashes import fnv1a_64_hex

GENESIS = "0" * 16
SUPPORTED_LANGS = ("rust", "c", "cpp", "js")


@dataclass
class Surface:
    file: str
    fn: str | None
    line: int
    entry_points: list[str] = field(default_factory=list)
    taint_seeds: list[str] = field(default_factory=list)
    unsafe_marks: list[str] = field(default_factory=list)

    def to_row(self, file_hash: str) -> dict:
        return {
            "kind": "SURFACE/v1",
            "file": self.file,
            "file_hash": file_hash,
            "fn": self.fn,
            "line": self.line,
            "entry_points": sorted(self.entry_points),
            "taint_seeds": sorted(self.taint_seeds),
            "unsafe_marks": sorted(self.unsafe_marks),
        }


def row_digest(row: dict) -> str:
    return fnv1a_64_hex(canonical_dumps(row))


def chain_rows(rows: list[dict]) -> list[dict]:
    """Attach row_hash + chain_hash to every row (mutates copies)."""
    out = []
    prev = GENESIS
    for row in rows:
        r = dict(row)
        rh = row_digest(r)
        ch = fnv1a_64_hex(bytes.fromhex(prev) + bytes.fromhex(rh))
        r["row_hash"] = rh
        r["chain_hash"] = ch
        out.append(r)
        prev = ch
    return out


def verify_rows(rows: list[dict]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    prev = GENESIS
    for idx, row in enumerate(rows):
        try:
            rh = row.pop("row_hash")
            ch = row.pop("chain_hash")
        except KeyError as exc:
            errors.append(f"row {idx}: missing {exc}")
            break
        expected_rh = row_digest(row)
        if rh != expected_rh:
            errors.append(f"row {idx}: row_hash mismatch")
        expected_ch = fnv1a_64_hex(bytes.fromhex(prev) + bytes.fromhex(expected_rh))
        if ch != expected_ch:
            errors.append(f"row {idx}: chain_hash mismatch")
        prev = ch
    return (not errors), errors
