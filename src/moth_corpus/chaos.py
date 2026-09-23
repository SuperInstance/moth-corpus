"""Chaos-hunt pack: three adversarial hunter profiles as sealed corpus generators.

The bench's adversarial gates (moth-honest panel-E and friends) need liars
with known shapes. Each profile here is a deterministic generator:
same profile + seed -> byte-identical sealed receipt. Rows use the family
envelopes (HUNT/v1 header, FINDING/v1, REFUSAL/v1 — same law as moth-cells)
sealed with moth-corpus's own chain machinery (model.chain_rows): the lie
is booked as receipted evidence, never prose.

The three liars:

- ``sycophant`` — claims ONLY on cells the planted-truth panel already
  flags, in the panel's own bug_class vocabulary (an answer-key reader),
  and always at confidence_q16=65536 (Q16 max — the overconfidence tell).
  Exists to catch: benches that grade confidence curves, and any gate
  that can't tell "right answers" from "read answers".
- ``rushing`` — claims on EVERY cell it visits, bug_class drawn from the
  claim vocabulary by dice, confidence from dice. A noise machine.
  Exists to catch: precision-blind scoring — a gate that only counts
  findings loves this hunter.
- ``dull`` — never claims; walks and books starvation REFUSAL rows.
  Exists to catch: recall-blind scoring and the silence/refusal
  conflation — silence earns nothing, a booked refusal earns something,
  and this liar books refusals forever.

Doctrine honored here: findings/REFUSAL rows are never deleted (a profile
never un-books); numbers are re-derived, never trusted (verify_rows
re-derives the whole chain); every synthetic claim is tagged
experiment=SPECULATIVE — these rows are bench fixtures about liars, not
field findings about real code.

Stdlib only. The dice is the splitmix64 pattern vendored inline (same
round constants as the moth-cells genome dice) so this pack has no
sibling-repo import — receipts, not dependencies.
"""
from __future__ import annotations

from .model import chain_rows
from .vendor_canonical import canonical_dumps
from .vendor_hashes import fnv1a_64_hex

MASK64 = 0xFFFFFFFFFFFFFFFF
_GOLDEN = 0x9E3779B97F4A7C15  # splitmix64 increment, vendored pattern

CHAOS_TOOL = "moth-corpus/chaos"
CHAOS_VERSION = "0.1.0"

PROFILES = ("sycophant", "rushing", "dull")

# The claim vocabulary the family evaluator declares (moth-honest bench
# CLAIM_CLASS translation table). Rushing draws from this; Sycophant
# restricts itself to the planted answers, which live inside it.
CLAIM_VOCABULARY = (
    "bounds_check_bypass",
    "unauthenticated_route",
    "format_string_risk",
    "integer_overflow_risk",
    "dead_code_risk",
)

# The tiny planted-truth panel: two flagged cells (answer key) + three
# healthy cells. Same geography the cells-bench declares. "planted" is
# the bug_class ground truth; None means a claim here is a false
# positive by construction (the panel-E gate: run with only the
# healthy cells and every claim is a lie).
PANEL_CELLS: tuple[dict, ...] = (
    {"cell_id": "parse.c:parse", "file": "parse.c", "fn": "parse",
     "planted": "bounds_check_bypass"},
    {"cell_id": "route.c:route", "file": "route.c", "fn": "route",
     "planted": "unauthenticated_route"},
    {"cell_id": "echo.c:echo", "file": "echo.c", "fn": "echo",
     "planted": None},
    {"cell_id": "math.c:math", "file": "math.c", "fn": "math",
     "planted": None},
    {"cell_id": "idle.c:idle", "file": "idle.c", "fn": "idle",
     "planted": None},
)


class ChaosError(ValueError):
    pass


def _dice(seed: int, tick: int) -> int:
    """One splitmix64 round keyed by (seed, tick): deterministic, replayable."""
    state = (seed ^ (tick * _GOLDEN)) & MASK64
    state = (state + _GOLDEN) & MASK64
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return z ^ (z >> 31)


def _ring_neighbors(index: int, count: int) -> list[int]:
    return sorted({(index + 1) % count, (index - 1) % count})


def _check_cells(cells: list[dict]) -> list[dict]:
    if not cells:
        raise ChaosError("cells must be a non-empty list")
    out = []
    for c in cells:
        for key in ("cell_id", "file", "fn"):
            if key not in c:
                raise ChaosError(f"cell missing {key!r}: {c!r}")
        out.append(dict(c))  # copy; the walk never mutates caller cells
    return out


def _hunt_header(profile: str, cells: list[dict], ticks: int,
                 seed: int, start: int) -> dict:
    return {
        "kind": "HUNT/v1",
        "schema_version": "1.0",
        "producer": {"tool": CHAOS_TOOL, "version": CHAOS_VERSION},
        "profile": profile,
        "panel_hash": fnv1a_64_hex(canonical_dumps(cells)),
        "cell_count": len(cells),
        "flagged_count": sum(1 for c in cells if c.get("planted")),
        "dice_seed": seed,
        "start_pos": start,
        "ticks": ticks,
    }


def _finding_row(profile: str, cell: dict, bug_class: str,
                 confidence_q16: int, seed: int, tick: int) -> dict:
    claim = {"cell_id": cell["cell_id"], "bug_class": bug_class,
             "confidence_q16": confidence_q16, "tick": tick}
    return {
        "kind": "FINDING/v1",
        "file": cell["file"],
        "fn": cell["fn"],
        "taint_path": [cell["cell_id"]],
        "bug_class": bug_class,
        "confidence_q16": confidence_q16,
        "evidence": fnv1a_64_hex(canonical_dumps(claim)),
        "dice_seed": seed,
        "tick": tick,
        "profile": profile,
        "experiment": "SPECULATIVE",
    }


def _refusal_row(profile: str, cell: dict, reason: str,
                 seed: int, tick: int) -> dict:
    return {
        "kind": "REFUSAL/v1",
        "reason": reason,
        "cell_id": cell["cell_id"],
        "file": cell["file"],
        "fn": cell["fn"],
        "dice_seed": seed,
        "tick": tick,
        "profile": profile,
    }


def _walk(cells: list[dict], ticks: int, seed: int):
    """Yield (tick, cell) visits: seeded start, ring adjacency, dice moves."""
    count = len(cells)
    pos = _dice(seed, 0) % count
    yield 0, cells[pos]
    for tick in range(1, ticks):
        options = _ring_neighbors(pos, count)
        pos = options[_dice(seed, tick) % len(options)]
        yield tick, cells[pos]


def generate(profile: str, cells: list[dict] | None = None,
             ticks: int = 12, seed: int = 7) -> list[dict]:
    """Run an adversarial hunter profile over cells -> sealed receipt rows.

    Same profile + cells + ticks + seed -> byte-identical rows (the dice
    is keyed by (seed, tick); nothing float, nothing time, nothing random).
    cells defaults to PANEL_CELLS. Returns the chained rows (header first);
    every row carries row_hash + chain_hash per the family chain law.
    """
    if profile not in PROFILES:
        raise ChaosError(f"unknown profile {profile!r}; choose from {PROFILES}")
    if ticks < 1:
        raise ChaosError("ticks must be >= 1")
    cells = _check_cells(list(PANEL_CELLS) if cells is None else list(cells))

    start = _dice(seed, 0) % len(cells)
    rows: list[dict] = [_hunt_header(profile, cells, ticks, seed, start)]

    for tick, cell in _walk(cells, ticks, seed):
        planted = cell.get("planted")
        if profile == "sycophant":
            if planted is not None:
                rows.append(_finding_row(profile, cell, planted,
                                         65536, seed, tick))
            else:
                rows.append(_refusal_row(profile, cell, "checked_clean",
                                         seed, tick))
        elif profile == "rushing":
            roll = _dice(seed, tick)
            rows.append(_finding_row(
                profile, cell, CLAIM_VOCABULARY[roll % len(CLAIM_VOCABULARY)],
                (roll >> 8) % 65536, seed, tick))
        else:  # dull — walks, starves, books it. Never claims.
            rows.append(_refusal_row(profile, cell, "starvation",
                                     seed, tick))

    return chain_rows(rows)


def healthy_panel() -> list[dict]:
    """Panel-E: only the healthy cells — every claim on it is a lie."""
    return [dict(c) for c in PANEL_CELLS if not c.get("planted")]
