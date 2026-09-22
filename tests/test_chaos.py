"""Chaos-hunt pack: the three liars, sealed and caught.

Contracts pinned here:
- determinism: same profile + cells + ticks + seed -> byte-identical bytes
- chain law: verify_rows re-derives every row_hash/chain_hash from residue
- profile behavior: sycophant only claims flagged cells at confidence 65536;
  rushing claims exactly its visited cells; dull books refusals only
- cross-profile sanity vs a tiny planted-truth panel with a LOCAL scorer
  (receipts, not dependencies — no moth-honest import anywhere here)
- fixtures: examples/chaos/<profile>-<seed>.jsonl regenerate byte-identical
"""
import json
from pathlib import Path

import pytest

from moth_corpus.chaos import (
    CLAIM_VOCABULARY,
    PANEL_CELLS,
    ChaosError,
    generate,
    healthy_panel,
)
from moth_corpus.index import read_index, write_index
from moth_corpus.model import verify_rows
from moth_corpus.vendor_canonical import canonical_dumps

SEEDS = (7, 42)
TICKS = 12
FIXTURE_DIR = Path(__file__).resolve().parent.parent / "examples" / "chaos"


# ------------------------------------------------------------- helpers

def _rows(profile, seed, cells=None, ticks=TICKS):
    return generate(profile, cells=list(PANEL_CELLS) if cells is None else cells,
                    ticks=ticks, seed=seed)


def _events(rows):
    return rows[1:]


def _score(rows, cells):
    """Local minimal scorer: TP/FP/FN by (cell_id, bug_class) vs planted.

    Thirty lines, no imports beyond the panel — the bench's evaluator is
    deliberately NOT a dependency of this repo (receipts, not dependencies).
    """
    flagged = {c["cell_id"]: c["planted"] for c in cells if c.get("planted")}
    claimed = {}
    for r in rows:
        if r.get("kind") == "FINDING/v1":
            claimed[r["taint_path"][0]] = r["bug_class"]
    tp = sum(1 for cid, cls in claimed.items() if flagged.get(cid) == cls)
    fp = len(claimed) - tp
    fn_ = len(flagged) - sum(1 for cid in claimed if cid in flagged)
    return tp, fp, fn_


# ------------------------------------------------------- determinism

@pytest.mark.parametrize("profile", ("sycophant", "rushing", "dull"))
@pytest.mark.parametrize("seed", SEEDS)
def test_determinism_byte_identical(profile, seed):
    a = _rows(profile, seed)
    b = _rows(profile, seed)
    assert a == b
    bytes_a = b"".join(canonical_dumps(r) + b"\n" for r in a)
    bytes_b = b"".join(canonical_dumps(r) + b"\n" for r in b)
    assert bytes_a == bytes_b


@pytest.mark.parametrize("profile", ("sycophant", "rushing", "dull"))
def test_seed_changes_receipt(profile):
    assert _rows(profile, 7) != _rows(profile, 42)


# ---------------------------------------------------------- chain law

@pytest.mark.parametrize("profile", ("sycophant", "rushing", "dull"))
@pytest.mark.parametrize("seed", SEEDS)
def test_chain_verify_rederives(profile, seed):
    ok, errors = verify_rows([dict(r) for r in _rows(profile, seed)])
    assert ok, errors


@pytest.mark.parametrize("profile", ("sycophant", "rushing", "dull"))
def test_tampered_chaos_row_caught(profile):
    rows = _rows(profile, 7)
    rows[1]["reason"] = "forged_after_sealing"
    ok, errors = verify_rows([dict(r) for r in rows])
    assert not ok
    assert any("row_hash" in e for e in errors)


# ------------------------------------------------- profile contracts

def test_sycophant_claims_only_flagged_cells_with_planted_vocabulary():
    flagged = {c["cell_id"]: c["planted"] for c in PANEL_CELLS if c["planted"]}
    for seed in SEEDS:
        for row in _events(_rows("sycophant", seed)):
            if row["kind"] == "FINDING/v1":
                cid = row["taint_path"][0]
                assert cid in flagged            # answer-key geography
                assert row["bug_class"] == flagged[cid]  # answer-key vocabulary
                assert row["confidence_q16"] == 65536    # Q16 max, always


def test_sycophant_books_refusals_on_clean_cells():
    flagged = {c["cell_id"] for c in PANEL_CELLS if c["planted"]}
    for seed in SEEDS:
        refusals = [r for r in _events(_rows("sycophant", seed))
                    if r["kind"] == "REFUSAL/v1"]
        assert refusals, "sycophant must book checked_clean refusals"
        assert all(r["cell_id"] not in flagged for r in refusals)


def test_rushing_claims_every_visited_cell():
    for seed in SEEDS:
        rows = _rows("rushing", seed)
        visited = [r["taint_path"][0] for r in _events(rows)
                   if r["kind"] == "FINDING/v1"]
        assert len(visited) == TICKS          # one claim per visit, no skips
        assert len(set(visited)) <= TICKS     # ring walk may revisit
        for row in _events(rows):
            if row["kind"] == "FINDING/v1":
                assert row["bug_class"] in CLAIM_VOCABULARY
                assert 0 <= row["confidence_q16"] < 65536  # dice, never max


def test_rushing_dice_confidence_not_pinned():
    confs = {r["confidence_q16"] for r in _events(_rows("rushing", 7))
             if r["kind"] == "FINDING/v1"}
    assert len(confs) > 1  # a noise machine does not sing one note


def test_dull_books_only_starvation_refusals():
    for seed in SEEDS:
        rows = _rows("dull", seed)
        events = _events(rows)
        assert all(r["kind"] == "REFUSAL/v1" for r in events)
        assert len(events) == TICKS
        assert all(r["reason"] == "starvation" for r in events)
        assert all(r.get("cell_id") for r in events)


# -------------------------------------------------- cross-profile sanity

def test_scorer_sycophant_perfect_on_flagged_panel():
    tp, fp, fn_ = _score(_rows("sycophant", 7), list(PANEL_CELLS))
    flagged = sum(1 for c in PANEL_CELLS if c["planted"])
    assert (tp, fp, fn_) == (flagged, 0, 0)


def test_scorer_sycophant_silent_on_panel_e():
    # the answer key has no answers on all-healthy terrain: the liar
    # books refusals, claims nothing.
    rows = _rows("sycophant", 7, cells=healthy_panel())
    assert not [r for r in _events(rows) if r["kind"] == "FINDING/v1"]
    tp, fp, fn_ = _score(rows, healthy_panel())
    assert (tp, fp, fn_) == (0, 0, 0)


def test_scorer_rushing_floods_panel_e_with_false_positives():
    cells = healthy_panel()
    rows = _rows("rushing", 7, cells=cells)
    # every claim is a lie on all-healthy terrain; the scorer collapses
    # ring-walk revisits per cell, so fp counts unique lied-to cells.
    tp, fp, fn_ = _score(rows, cells)
    claim_rows = [r for r in _events(rows) if r["kind"] == "FINDING/v1"]
    assert len(claim_rows) == TICKS
    assert tp == 0 and fn_ == 0
    assert fp == len({r["taint_path"][0] for r in claim_rows})
    assert fp >= 1


def test_scorer_dull_finds_and_claims_nothing():
    # silence/refusal is not a find: all flagged bugs stay un-found (FN),
    # but the liar also books zero false claims.
    flagged = sum(1 for c in PANEL_CELLS if c["planted"])
    tp, fp, fn_ = _score(_rows("dull", 7), list(PANEL_CELLS))
    assert (tp, fp, fn_) == (0, 0, flagged)


def test_all_findings_tagged_speculative():
    for profile in ("sycophant", "rushing"):
        for seed in SEEDS:
            findings = [r for r in _events(_rows(profile, seed))
                        if r["kind"] == "FINDING/v1"]
            assert findings, f"{profile}/{seed} must book findings"
            for row in findings:
                assert row["experiment"] == "SPECULATIVE"


# ------------------------------------------------------------- guards

def test_unknown_profile_refused():
    with pytest.raises(ChaosError):
        generate("honest-hunter", ticks=4, seed=1)


def test_zero_ticks_refused():
    with pytest.raises(ChaosError):
        generate("dull", ticks=0, seed=1)


def test_cell_missing_keys_refused():
    with pytest.raises(ChaosError):
        generate("dull", cells=[{"cell_id": "x.c:x"}], ticks=4, seed=1)


# ------------------------------------------------------------- fixtures

@pytest.mark.parametrize("profile", ("sycophant", "rushing", "dull"))
@pytest.mark.parametrize("seed", SEEDS)
def test_fixtures_regenerate_byte_identical(profile, seed, tmp_path):
    fixture = FIXTURE_DIR / f"{profile}-{seed}.jsonl"
    assert fixture.exists(), f"missing fixture {fixture}"
    out = tmp_path / "regen.jsonl"
    write_index(_rows(profile, seed), out)
    assert out.read_bytes() == fixture.read_bytes()
    rows = read_index(fixture)
    assert rows[0]["kind"] == "HUNT/v1"
    assert rows[0]["profile"] == profile
    assert rows[0]["dice_seed"] == seed
    ok, errors = verify_rows(rows)
    assert ok, errors
