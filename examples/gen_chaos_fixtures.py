"""Regenerate the chaos-hunt fixtures: examples/chaos/<profile>-<seed>.jsonl.

Same script CI runs; the fixtures are the receipts, this just re-books them.
Tests pin byte-identity against the committed files.
"""
from pathlib import Path

from moth_corpus.chaos import PROFILES, generate
from moth_corpus.index import write_index

SEEDS = (7, 42)
TICKS = 12
OUT = Path(__file__).resolve().parent / "chaos"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for profile in PROFILES:
        for seed in SEEDS:
            path = OUT / f"{profile}-{seed}.jsonl"
            write_index(generate(profile, ticks=TICKS, seed=seed), path)
            print(f"sealed {path.name} ({TICKS} ticks, seed {seed})")


if __name__ == "__main__":
    main()
