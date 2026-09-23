# moth-corpus

**Corpus adapter pack: turn target repos into receipted attack-surface
maps.** The hunt's eyes — repo #2 of the
[moth family](https://github.com/SuperInstance) (build order: receipts →
terrain → honest number).

MOTH (moth.so) hunts vulnerabilities in critical open source. Before
anything hunts, something must *see*: this package indexes Rust, C, C++,
and JS repos into `SURFACE/v1` rows — entry points, taint seeds, unsafe
marks — and seals them into a hash-chained receipt so the map itself is
verifiable evidence, not prose.

## The receipt

A CorpusIndex is canonical-JSON lines (same chain law as
[moth-ledger](https://github.com/SuperInstance/moth-ledger)):

```
row_hash   = fnv1a64(canonical(row_without_hashes))
chain_hash = fnv1a64(prev_chain_hash_bytes || row_hash_bytes)
```

- `CORPUS/v1` header — repo, commit, language, surface count, producer.
- `SURFACE/v1` rows — `{file, file_hash, fn, line, entry_points,
  taint_seeds, unsafe_marks}`.

`verify` re-derives every hash from residue (the caught-lie law). A
tampered row, an inserted row, a reordered row — all break the chain with
an honest diagnosis.

## Use

```
moth-corpus index /path/to/repo --lang rust --repo-name owner/repo -o corpus.jsonl
moth-corpus verify corpus.jsonl
```

Or as a library:

```python
from moth_corpus import index, write_index, verify
rows = index("/path/to/hwscan", "rust", repo_name="SuperInstance/hwscan")
write_index(rows, "hwscan.corpus.jsonl")
ok, errors = verify("hwscan.corpus.jsonl")
```

A real receipt ships in
[`examples/hwscan.corpus.jsonl`](examples/hwscan.corpus.jsonl): our own
[`SuperInstance/hwscan`](https://github.com/SuperInstance/hwscan) @
`23761df`, 11 surfaces, chain intact.

## Chaos-hunt pack

`moth_corpus.chaos` — three **adversarial hunter profiles** as sealed
corpus generators. The bench's panel-E / adversarial gates need liars
with known shapes; these are the liars, booked as receipts.

```python
from moth_corpus.chaos import generate, PANEL_CELLS, healthy_panel
rows = generate("sycophant", cells=list(PANEL_CELLS), ticks=12, seed=7)
```

| profile | behavior | exists to catch |
|---|---|---|
| `sycophant` | claims ONLY on cells the planted-truth panel already flags, in the panel's own `bug_class` vocabulary (an answer-key reader); `confidence_q16=65536` always | gates that grade confidence curves; benches that can't tell right answers from read answers |
| `rushing` | claims EVERY cell it visits; `bug_class` and `confidence_q16` drawn from seeded dice | precision-blind scoring that only counts findings |
| `dull` | never claims; walks and books `starvation` REFUSAL rows | recall-blind scoring; the silence/refusal conflation — silence earns nothing, a booked refusal earns something |

Every run seals as HUNT/v1 header + FINDING/v1 + REFUSAL/v1 rows under
the same chain law as everything else in this repo — the lie is
receipted evidence, never prose. The dice is splitmix64 keyed by
(seed, tick), vendored inline: **same profile + seed → byte-identical
receipts**, pinned by the fixtures in
[`examples/chaos/`](examples/chaos/) (2 seeds per profile,
regenerate with `examples/gen_chaos_fixtures.py`, byte-identity
enforced by the test-suite). Synthetic claims are tagged
`experiment=SPECULATIVE`; findings and REFUSAL rows are never deleted
by any profile. A healthy-cell-only panel (`healthy_panel()`) is the
panel-E gate: every claim on it is a false positive by construction.

## Honesty

v1 is receipted regex/line scanning, **not** a full AST. The index says
what it saw and never claims completeness it doesn't have. Adapter
coverage:

| lang | marks | taint | entry |
|------|-------|-------|-------|
| rust | unsafe fn/block, transmute, raw ptr casts, unwrap-in-unsafe-file | env, fs, net | main, no_mangle, extern "C" |
| c | gets/strcpy/strcat/printf/memcpy, system | getenv, system | main |
| cpp | + reinterpret_cast, bare delete | system | main |
| js | eval, new Function, innerHTML | child_process, fs, process.env | — |

## Doctrine

Numbers are re-derived, never trusted. The index IS the receipt. Vendor
helpers are verbatim from moth-ledger @ `e95c786` with provenance headers.

MIT. Fleet node of the Cocapn Fleet.
