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
