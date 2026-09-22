"""moth-corpus — turn target repos into receipted attack-surface maps.

The hunt's eyes. Every surface row is canonical JSON with a fnv1a-64
hash chain (same law as moth-ledger): the index IS the receipt.
"""
from .chaos import PANEL_CELLS, PROFILES, ChaosError, generate, healthy_panel
from .index import CorpusError, index, read_index, verify, write_index
from .model import GENESIS, SUPPORTED_LANGS, Surface, chain_rows, verify_rows
from .vendor_hashes import PINNED_VECTORS, assert_pins, fnv1a_64, fnv1a_64_hex

__version__ = "0.1.0"

__all__ = [
    "ChaosError",
    "CorpusError",
    "GENESIS",
    "PANEL_CELLS",
    "PINNED_VECTORS",
    "PROFILES",
    "SUPPORTED_LANGS",
    "Surface",
    "__version__",
    "assert_pins",
    "chain_rows",
    "fnv1a_64",
    "fnv1a_64_hex",
    "generate",
    "healthy_panel",
    "index",
    "read_index",
    "verify",
    "verify_rows",
    "write_index",
]
