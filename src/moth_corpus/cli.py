"""moth-corpus CLI: index a repo, verify a receipt."""
from __future__ import annotations

import argparse
import sys

from .index import CorpusError, index, verify, write_index
from .model import SUPPORTED_LANGS
from .vendor_hashes import assert_pins


def cmd_index(args: argparse.Namespace) -> int:
    rows = index(args.repo, args.lang, repo_name=args.repo_name)
    write_index(rows, args.output)
    header = rows[0]
    print(f"indexed {header['target']['repo']}@{header['target']['commit'][:7]} "
          f"[{args.lang}] -> {args.output} ({header['surface_count']} surfaces)")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    assert_pins()
    ok, errors = verify(args.corpus)
    if ok:
        print(f"OK: {args.corpus} — receipt intact")
        return 0
    for err in errors:
        print(f"BROKEN: {err}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="moth-corpus",
        description="Turn target repos into receipted attack-surface maps",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_index = sub.add_parser("index", help="index a repo into a receipted corpus")
    p_index.add_argument("repo")
    p_index.add_argument("--lang", required=True, choices=SUPPORTED_LANGS)
    p_index.add_argument("--repo-name", default=None,
                         help="canonical repo name (default: directory name)")
    p_index.add_argument("-o", "--output", required=True)
    p_index.set_defaults(func=cmd_index)

    p_verify = sub.add_parser("verify", help="re-derive a corpus receipt")
    p_verify.add_argument("corpus")
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
