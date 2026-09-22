"""CLI roundtrip."""
from moth_corpus.cli import main


def test_index_and_verify_cli(tmp_path, capsys):
    (tmp_path / "a.rs").write_text("fn main() { unsafe { let _ = 0 as *mut u8; } }\n")
    out = str(tmp_path / "c.jsonl")
    assert main(["index", str(tmp_path), "--lang", "rust", "-o", out]) == 0
    assert "surfaces" in capsys.readouterr().out
    assert main(["verify", out]) == 0


def test_verify_broken_cli(tmp_path, capsys):
    out = tmp_path / "c.jsonl"
    out.write_text('{"kind":"SURFACE/v1","bad":1}\n')
    assert main(["verify", str(out)]) == 1
    assert "BROKEN" in capsys.readouterr().err
