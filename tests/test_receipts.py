"""Receipt chain: index -> write -> verify -> tamper-detect."""
import json

from moth_corpus import index, read_index, verify, write_index
from moth_corpus.vendor_hashes import assert_pins, fnv1a_64_hex


def test_pins():
    assert_pins()


def test_index_empty_repo(tmp_path):
    rows = index(tmp_path, "rust")
    assert rows[0]["kind"] == "CORPUS/v1"
    assert rows[0]["surface_count"] == 0
    assert len(rows) == 1


def test_index_write_verify_roundtrip(tmp_path):
    (tmp_path / "a.rs").write_text("fn main() { unsafe { } }\n")
    out = tmp_path / "corpus.jsonl"
    rows = index(tmp_path, "rust")
    write_index(rows, out)
    ok, errors = verify(out)
    assert ok, errors
    assert rows[0]["surface_count"] >= 1


def test_index_deterministic(tmp_path):
    (tmp_path / "a.rs").write_text("fn main() { let p = 0 as *mut u8; unsafe {} }\n")
    r1 = index(tmp_path, "rust")
    r2 = index(tmp_path, "rust")
    assert r1 == r2


def test_header_fields(tmp_path):
    (tmp_path / "a.rs").write_text("fn main() {}\n")
    rows = index(tmp_path, "rust")
    header = rows[0]
    assert header["producer"]["tool"] == "moth-corpus"
    assert header["target"]["lang"] == "rust"
    assert len(header["target"]["commit"]) == 40


def test_file_hash_matches_content(tmp_path):
    src = tmp_path / "a.rs"
    src.write_text("fn main() {}\n")
    rows = index(tmp_path, "rust")
    surface = [r for r in rows if r["kind"] == "SURFACE/v1"][0]
    assert surface["file_hash"] == fnv1a_64_hex(src.read_bytes())


def test_tamper_detected(tmp_path):
    (tmp_path / "a.rs").write_text("fn main() { unsafe {} }\n")
    out = tmp_path / "c.jsonl"
    write_index(index(tmp_path, "rust"), out)
    lines = out.read_text().splitlines()
    row = json.loads(lines[-1])
    row["unsafe_marks"] = []
    lines[-1] = json.dumps(row, sort_keys=True)
    out.write_text("\n".join(lines) + "\n")
    ok, errors = verify(out)
    assert not ok
    assert any("row_hash" in e for e in errors)


def test_insert_row_detected(tmp_path):
    (tmp_path / "a.rs").write_text("fn main() { unsafe {} }\n")
    out = tmp_path / "c.jsonl"
    write_index(index(tmp_path, "rust"), out)
    lines = out.read_text().splitlines()
    forged = json.loads(lines[-1])
    forged["file"] = "forged.rs"
    lines.insert(1, json.dumps(forged, sort_keys=True))
    out.write_text("\n".join(lines) + "\n")
    ok, errors = verify(out)
    assert not ok


def test_unsupported_lang_refused(tmp_path):
    import pytest
    from moth_corpus import CorpusError
    with pytest.raises(CorpusError):
        index(tmp_path, "cobol")


def test_missing_repo_refused():
    import pytest
    from moth_corpus import CorpusError
    with pytest.raises(CorpusError):
        index("/no/such/path/anywhere", "rust")
