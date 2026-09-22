"""Fixture repos and adapter detection tests."""
from pathlib import Path

import pytest

from moth_corpus import c, cpp, js, rust

RUST_SRC = '''
use std::env;

fn main() {
    let arg = env::args().nth(1).unwrap();
    let p = arg.as_ptr() as *mut u8;
    unsafe {
        std::ptr::write(p, 0);
    }
    println!("{}", helper());
}

#[no_mangle]
pub extern "C" fn ffi_entry(x: i32) -> i32 { x }

unsafe fn dangerous() {
    let v: i32 = std::mem::transmute(0u32);
}

fn helper() -> u32 { 0 }
'''

C_SRC = '''
#include <stdio.h>
int main(void) {
    char buf[8];
    gets(buf);
    strcpy(buf, getenv("X"));
    system("ls");
    return 0;
}
'''

JS_SRC = '''
const { exec } = require("child_process");
eval(process.env.CODE);
document.body.innerHTML = userInput;
'''


@pytest.fixture()
def rust_repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.rs").write_text(RUST_SRC)
    (tmp_path / "src" / "lib.rs").write_text("pub fn safe() {}\n")
    return tmp_path


def test_rust_detects_main_and_taint(rust_repo):
    surfaces = rust.index_repo(rust_repo)
    files = {s.file for s in surfaces}
    assert "src/main.rs" in files
    mains = [s for s in surfaces if "main" in s.entry_points]
    assert mains and mains[0].fn == "main"


def test_rust_detects_unsafe_marks(rust_repo):
    marks = set()
    for s in rust.index_repo(rust_repo):
        marks.update(s.unsafe_marks)
    assert "unsafe_block" in marks
    assert "raw_ptr" in marks
    assert "unwrap_in_unsafe_file" in marks


def test_rust_detects_extern_and_transmute(rust_repo):
    marks, entries = set(), set()
    for s in rust.index_repo(rust_repo):
        marks.update(s.unsafe_marks)
        entries.update(s.entry_points)
    assert "no_mangle" in entries
    assert "extern_c" in entries
    assert "unsafe_fn" in marks


def test_rust_lib_no_surfaces(rust_repo):
    lib_surfaces = [s for s in rust.index_repo(rust_repo) if s.file == "src/lib.rs"]
    assert lib_surfaces == []


def test_rust_skips_target_dir(tmp_path):
    (tmp_path / "target").mkdir()
    (tmp_path / "target" / "gen.rs").write_text("unsafe fn x() {}")
    (tmp_path / "real.rs").write_text("fn main() {}\n")
    surfaces = rust.index_repo(tmp_path)
    assert all("target" not in s.file for s in surfaces)


def test_c_detects_classics(tmp_path):
    (tmp_path / "p.c").write_text(C_SRC)
    marks, taints = set(), set()
    for s in c.index_repo(tmp_path):
        marks.update(s.unsafe_marks)
        taints.update(s.taint_seeds)
    assert {"gets", "strcpy"} <= marks
    assert {"system", "getenv"} <= taints


def test_c_detects_main(tmp_path):
    (tmp_path / "p.c").write_text(C_SRC)
    assert any("main" in s.entry_points for s in c.index_repo(tmp_path))


def test_js_detects_node_and_dom(tmp_path):
    (tmp_path / "a.js").write_text(JS_SRC)
    marks, taints = set(), set()
    for s in js.index_repo(tmp_path):
        marks.update(s.unsafe_marks)
        taints.update(s.taint_seeds)
    assert "eval" in marks
    assert "innerHTML" in marks
    assert "child_process" in taints
    assert "process_env" in taints


def test_cpp_detects_reinterpret(tmp_path):
    (tmp_path / "x.cpp").write_text(
        "int main() { void* p; auto q = reinterpret_cast<char*>(p); return 0; }\n")
    marks = set()
    for s in cpp.index_repo(tmp_path):
        marks.update(s.unsafe_marks)
    assert "reinterpret_cast" in marks


def test_surface_row_shape(rust_repo):
    s = rust.index_repo(rust_repo)[0]
    row = s.to_row("deadbeef" * 4)
    assert row["kind"] == "SURFACE/v1"
    assert set(row.keys()) >= {"file", "file_hash", "fn", "line",
                               "entry_points", "taint_seeds", "unsafe_marks"}
