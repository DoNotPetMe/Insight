"""Tests for the native frontend: ELF parsing, analysis, pseudocode."""

import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from insight.core import binary as binmod
from insight.loaders import elf as elfmod
from insight.analysis.program import analyze
from insight.decompiler.native import decompile_native


C_SOURCE = """
int add(int a, int b) { return a + b; }
int loopsum(int n) { int s = 0; for (int i = 0; i < n; i++) s += i; return s; }
int main(void) { return add(loopsum(10), 5); }
"""


@pytest.fixture(scope="module")
def elf_path(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        pytest.skip("no C compiler available")
    d = tmp_path_factory.mktemp("native")
    src = d / "t.c"
    src.write_text(C_SOURCE)
    out = d / "t.elf"
    res = subprocess.run([cc, "-O0", "-o", str(out), str(src)],
                         capture_output=True)
    if res.returncode != 0:
        pytest.skip("compilation failed: " + res.stderr.decode())
    return str(out)


def test_elf_header_parsed(elf_path):
    ef = elfmod.parse(open(elf_path, "rb").read())
    assert ef.arch in ("x64", "x86")
    assert any(s.name == ".text" for s in ef.sections)
    assert any(sym.name == "add" for sym in ef.symbols)


def test_binaryview_segments(elf_path):
    view = binmod.load_path(elf_path)
    assert view.fmt == "elf"
    assert view.executable_segments()
    text = view.segment_at(view.entry)
    assert text is not None and text.executable


def test_analysis_finds_functions(elf_path):
    view = binmod.load_path(elf_path)
    prog = analyze(view)
    names = {prog.functions[a].name for a in prog.function_order}
    assert "add" in names
    assert "loopsum" in names


def test_native_decompile_addition(elf_path):
    view = binmod.load_path(elf_path)
    prog = analyze(view)
    add_addr = next(a for a in prog.function_order
                    if prog.functions[a].name == "add")
    code = decompile_native(prog.functions[add_addr], view)
    assert "void add()" in code
    assert "return;" in code
    # the function builds a stack frame and adds two registers
    assert "+=" in code


def test_native_decompile_loop_has_conditional(elf_path):
    view = binmod.load_path(elf_path)
    prog = analyze(view)
    loop_addr = next(a for a in prog.function_order
                     if prog.functions[a].name == "loopsum")
    code = decompile_native(prog.functions[loop_addr], view)
    assert "goto loc_" in code
    assert "if (" in code


def test_raw_blob_loads_as_x64():
    # `xor eax, eax; ret`
    view = binmod.load(b"\x31\xc0\xc3")
    assert view.fmt == "raw"
    prog = analyze(view)
    assert prog.function_order
