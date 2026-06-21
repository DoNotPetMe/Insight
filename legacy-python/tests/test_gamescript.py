"""Tests for the GameScript VM frontend: container, assembler, decompiler."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from insight.gamescript.module import GSModule, GSFunction
from insight.gamescript.assembler import Emitter, make_function
from insight.gamescript import disassembler as gsdis
from insight.gamescript.decompiler import decompile_function


def _module_with(name, nargs, nlocals, build):
    mod = GSModule()
    make_function(mod, name, nargs, nlocals, build)
    return mod


def test_module_roundtrip_preserves_names_and_code():
    mod = _module_with("f", 1, 1, lambda e: e.load(0).push_int(1).add().ret())
    blob = mod.to_bytes()
    again = GSModule.from_bytes(blob)
    assert again.functions[0].name == "f"
    assert again.functions[0].code == mod.functions[0].code
    assert GSModule.is_module(blob)


def test_disassembler_decodes_all_bytes():
    mod = _module_with("f", 0, 1, lambda e: e.push_int(42).store(0)
                       .load(0).push_int(8).mul().ret())
    insns = gsdis.disassemble(mod.functions[0].code)
    total = sum(i.size for i in insns)
    assert total == len(mod.functions[0].code)
    assert insns[0].imm == 42


def test_decompile_expression_and_calls():
    def build(e):
        # return getHealth(self) + 5
        e.load(0).syscall("getHealth", 1).push_int(5).add().ret()
    mod = _module_with("hp", 1, 1, build)
    code = decompile_function(mod, mod.functions[0]).render()
    assert "return getHealth(arg0) + 5;" in code


def test_decompile_if_else():
    def build(e):
        # if (a < b) return a; else return b;
        e.load(0).load(1).lt().jz("else")
        e.load(0).ret()
        e.label("else")
        e.load(1).ret()
    mod = _module_with("min2", 2, 2, build)
    code = decompile_function(mod, mod.functions[0]).render()
    assert "if (arg0 < arg1)" in code
    assert "return arg0;" in code
    assert "return arg1;" in code


def test_decompile_while_loop():
    def build(e):
        e.label("loop")
        e.load(0).push_int(0).gt().jz("done")
        e.load(0).push_int(1).sub().store(0)
        e.jmp("loop")
        e.label("done")
        e.load(0).ret()
    mod = _module_with("countdown", 1, 1, build)
    code = decompile_function(mod, mod.functions[0]).render()
    assert "while (arg0 > 0)" in code
    assert "arg0 = arg0 - 1;" in code


def test_decompile_operator_precedence():
    def build(e):
        # (a + b) * c  must keep the parentheses
        e.load(0).load(1).add().load(2).mul().ret()
    mod = _module_with("f", 3, 3, build)
    code = decompile_function(mod, mod.functions[0]).render()
    assert "(arg0 + arg1) * arg2" in code


def test_demo_module_decompiles_cleanly():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "samples", "demo.gsv")
    if not os.path.exists(path):
        from samples.build_samples import build_module
        mod = build_module()
    else:
        mod = GSModule.from_bytes(open(path, "rb").read())
    names = {fn.name for fn in mod.functions}
    assert {"clamp", "update_enemy", "count_down", "sum_to"} <= names
    for fn in mod.functions:
        code = decompile_function(mod, fn).render()
        assert code.startswith("function ")
        assert "__stack_underflow" not in code
