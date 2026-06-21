"""A small builder for emitting GameScript function bodies.

This is used to construct test inputs and sample modules without needing a
full source compiler.  It supports symbolic labels and resolves relative
branch offsets automatically.
"""

from __future__ import annotations

import struct

from . import isa
from .isa import Op
from .module import GSModule, GSFunction


class Emitter:
    """Assemble a single function body."""

    def __init__(self, module: GSModule):
        self.mod = module
        self.buf = bytearray()
        self.labels: dict[str, int] = {}
        # (position_of_operand, label, end_of_instruction)
        self.fixups: list[tuple[int, str, int]] = []

    # -- label management ----------------------------------------------
    def label(self, name: str) -> "Emitter":
        self.labels[name] = len(self.buf)
        return self

    # -- raw emit helpers ----------------------------------------------
    def _op(self, op: Op):
        self.buf.append(int(op))

    def push_int(self, v: int):
        self._op(Op.PUSH_INT)
        self.buf += struct.pack("<i", v)
        return self

    def push_float(self, v: float):
        self._op(Op.PUSH_FLOAT)
        self.buf += struct.pack("<f", v)
        return self

    def push_str(self, s: str):
        self._op(Op.PUSH_STR)
        self.buf += struct.pack("<H", self.mod.intern(s))
        return self

    def push_null(self):
        self._op(Op.PUSH_NULL); return self

    def push_true(self):
        self._op(Op.PUSH_TRUE); return self

    def push_false(self):
        self._op(Op.PUSH_FALSE); return self

    def pop(self):
        self._op(Op.POP); return self

    def dup(self):
        self._op(Op.DUP); return self

    def load(self, slot: int):
        self._op(Op.LOAD); self.buf.append(slot & 0xFF); return self

    def store(self, slot: int):
        self._op(Op.STORE); self.buf.append(slot & 0xFF); return self

    def load_global(self, name: str):
        self._op(Op.LOAD_GLOBAL); self.buf += struct.pack("<H", self.mod.intern(name)); return self

    def store_global(self, name: str):
        self._op(Op.STORE_GLOBAL); self.buf += struct.pack("<H", self.mod.intern(name)); return self

    def _simple(self, op: Op):
        self._op(op); return self

    # arithmetic / logic shortcuts
    def add(self): return self._simple(Op.ADD)
    def sub(self): return self._simple(Op.SUB)
    def mul(self): return self._simple(Op.MUL)
    def div(self): return self._simple(Op.DIV)
    def mod(self): return self._simple(Op.MOD)
    def neg(self): return self._simple(Op.NEG)
    def eq(self): return self._simple(Op.EQ)
    def ne(self): return self._simple(Op.NE)
    def lt(self): return self._simple(Op.LT)
    def le(self): return self._simple(Op.LE)
    def gt(self): return self._simple(Op.GT)
    def ge(self): return self._simple(Op.GE)
    def and_(self): return self._simple(Op.AND)
    def or_(self): return self._simple(Op.OR)
    def not_(self): return self._simple(Op.NOT)
    def band(self): return self._simple(Op.BAND)
    def bor(self): return self._simple(Op.BOR)
    def bxor(self): return self._simple(Op.BXOR)
    def shl(self): return self._simple(Op.SHL)
    def shr(self): return self._simple(Op.SHR)

    # branches (target given as label name)
    def _branch(self, op: Op, label: str):
        self._op(op)
        operand_pos = len(self.buf)
        self.buf += b"\x00\x00"            # placeholder
        end = len(self.buf)
        self.fixups.append((operand_pos, label, end))
        return self

    def jmp(self, label: str): return self._branch(Op.JMP, label)
    def jz(self, label: str): return self._branch(Op.JZ, label)
    def jnz(self, label: str): return self._branch(Op.JNZ, label)

    def call(self, func_idx: int, argc: int):
        self._op(Op.CALL); self.buf += struct.pack("<HB", func_idx, argc); return self

    def syscall(self, name: str, argc: int):
        self._op(Op.SYSCALL)
        self.buf += struct.pack("<HB", self.mod.intern(name), argc)
        return self

    def ret(self): return self._simple(Op.RET)
    def ret_void(self): return self._simple(Op.RET_VOID)
    def halt(self): return self._simple(Op.HALT)

    # -- finish ---------------------------------------------------------
    def build(self) -> bytes:
        for operand_pos, label, end in self.fixups:
            if label not in self.labels:
                raise KeyError(f"undefined label: {label}")
            rel = self.labels[label] - end
            struct.pack_into("<h", self.buf, operand_pos, rel)
        return bytes(self.buf)


def make_function(module: GSModule, name: str, nargs: int, nlocals: int,
                  build_fn) -> GSFunction:
    """Helper: ``build_fn(emitter)`` populates the body."""
    em = Emitter(module)
    build_fn(em)
    fn = GSFunction(name=name, nargs=nargs, nlocals=nlocals, code=em.build())
    module.functions.append(fn)
    return fn
