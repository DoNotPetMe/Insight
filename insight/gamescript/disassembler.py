"""Linear disassembly of GameScript bytecode into decoded instructions."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from . import isa
from .isa import Op, OperandKind


@dataclass
class GSInsn:
    addr: int              # offset within the function body
    op: Op
    size: int              # total bytes consumed (opcode + operands)
    # decoded operand(s); meaning depends on the opcode
    imm: object = None     # int / float immediate, or string-pool index
    target: int | None = None   # absolute branch target (for jumps)
    argc: int | None = None     # for CALL / SYSCALL

    @property
    def mnemonic(self) -> str:
        return isa.info(self.op).mnemonic


def decode_one(code: bytes, pos: int) -> GSInsn:
    opcode = code[pos]
    op = Op(opcode)
    inf = isa.info(opcode)
    kind = inf.operand
    start = pos
    pos += 1
    imm = None
    target = None
    argc = None

    if kind == OperandKind.I32:
        (imm,) = struct.unpack_from("<i", code, pos)
        pos += 4
    elif kind == OperandKind.F32:
        (imm,) = struct.unpack_from("<f", code, pos)
        pos += 4
    elif kind == OperandKind.U16:
        (imm,) = struct.unpack_from("<H", code, pos)
        pos += 2
    elif kind == OperandKind.U8:
        (imm,) = struct.unpack_from("<B", code, pos)
        pos += 1
    elif kind == OperandKind.REL16:
        (rel,) = struct.unpack_from("<h", code, pos)
        pos += 2
        target = pos + rel  # relative to the address after this instruction
    elif kind == OperandKind.CALL or kind == OperandKind.SYSCALL:
        (imm,) = struct.unpack_from("<H", code, pos)
        pos += 2
        (argc,) = struct.unpack_from("<B", code, pos)
        pos += 1

    return GSInsn(addr=start, op=op, size=pos - start,
                  imm=imm, target=target, argc=argc)


def disassemble(code: bytes) -> list[GSInsn]:
    """Linearly decode every instruction in a function body."""
    out = []
    pos = 0
    n = len(code)
    while pos < n:
        insn = decode_one(code, pos)
        out.append(insn)
        pos += insn.size
    return out


def format_insn(insn: GSInsn, module=None) -> str:
    """Human-readable text form of one instruction (for the disasm view)."""
    mn = insn.mnemonic
    if insn.op in (Op.PUSH_INT, Op.LOAD, Op.STORE):
        return f"{mn} {insn.imm}"
    if insn.op == Op.PUSH_FLOAT:
        return f"{mn} {insn.imm:g}"
    if insn.op == Op.PUSH_STR:
        s = module.string(insn.imm) if module else insn.imm
        return f'{mn} "{s}"' if module else f"{mn} #{insn.imm}"
    if insn.op in (Op.LOAD_GLOBAL, Op.STORE_GLOBAL):
        s = module.string(insn.imm) if module else f"#{insn.imm}"
        return f"{mn} {s}"
    if insn.op in (Op.JMP, Op.JZ, Op.JNZ):
        return f"{mn} -> {insn.target:#06x}"
    if insn.op == Op.CALL:
        name = module.functions[insn.imm].name if module and insn.imm < len(module.functions) else f"fn#{insn.imm}"
        return f"{mn} {name}, argc={insn.argc}"
    if insn.op == Op.SYSCALL:
        s = module.string(insn.imm) if module else f"#{insn.imm}"
        return f"{mn} {s}, argc={insn.argc}"
    return mn
