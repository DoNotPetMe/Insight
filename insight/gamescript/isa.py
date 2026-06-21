"""Instruction set definition for the GameScript VM.

GameScript is a small, stack-based bytecode of the sort game engines commonly
ship for their embedded scripting layers (quest logic, AI, UI behaviour, ...).
Insight models it end-to-end so that compiled script blobs can be lifted back
into readable pseudocode for modding and study.

A module on disk has the layout::

    magic   : 4 bytes  = b"GSV1"
    nstr    : u16       number of string-pool entries
    strings : nstr * (u16 len + utf-8 bytes)
    nfunc   : u16       number of functions
    funcs   : nfunc * function-record
    code    : remaining bytes (all function bodies, concatenated)

A function-record is::

    name_idx : u16   index into the string pool
    nargs    : u8
    nlocals  : u8    total local slots (arguments occupy the first nargs)
    offset   : u32   start of the body inside the code blob
    length   : u32   body length in bytes

Operands are little-endian.  Jump targets are signed 16-bit offsets relative to
the address of the *following* instruction, matching typical VM encodings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Op(IntEnum):
    # --- stack / constants ----------------------------------------------
    NOP = 0x00
    PUSH_INT = 0x01      # operand: i32 immediate
    PUSH_FLOAT = 0x02    # operand: f32 immediate
    PUSH_STR = 0x03      # operand: u16 string-pool index
    PUSH_NULL = 0x04
    PUSH_TRUE = 0x05
    PUSH_FALSE = 0x06
    POP = 0x07
    DUP = 0x08

    # --- variables ------------------------------------------------------
    LOAD = 0x10          # operand: u8 local slot
    STORE = 0x11         # operand: u8 local slot
    LOAD_GLOBAL = 0x12   # operand: u16 string-pool index (global name)
    STORE_GLOBAL = 0x13  # operand: u16 string-pool index

    # --- arithmetic -----------------------------------------------------
    ADD = 0x20
    SUB = 0x21
    MUL = 0x22
    DIV = 0x23
    MOD = 0x24
    NEG = 0x25

    # --- comparison -----------------------------------------------------
    EQ = 0x30
    NE = 0x31
    LT = 0x32
    LE = 0x33
    GT = 0x34
    GE = 0x35

    # --- logical / bitwise ---------------------------------------------
    AND = 0x40
    OR = 0x41
    NOT = 0x42
    BAND = 0x43
    BOR = 0x44
    BXOR = 0x45
    SHL = 0x46
    SHR = 0x47

    # --- control flow ---------------------------------------------------
    JMP = 0x50           # operand: i16 relative target
    JZ = 0x51            # operand: i16; pop, branch if value is false/zero
    JNZ = 0x52           # operand: i16; pop, branch if value is truthy

    # --- calls ----------------------------------------------------------
    CALL = 0x60          # operands: u16 func index, u8 argc
    SYSCALL = 0x61       # operands: u16 name index (host API), u8 argc
    RET = 0x62           # return value on top of stack
    RET_VOID = 0x63
    HALT = 0x6F


class OperandKind(IntEnum):
    NONE = 0
    I32 = 1
    F32 = 2
    U16 = 3     # string-pool index
    U8 = 4      # local slot
    REL16 = 5   # signed branch offset
    CALL = 6    # u16 func index + u8 argc
    SYSCALL = 7  # u16 name index + u8 argc


@dataclass(frozen=True)
class OpInfo:
    op: Op
    mnemonic: str
    operand: OperandKind
    # net effect on stack depth (pops are negative); used by the analyser.
    stack_delta: int = 0
    pops: int = 0  # how many values consumed (for n-ary ops / variadic calls)


# size in bytes of each operand kind (excluding the 1-byte opcode)
OPERAND_SIZE = {
    OperandKind.NONE: 0,
    OperandKind.I32: 4,
    OperandKind.F32: 4,
    OperandKind.U16: 2,
    OperandKind.U8: 1,
    OperandKind.REL16: 2,
    OperandKind.CALL: 3,     # u16 + u8
    OperandKind.SYSCALL: 3,  # u16 + u8
}


def _t(op, mn, operand=OperandKind.NONE, stack_delta=0, pops=0):
    return OpInfo(op, mn, operand, stack_delta, pops)


TABLE: dict[int, OpInfo] = {info.op: info for info in [
    _t(Op.NOP, "nop"),
    _t(Op.PUSH_INT, "push.i", OperandKind.I32, +1),
    _t(Op.PUSH_FLOAT, "push.f", OperandKind.F32, +1),
    _t(Op.PUSH_STR, "push.s", OperandKind.U16, +1),
    _t(Op.PUSH_NULL, "push.null", stack_delta=+1),
    _t(Op.PUSH_TRUE, "push.true", stack_delta=+1),
    _t(Op.PUSH_FALSE, "push.false", stack_delta=+1),
    _t(Op.POP, "pop", stack_delta=-1, pops=1),
    _t(Op.DUP, "dup", stack_delta=+1),
    _t(Op.LOAD, "load", OperandKind.U8, +1),
    _t(Op.STORE, "store", OperandKind.U8, -1, pops=1),
    _t(Op.LOAD_GLOBAL, "load.g", OperandKind.U16, +1),
    _t(Op.STORE_GLOBAL, "store.g", OperandKind.U16, -1, pops=1),
    _t(Op.ADD, "add", stack_delta=-1, pops=2),
    _t(Op.SUB, "sub", stack_delta=-1, pops=2),
    _t(Op.MUL, "mul", stack_delta=-1, pops=2),
    _t(Op.DIV, "div", stack_delta=-1, pops=2),
    _t(Op.MOD, "mod", stack_delta=-1, pops=2),
    _t(Op.NEG, "neg", stack_delta=0, pops=1),
    _t(Op.EQ, "eq", stack_delta=-1, pops=2),
    _t(Op.NE, "ne", stack_delta=-1, pops=2),
    _t(Op.LT, "lt", stack_delta=-1, pops=2),
    _t(Op.LE, "le", stack_delta=-1, pops=2),
    _t(Op.GT, "gt", stack_delta=-1, pops=2),
    _t(Op.GE, "ge", stack_delta=-1, pops=2),
    _t(Op.AND, "and", stack_delta=-1, pops=2),
    _t(Op.OR, "or", stack_delta=-1, pops=2),
    _t(Op.NOT, "not", stack_delta=0, pops=1),
    _t(Op.BAND, "band", stack_delta=-1, pops=2),
    _t(Op.BOR, "bor", stack_delta=-1, pops=2),
    _t(Op.BXOR, "bxor", stack_delta=-1, pops=2),
    _t(Op.SHL, "shl", stack_delta=-1, pops=2),
    _t(Op.SHR, "shr", stack_delta=-1, pops=2),
    _t(Op.JMP, "jmp", OperandKind.REL16),
    _t(Op.JZ, "jz", OperandKind.REL16, -1, pops=1),
    _t(Op.JNZ, "jnz", OperandKind.REL16, -1, pops=1),
    _t(Op.CALL, "call", OperandKind.CALL),       # delta computed from argc
    _t(Op.SYSCALL, "syscall", OperandKind.SYSCALL),
    _t(Op.RET, "ret", stack_delta=-1, pops=1),
    _t(Op.RET_VOID, "ret.void"),
    _t(Op.HALT, "halt"),
]}

MAGIC = b"GSV1"

# Binary operators and their pseudocode spelling + precedence.
BINOP_SPELLING = {
    Op.ADD: ("+", 11), Op.SUB: ("-", 11),
    Op.MUL: ("*", 12), Op.DIV: ("/", 12), Op.MOD: ("%", 12),
    Op.SHL: ("<<", 10), Op.SHR: (">>", 10),
    Op.LT: ("<", 9), Op.LE: ("<=", 9), Op.GT: (">", 9), Op.GE: (">=", 9),
    Op.EQ: ("==", 8), Op.NE: ("!=", 8),
    Op.BAND: ("&", 7), Op.BXOR: ("^", 6), Op.BOR: ("|", 5),
    Op.AND: ("&&", 4), Op.OR: ("||", 3),
}


def info(opcode: int) -> OpInfo:
    try:
        return TABLE[Op(opcode)]
    except ValueError as exc:  # unknown opcode
        raise KeyError(f"unknown opcode 0x{opcode:02x}") from exc
