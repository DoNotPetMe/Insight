"""Low-level pseudocode for native functions.

Full native decompilation (type and variable recovery, full structuring) is a
large undertaking; Insight ships an honest first layer: instructions are lifted
to readable C-like statements, compare/branch pairs are folded into ``if``
conditions, and control flow is rendered with labelled blocks and ``goto`` so
the recovered logic is easy to follow and to refine by hand.
"""

from __future__ import annotations

from ..analysis.program import NativeFunction
from ..core.binary import BinaryView


# x86/x64 conditional-jump mnemonic -> comparison operator (signed view)
_JCC = {
    "je": "==", "jz": "==", "jne": "!=", "jnz": "!=",
    "jg": ">", "jnle": ">", "jge": ">=", "jnl": ">=",
    "jl": "<", "jnge": "<", "jle": "<=", "jng": "<=",
    "ja": ">", "jae": ">=", "jb": "<", "jbe": "<=",
    "js": "< 0", "jns": ">= 0",
}

# binary "dst OP= src" instructions
_BINOP = {
    "add": "+=", "sub": "-=", "and": "&=", "or": "|=", "xor": "^=",
    "shl": "<<=", "sal": "<<=", "shr": ">>=", "sar": ">>=",
    "imul": "*=", "mul": "*=", "or": "|=",
}


def _label(addr: int) -> str:
    return f"loc_{addr:x}"


def _resolve_call(view: BinaryView, target):
    if target is None:
        return None
    sym = view.symbol_at(target)
    if sym:
        return sym.name
    return f"sub_{target:x}"


def decompile_native(fn: NativeFunction, view: BinaryView) -> str:
    """Produce pseudocode text for one native function."""
    lines = [f"// {view.arch} @ {fn.addr:#x}  ({len(fn.insns)} instructions)"]
    sig = f"void {fn.name}()" + " {"
    lines.append(sig)

    block_addrs = set(fn.block_order)
    last_cmp = None  # (lhs, rhs) from the most recent cmp/test

    for baddr in fn.block_order:
        blk = fn.blocks[baddr]
        # label every block that is a branch target for readability
        lines.append(f"{_label(baddr)}:")
        for insn in blk.insns:
            stmt = _lift_insn(insn, view, last_cmp)
            # update compare context
            if insn.mnemonic in ("cmp", "test"):
                ops = [o.strip() for o in insn.op_str.split(",")]
                if len(ops) == 2:
                    last_cmp = (ops[0], ops[1], insn.mnemonic)
            elif insn.mnemonic in _JCC:
                last_cmp = None  # consumed
            if stmt:
                lines.append("    " + stmt)
    lines.append("}")
    return "\n".join(lines)


def _lift_insn(insn, view, last_cmp) -> str:
    m = insn.mnemonic
    ops = [o.strip() for o in insn.op_str.split(",")] if insn.op_str else []

    if m == "nop" or m.startswith("nop"):
        return ""
    if m == "mov" or m == "movzx" or m == "movsx" or m == "movabs":
        if len(ops) == 2:
            return f"{ops[0]} = {ops[1]};"
    if m == "lea" and len(ops) == 2:
        inner = ops[1].strip("[]")
        return f"{ops[0]} = &({inner});"
    if m in _BINOP and len(ops) == 2:
        return f"{ops[0]} {_BINOP[m]} {ops[1]};"
    if m == "inc" and ops:
        return f"{ops[0]}++;"
    if m == "dec" and ops:
        return f"{ops[0]}--;"
    if m == "neg" and ops:
        return f"{ops[0]} = -{ops[0]};"
    if m == "not" and ops:
        return f"{ops[0]} = ~{ops[0]};"
    if m == "push" and ops:
        return f"push({ops[0]});"
    if m == "pop" and ops:
        return f"{ops[0]} = pop();"
    if m == "cmp" or m == "test":
        return f"// flags = {insn.text}"
    if insn.is_call:
        name = _resolve_call(view, insn.target)
        if name:
            return f"{name}();"
        return f"call({insn.op_str});  // indirect"
    if insn.is_ret:
        return "return;"
    if m in _JCC:
        op = _JCC[m]
        target = _label(insn.target) if insn.target is not None else "?"
        if last_cmp:
            lhs, rhs, kind = last_cmp
            if op.endswith("0"):  # js/jns
                cond = f"{lhs} {op}"
            else:
                cond = f"{lhs} {op} {rhs}"
            return f"if ({cond}) goto {target};"
        return f"if ({m}) goto {target};"
    if insn.is_jump:  # unconditional
        target = _label(insn.target) if insn.target is not None else insn.op_str
        return f"goto {target};"
    # fallback: keep the raw instruction as an annotated statement
    return f"__asm(\"{insn.text}\");"
