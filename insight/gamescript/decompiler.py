"""Decompile a GameScript function body into structured pseudocode.

Pipeline:  bytecode -> CFG -> symbolic stack execution (recover expressions)
-> shared control-flow structuring (``decompiler.structuring``) -> C-like AST.

Only the per-block lifting (symbolic stack execution) lives here; the if/else
and loop recovery is the engine-neutral structurer shared with the other
front ends.
"""

from __future__ import annotations

from . import isa
from .isa import Op
from .cfg import CFG, BasicBlock, build_cfg
from ..decompiler import ast_nodes as A
from ..decompiler import structuring


class GSDecompiler:
    def __init__(self, module, func, signature=None):
        self.module = module
        self.func = func
        self.signature = signature  # optional list of parameter names
        self.cfg: CFG = build_cfg(func.code)
        self.used_slots: set[int] = set()

    # -- variable naming ------------------------------------------------
    def _slot_name(self, slot: int) -> str:
        self.used_slots.add(slot)
        if self.signature and slot < len(self.signature):
            return self.signature[slot]
        if slot < self.func.nargs:
            return f"arg{slot}"
        return f"v{slot}"

    # -- symbolic execution of one block --------------------------------
    def _decode_block(self, addr: int):
        """Lift a block to ``(statements, cond, true_succ, false_succ)``."""
        bb = self.cfg.blocks[addr]
        stack: list[A.Expr] = []
        stmts: list[A.Stmt] = []
        mod = self.module

        def push(e):
            stack.append(e)

        def pop():
            return stack.pop() if stack else A.Raw("__stack_underflow")

        for insn in bb.insns:
            op = insn.op
            if op == Op.NOP:
                continue
            elif op == Op.PUSH_INT:
                push(A.Literal(insn.imm))
            elif op == Op.PUSH_FLOAT:
                push(A.Literal(float(insn.imm)))
            elif op == Op.PUSH_STR:
                push(A.Literal('"' + mod.string(insn.imm) + '"'))
            elif op == Op.PUSH_NULL:
                push(A.Literal("null"))
            elif op == Op.PUSH_TRUE:
                push(A.Literal(True))
            elif op == Op.PUSH_FALSE:
                push(A.Literal(False))
            elif op == Op.DUP:
                top = pop(); push(top); push(top)
            elif op == Op.POP:
                val = pop()
                if isinstance(val, A.Call):
                    stmts.append(A.ExprStmt(val))
            elif op == Op.LOAD:
                push(A.Name(self._slot_name(insn.imm)))
            elif op == Op.STORE:
                stmts.append(A.Assign(self._slot_name(insn.imm), pop()))
            elif op == Op.LOAD_GLOBAL:
                push(A.Name(mod.string(insn.imm)))
            elif op == Op.STORE_GLOBAL:
                stmts.append(A.Assign(mod.string(insn.imm), pop()))
            elif op in isa.BINOP_SPELLING:
                sym, prec = isa.BINOP_SPELLING[op]
                rhs = pop(); lhs = pop()
                push(A.Binary(sym, lhs, rhs, prec))
            elif op == Op.NEG:
                push(A.Unary("-", pop()))
            elif op == Op.NOT:
                push(structuring.negate(pop()))
            elif op == Op.CALL:
                argc = insn.argc or 0
                args = [pop() for _ in range(argc)][::-1]
                name = (mod.functions[insn.imm].name
                        if insn.imm < len(mod.functions) else f"fn_{insn.imm}")
                push(A.Call(name, args, is_host=False))
            elif op == Op.SYSCALL:
                argc = insn.argc or 0
                args = [pop() for _ in range(argc)][::-1]
                push(A.Call(mod.string(insn.imm), args, is_host=True))
            elif op == Op.RET:
                stmts.append(A.Return(pop()))
            elif op == Op.RET_VOID:
                stmts.append(A.Return(None))
            elif op == Op.HALT:
                stmts.append(A.ExprStmt(A.Raw("halt()")))
            elif op in (Op.JMP, Op.JZ, Op.JNZ):
                pass
            else:  # pragma: no cover - defensive
                stmts.append(A.Comment(f"unhandled {insn.mnemonic}"))

        term = bb.terminator
        result = (stmts, None, None, None)
        if term is not None and term.op in (Op.JZ, Op.JNZ):
            cond = pop() if stack else A.Raw("cond")
            taken = bb.succs[0] if bb.succs else None
            fall = bb.succs[1] if len(bb.succs) > 1 else None
            if term.op == Op.JZ:
                result = (stmts, cond, fall, taken)
            else:
                result = (stmts, cond, taken, fall)

        for leftover in stack:
            if isinstance(leftover, A.Call):
                stmts.append(A.ExprStmt(leftover))
        return result

    # -- whole-function structuring -------------------------------------
    def decompile(self) -> A.Function:
        succs = {addr: list(bb.succs) for addr, bb in self.cfg.blocks.items()}
        body = structuring.structure(succs, self.cfg.entry, self._decode_block)
        params = [self._slot_name(i) for i in range(self.func.nargs)]
        locals_decl = sorted(
            {self._slot_name(s) for s in self.used_slots if s >= self.func.nargs},
            key=lambda name: (len(name), name))
        return A.Function(name=self.func.name, params=params, body=body,
                          locals_decl=locals_decl)


def decompile_function(module, func, signature=None) -> A.Function:
    return GSDecompiler(module, func, signature).decompile()
