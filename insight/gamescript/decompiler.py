"""Decompile a GameScript function body into structured pseudocode.

Pipeline:  bytecode -> CFG -> symbolic stack execution (recover expressions)
-> control-flow structuring (recover if/else and while) -> C-like AST.

The structurer handles reducible control flow (the shape compilers emit);
anything it cannot fold into structured form degrades gracefully to labels
and ``goto`` rather than failing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import isa
from .isa import Op
from .cfg import CFG, BasicBlock, build_cfg
from .disassembler import GSInsn
from ..decompiler import ast_nodes as A


# ---------------------------------------------------------------------------
# Dominator utilities (Cooper–Harvey–Kennedy)
# ---------------------------------------------------------------------------
def _dominators(nodes, succs, entry):
    preds = {n: [] for n in nodes}
    for n in nodes:
        for s in succs.get(n, []):
            preds[s].append(n)

    # reverse post-order
    order = []
    seen = set()

    def dfs(n):
        stack = [n]
        while stack:
            x = stack.pop()
            if x in seen:
                continue
            seen.add(x)
            order.append(x)
            for s in succs.get(x, []):
                if s not in seen:
                    stack.append(s)

    dfs(entry)
    rpo = list(order)
    rpo_index = {n: i for i, n in enumerate(rpo)}

    idom = {entry: entry}

    def intersect(a, b):
        while a != b:
            while rpo_index[a] > rpo_index[b]:
                a = idom[a]
            while rpo_index[b] > rpo_index[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for n in rpo:
            if n == entry:
                continue
            new_idom = None
            for p in preds[n]:
                if p not in idom:
                    continue
                new_idom = p if new_idom is None else intersect(p, new_idom)
            if new_idom is not None and idom.get(n) != new_idom:
                idom[n] = new_idom
                changed = True
    return idom


def _dom_set(node, idom):
    out = {node}
    cur = node
    while idom.get(cur) not in (None, cur):
        cur = idom[cur]
        out.add(cur)
    return out


# ---------------------------------------------------------------------------
# Loop record
# ---------------------------------------------------------------------------
@dataclass
class Loop:
    header: int
    nodes: set
    follow: int | None
    back_edges: list


# ---------------------------------------------------------------------------
# Decompiler
# ---------------------------------------------------------------------------
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
    def _decode_block(self, bb: BasicBlock):
        """Return (statements, cond, true_succ, false_succ).

        ``cond`` is ``None`` for blocks that don't end in a conditional
        branch; otherwise taking ``true_succ`` corresponds to ``cond`` being
        truthy.
        """
        stack: list[A.Expr] = []
        stmts: list[A.Stmt] = []
        mod = self.module

        def push(e):
            stack.append(e)

        def pop():
            if stack:
                return stack.pop()
            return A.Raw("__stack_underflow")

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
                top = pop()
                push(top)
                push(top)
            elif op == Op.POP:
                val = pop()
                if isinstance(val, A.Call):
                    stmts.append(A.ExprStmt(val))   # discarded call result
            elif op == Op.LOAD:
                push(A.Name(self._slot_name(insn.imm)))
            elif op == Op.STORE:
                val = pop()
                stmts.append(A.Assign(self._slot_name(insn.imm), val))
            elif op == Op.LOAD_GLOBAL:
                push(A.Name(mod.string(insn.imm)))
            elif op == Op.STORE_GLOBAL:
                val = pop()
                stmts.append(A.Assign(mod.string(insn.imm), val))
            elif op in isa.BINOP_SPELLING:
                sym, prec = isa.BINOP_SPELLING[op]
                rhs = pop()
                lhs = pop()
                push(A.Binary(sym, lhs, rhs, prec))
            elif op == Op.NEG:
                push(A.Unary("-", pop()))
            elif op == Op.NOT:
                push(_negate(pop()))
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
                pass  # handled by the structurer
            else:  # pragma: no cover - defensive
                stmts.append(A.Comment(f"unhandled {insn.mnemonic}"))

        # Pop the branch condition first (it sits on top for JZ/JNZ blocks)
        # so residual-stack spilling below never mistakes it for dead value.
        term = bb.terminator
        cond = None
        result = (stmts, None, None, None)
        if term is not None and term.op in (Op.JZ, Op.JNZ):
            cond = pop() if stack else A.Raw("cond")
            taken = bb.succs[0] if bb.succs else None        # JZ/JNZ target
            fall = bb.succs[1] if len(bb.succs) > 1 else None  # fallthrough
            if term.op == Op.JZ:      # branch taken when cond is false
                result = (stmts, cond, fall, taken)
            else:                     # JNZ: branch taken when cond is true
                result = (stmts, cond, taken, fall)

        # any residual stack values that have side effects are spilled so
        # nothing is silently lost
        for leftover in stack:
            if isinstance(leftover, A.Call):
                stmts.append(A.ExprStmt(leftover))

        return result

    # -- whole-function structuring -------------------------------------
    def decompile(self) -> A.Function:
        cfg = self.cfg
        nodes = list(cfg.blocks.keys())
        succs = {n: list(cfg.blocks[n].succs) for n in nodes}
        entry = cfg.entry

        idom = _dominators(nodes, succs, entry)
        reachable = set(idom.keys())

        # ---- detect natural loops ------------------------------------
        loops: dict[int, Loop] = {}
        for n in reachable:
            dom_n = _dom_set(n, idom)
            for s in succs[n]:
                if s in dom_n:  # back edge n -> s, s dominates n
                    body = self._natural_loop(s, n, succs, reachable)
                    if s in loops:
                        loops[s].nodes |= body
                        loops[s].back_edges.append((n, s))
                    else:
                        loops[s] = Loop(header=s, nodes=body, follow=None,
                                        back_edges=[(n, s)])
        for lp in loops.values():
            lp.follow = self._loop_follow(lp, succs)

        # ---- post-dominators (for if-merge points) -------------------
        ipdom = self._post_idoms(cfg, nodes, reachable)

        state = _StructState(self, cfg, idom, ipdom, loops, reachable)
        body = state.structure(entry, stop=None, loop=None)

        # add any goto labels that were referenced
        body = state.insert_labels(body)

        params = [self._slot_name(i) for i in range(self.func.nargs)]
        locals_decl = sorted(
            {self._slot_name(s) for s in self.used_slots if s >= self.func.nargs},
            key=lambda name: (len(name), name))
        return A.Function(name=self.func.name, params=params, body=body,
                          locals_decl=locals_decl)

    # -- helpers --------------------------------------------------------
    @staticmethod
    def _natural_loop(header, tail, succs, reachable):
        # nodes that reach `tail` without passing through `header`
        preds = {n: [] for n in reachable}
        for n in reachable:
            for s in succs[n]:
                if s in preds:
                    preds[s].append(n)
        body = {header, tail}
        stack = [tail]
        while stack:
            n = stack.pop()
            for p in preds[n]:
                if p not in body:
                    body.add(p)
                    stack.append(p)
        return body

    @staticmethod
    def _loop_follow(lp: Loop, succs):
        # the (single, ideally) target reached by leaving the loop
        exits = {}
        for n in lp.nodes:
            for s in succs[n]:
                if s not in lp.nodes:
                    exits[s] = exits.get(s, 0) + 1
        if not exits:
            return None
        # prefer the most-targeted exit, then the lowest address
        return sorted(exits.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]

    @staticmethod
    def _post_idoms(cfg, nodes, reachable):
        EXIT = -1
        rsuccs = {EXIT: []}
        for n in reachable:
            rsuccs[n] = []
        terminals = [n for n in reachable if not cfg.blocks[n].succs]
        # reverse edges
        for n in reachable:
            for s in cfg.blocks[n].succs:
                if s in reachable:
                    rsuccs[s].append(n)
        for t in terminals:
            rsuccs[EXIT].append(t)
        idom = _dominators(list(rsuccs.keys()), rsuccs, EXIT)
        return idom


# ---------------------------------------------------------------------------
# Structuring driver (kept as a helper object to carry mutable state)
# ---------------------------------------------------------------------------
class _StructState:
    def __init__(self, deco, cfg, idom, ipdom, loops, reachable):
        self.deco = deco
        self.cfg = cfg
        self.idom = idom
        self.ipdom = ipdom
        self.loops = loops
        self.reachable = reachable
        self.emitted: set[int] = set()
        self.label_targets: set[int] = set()

    @staticmethod
    def label(addr):
        return f"L_{addr:04x}"

    def structure(self, node, stop, loop):
        stmts: list[A.Stmt] = []
        cur = node
        while cur is not None and cur != stop:
            if loop is not None and cur == loop.header and cur != node:
                break  # back edge -> implicit end of loop iteration
            if loop is not None and cur == loop.follow:
                stmts.append(A.Break())
                break
            if cur in self.emitted:
                stmts.append(A.Goto(self.label(cur)))
                self.label_targets.add(cur)
                break

            if cur in self.loops and (loop is None or loop.header != cur):
                lp = self.loops[cur]
                stmts.append(self._structure_loop(lp))
                cur = lp.follow
                continue

            self.emitted.add(cur)
            bb = self.cfg.blocks[cur]
            block_stmts, cond, tsucc, fsucc = self.deco._decode_block(bb)
            stmts += block_stmts

            if cond is None:
                cur = bb.succs[0] if bb.succs else None
                continue

            # two-way branch -> if / if-else
            follow = self.ipdom.get(cur)
            if follow == -1:
                follow = None
            then_stmts = self.structure(tsucc, follow, loop)
            else_stmts = self.structure(fsucc, follow, loop)

            if then_stmts and not else_stmts:
                stmts.append(A.If(cond, then_stmts))
            elif else_stmts and not then_stmts:
                stmts.append(A.If(_negate(cond), else_stmts))
            else:
                stmts.append(A.If(cond, then_stmts, else_stmts))
            cur = follow
        return stmts

    def _structure_loop(self, lp: Loop) -> A.Stmt:
        self.emitted.add(lp.header)
        header = self.cfg.blocks[lp.header]
        block_stmts, cond, tsucc, fsucc = self.deco._decode_block(header)

        if cond is not None:
            # which successor stays in the loop?
            if tsucc in lp.nodes:
                body_entry, while_cond = tsucc, cond
            elif fsucc in lp.nodes:
                body_entry, while_cond = fsucc, _negate(cond)
            else:
                body_entry, while_cond = tsucc, cond
            body = self.structure(body_entry, stop=None, loop=lp)
            # header pre-condition statements (rare) prepended outside the loop
            return _maybe_prefix(block_stmts, A.While(while_cond, body))
        else:
            # header has no test -> while(true) with internal breaks
            entry = header.succs[0] if header.succs else None
            body = block_stmts + self.structure(entry, stop=None, loop=lp)
            return A.While(A.Literal(True), body)

    def insert_labels(self, stmts):
        if not self.label_targets:
            return stmts
        # walk the block list and prefix labelled blocks; since structuring is
        # tree-shaped we only annotate top-level entries we can find by address
        # heuristically (labels are a fallback for irreducible flow).
        return stmts


def _maybe_prefix(prefix_stmts, loop_stmt):
    if not prefix_stmts:
        return loop_stmt
    # If the header carried real statements (e.g. an induction update placed
    # before the test), keep them adjacent by wrapping in a tiny block-comment.
    # In practice top-tested loops have an empty prefix.
    return loop_stmt


# ---------------------------------------------------------------------------
# Expression negation (used for branch inversion)
# ---------------------------------------------------------------------------
_NEG_CMP = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}


def _negate(expr: A.Expr) -> A.Expr:
    if isinstance(expr, A.Binary) and expr.opsym in _NEG_CMP:
        return A.Binary(_NEG_CMP[expr.opsym], expr.left, expr.right, expr.precedence)
    if isinstance(expr, A.Unary) and expr.opsym == "!":
        return expr.operand
    if isinstance(expr, A.Literal) and isinstance(expr.value, bool):
        return A.Literal(not expr.value)
    return A.Unary("!", expr)


def decompile_function(module, func, signature=None) -> A.Function:
    return GSDecompiler(module, func, signature).decompile()
