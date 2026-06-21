"""Generic control-flow structuring, shared by every bytecode front end.

Given a control-flow graph (successor lists keyed by block address) and a
callback that lifts each block to ``(statements, cond, true_succ, false_succ)``,
this recovers ``if``/``else`` and ``while`` using dominator / post-dominator
analysis and natural-loop detection.  Irreducible flow degrades to labels and
``goto`` instead of failing.

The GameScript front end, and the GML/GDScript/Blueprint front ends, all plug
into this same engine -- only their per-block lifting differs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import ast_nodes as A

# A block-lifter returns: (statements, condition_or_None, true_succ, false_succ)
BlockLifter = Callable[[int], tuple]


# ---------------------------------------------------------------------------
# Dominators (Cooper–Harvey–Kennedy)
# ---------------------------------------------------------------------------
def dominators(nodes, succs, entry):
    preds = {n: [] for n in nodes}
    for n in nodes:
        for s in succs.get(n, []):
            preds.setdefault(s, []).append(n)

    order, seen = [], set()
    stack = [entry]
    while stack:
        x = stack.pop()
        if x in seen:
            continue
        seen.add(x)
        order.append(x)
        for s in succs.get(x, []):
            if s not in seen:
                stack.append(s)
    rpo_index = {n: i for i, n in enumerate(order)}

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
        for n in order:
            if n == entry:
                continue
            new_idom = None
            for p in preds.get(n, []):
                if p not in idom:
                    continue
                new_idom = p if new_idom is None else intersect(p, new_idom)
            if new_idom is not None and idom.get(n) != new_idom:
                idom[n] = new_idom
                changed = True
    return idom


def dom_set(node, idom):
    out = {node}
    cur = node
    while idom.get(cur) not in (None, cur):
        cur = idom[cur]
        out.add(cur)
    return out


@dataclass
class Loop:
    header: int
    nodes: set
    follow: int | None
    back_edges: list


def _natural_loop(header, tail, succs, reachable):
    preds = {n: [] for n in reachable}
    for n in reachable:
        for s in succs.get(n, []):
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


def _loop_follow(lp: Loop, succs):
    exits = {}
    for n in lp.nodes:
        for s in succs.get(n, []):
            if s not in lp.nodes:
                exits[s] = exits.get(s, 0) + 1
    if not exits:
        return None
    return sorted(exits.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def _post_idoms(succs, reachable):
    EXIT = -1
    rsuccs = {EXIT: []}
    for n in reachable:
        rsuccs[n] = []
    terminals = [n for n in reachable if not succs.get(n)]
    for n in reachable:
        for s in succs.get(n, []):
            if s in reachable:
                rsuccs[s].append(n)
    for t in terminals:
        rsuccs[EXIT].append(t)
    return dominators(list(rsuccs.keys()), rsuccs, EXIT)


# ---------------------------------------------------------------------------
# Structuring driver
# ---------------------------------------------------------------------------
class _Structurer:
    def __init__(self, succs, entry, lift: BlockLifter):
        self.succs = succs
        self.entry = entry
        self.lift = lift
        self.idom = dominators(list(succs.keys()), succs, entry)
        self.reachable = set(self.idom.keys())

        self.loops: dict[int, Loop] = {}
        for n in self.reachable:
            dn = dom_set(n, self.idom)
            for s in self.succs.get(n, []):
                if s in dn:  # back edge n -> s
                    body = _natural_loop(s, n, succs, self.reachable)
                    if s in self.loops:
                        self.loops[s].nodes |= body
                        self.loops[s].back_edges.append((n, s))
                    else:
                        self.loops[s] = Loop(s, body, None, [(n, s)])
        for lp in self.loops.values():
            lp.follow = _loop_follow(lp, succs)

        self.ipdom = _post_idoms(succs, self.reachable)
        self.emitted: set[int] = set()

    @staticmethod
    def label(addr):
        return f"L_{addr:04x}"

    def run(self):
        return self.structure(self.entry, None, None)

    def structure(self, node, stop, loop):
        stmts: list[A.Stmt] = []
        cur = node
        while cur is not None and cur != stop:
            if loop is not None and cur == loop.header and cur != node:
                break
            if loop is not None and cur == loop.follow:
                stmts.append(A.Break())
                break
            if cur in self.emitted:
                stmts.append(A.Goto(self.label(cur)))
                break

            if cur in self.loops and (loop is None or loop.header != cur):
                lp = self.loops[cur]
                stmts.append(self._loop(lp))
                cur = lp.follow
                continue

            self.emitted.add(cur)
            block_stmts, cond, tsucc, fsucc = self.lift(cur)
            stmts += block_stmts

            if cond is None:
                succ = self.succs.get(cur, [])
                cur = succ[0] if succ else None
                continue

            follow = self.ipdom.get(cur)
            if follow == -1:
                follow = None
            then_stmts = self.structure(tsucc, follow, loop)
            else_stmts = self.structure(fsucc, follow, loop)
            if then_stmts and not else_stmts:
                stmts.append(A.If(cond, then_stmts))
            elif else_stmts and not then_stmts:
                stmts.append(A.If(negate(cond), else_stmts))
            else:
                stmts.append(A.If(cond, then_stmts, else_stmts))
            cur = follow
        return stmts

    def _loop(self, lp: Loop):
        self.emitted.add(lp.header)
        block_stmts, cond, tsucc, fsucc = self.lift(lp.header)
        if cond is not None:
            if tsucc in lp.nodes:
                body_entry, wcond = tsucc, cond
            elif fsucc in lp.nodes:
                body_entry, wcond = fsucc, negate(cond)
            else:
                body_entry, wcond = tsucc, cond
            body = self.structure(body_entry, None, lp)
            return A.While(wcond, body)
        succ = self.succs.get(lp.header, [])
        entry = succ[0] if succ else None
        body = block_stmts + self.structure(entry, None, lp)
        return A.While(A.Literal(True), body)


def structure(succs, entry, lift: BlockLifter):
    """Structure a CFG into a list of statements."""
    return _Structurer(succs, entry, lift).run()


# ---------------------------------------------------------------------------
# Expression negation (used for branch inversion)
# ---------------------------------------------------------------------------
_NEG_CMP = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}


def negate(expr: A.Expr) -> A.Expr:
    if isinstance(expr, A.Binary) and expr.opsym in _NEG_CMP:
        return A.Binary(_NEG_CMP[expr.opsym], expr.left, expr.right, expr.precedence)
    if isinstance(expr, A.Unary) and expr.opsym == "!":
        return expr.operand
    if isinstance(expr, A.Literal) and isinstance(expr.value, bool):
        return A.Literal(not expr.value)
    return A.Unary("!", expr)
