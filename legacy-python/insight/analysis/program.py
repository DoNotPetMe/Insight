"""Native program analysis: discover functions and their basic blocks.

Function entry points come from three sources: the binary's symbol table, the
declared entry point, and the targets of `call` instructions found while
disassembling.  Each function is then carved into basic blocks to give the
decompiler a control-flow graph to work from.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.binary import BinaryView
from ..disasm.engine import Disassembler, Insn


@dataclass
class NativeBlock:
    addr: int
    insns: list[Insn] = field(default_factory=list)
    succs: list[int] = field(default_factory=list)

    @property
    def end(self) -> int:
        return self.insns[-1].end if self.insns else self.addr


@dataclass
class NativeFunction:
    addr: int
    name: str
    insns: list[Insn] = field(default_factory=list)        # sorted by address
    blocks: dict[int, NativeBlock] = field(default_factory=dict)
    block_order: list[int] = field(default_factory=list)
    calls: list[int] = field(default_factory=list)         # callee addresses

    @property
    def size(self) -> int:
        if not self.insns:
            return 0
        return self.insns[-1].end - self.addr


@dataclass
class Program:
    view: BinaryView
    functions: dict[int, NativeFunction] = field(default_factory=dict)
    function_order: list[int] = field(default_factory=list)

    def function_at(self, addr: int):
        return self.functions.get(addr)


def analyze(view: BinaryView) -> Program:
    dis = Disassembler(view)

    # ---- collect candidate entry points ------------------------------
    entries: dict[int, str] = {}
    for sym in view.symbols:
        if view.segment_at(sym.addr) and view.segment_at(sym.addr).executable:
            entries[sym.addr] = sym.name
    if view.segment_at(view.entry) and view.segment_at(view.entry).executable:
        entries.setdefault(view.entry, "entry")

    # discover more entries via call targets across a full recursive sweep
    all_insns = dis.recursive(view.entry) if view.entry in entries or entries else {}
    for start in list(entries):
        all_insns.update(dis.recursive(start))
    for insn in all_insns.values():
        if insn.is_call and insn.target is not None:
            seg = view.segment_at(insn.target)
            if seg and seg.executable:
                entries.setdefault(insn.target, f"sub_{insn.target:x}")

    prog = Program(view=view)

    # ---- carve each function -----------------------------------------
    sorted_entries = sorted(entries)
    for idx, start in enumerate(sorted_entries):
        name = entries[start]
        fn = _carve_function(dis, view, start, name, sorted_entries)
        if fn.insns:
            prog.functions[start] = fn
    prog.function_order = sorted(prog.functions)
    return prog


def _carve_function(dis, view, start, name, all_entries) -> NativeFunction:
    """Follow control flow within a single function, stopping at other funcs."""
    other_entries = set(all_entries) - {start}
    insns: dict[int, Insn] = {}
    worklist = [start]
    calls = []
    while worklist:
        addr = worklist.pop()
        if addr in insns or addr in other_entries:
            continue
        seg = view.segment_at(addr)
        if seg is None or not seg.executable:
            continue
        for insn in dis.linear(addr):
            if insn.addr in insns or (insn.addr in other_entries and insn.addr != start):
                break
            insns[insn.addr] = insn
            if insn.is_ret:
                break
            if insn.is_call:
                if insn.target is not None:
                    calls.append(insn.target)
                continue  # fall through to next instruction
            if insn.is_jump:
                if insn.target is not None and view.segment_at(insn.target) \
                        and view.segment_at(insn.target).executable:
                    worklist.append(insn.target)
                if insn.is_cond:
                    worklist.append(insn.end)
                break
        # linear() already walked the straight-line run
    ordered = [insns[a] for a in sorted(insns)]
    fn = NativeFunction(addr=start, name=name, insns=ordered,
                        calls=sorted(set(calls)))
    _build_blocks(fn, view)
    return fn


def _build_blocks(fn: NativeFunction, view):
    if not fn.insns:
        return
    addr_set = {i.addr for i in fn.insns}
    leaders = {fn.insns[0].addr}
    for insn in fn.insns:
        if insn.is_jump:
            if insn.target in addr_set:
                leaders.add(insn.target)
            if insn.is_cond and insn.end in addr_set:
                leaders.add(insn.end)
        elif insn.is_ret:
            if insn.end in addr_set:
                leaders.add(insn.end)
    leaders = sorted(leaders)
    by_addr = {i.addr: i for i in fn.insns}
    ordered_addrs = sorted(addr_set)

    for idx, lead in enumerate(leaders):
        nxt = leaders[idx + 1] if idx + 1 < len(leaders) else None
        body = [by_addr[a] for a in ordered_addrs
                if a >= lead and (nxt is None or a < nxt)]
        blk = NativeBlock(addr=lead, insns=body)
        if body:
            term = body[-1]
            if term.is_jump:
                if term.target in addr_set:
                    blk.succs.append(term.target)
                if term.is_cond and term.end in addr_set:
                    blk.succs.append(term.end)
            elif term.is_ret:
                pass
            else:
                if term.end in addr_set:
                    blk.succs.append(term.end)
        fn.blocks[lead] = blk
    fn.block_order = leaders
