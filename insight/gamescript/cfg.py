"""Basic-block / control-flow-graph construction for GameScript functions."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import isa
from .isa import Op
from .disassembler import GSInsn, disassemble


# Opcodes that terminate a basic block.
_TERMINATORS = {Op.JMP, Op.JZ, Op.JNZ, Op.RET, Op.RET_VOID, Op.HALT}
_BRANCHES = {Op.JZ, Op.JNZ}


@dataclass
class BasicBlock:
    addr: int
    insns: list[GSInsn] = field(default_factory=list)
    succs: list[int] = field(default_factory=list)   # successor block addrs
    preds: list[int] = field(default_factory=list)

    @property
    def end(self) -> int:
        last = self.insns[-1]
        return last.addr + last.size

    @property
    def terminator(self) -> GSInsn | None:
        return self.insns[-1] if self.insns else None


@dataclass
class CFG:
    blocks: dict[int, BasicBlock]
    entry: int
    order: list[int]  # block addrs in ascending address order

    def block(self, addr: int) -> BasicBlock:
        return self.blocks[addr]


def build_cfg(code: bytes) -> CFG:
    insns = disassemble(code)
    if not insns:
        bb = BasicBlock(addr=0)
        return CFG(blocks={0: bb}, entry=0, order=[0])

    by_addr = {i.addr: i for i in insns}
    addrs = [i.addr for i in insns]
    end_addr = insns[-1].addr + insns[-1].size

    # ---- find block leaders ------------------------------------------
    leaders = {insns[0].addr}
    for i in insns:
        if i.op in _BRANCHES or i.op == Op.JMP:
            if i.target is not None and i.target in by_addr:
                leaders.add(i.target)
            # fallthrough after a conditional branch also starts a block
            nxt = i.addr + i.size
            if i.op in _BRANCHES and nxt in by_addr:
                leaders.add(nxt)
        elif i.op in (Op.RET, Op.RET_VOID, Op.HALT):
            nxt = i.addr + i.size
            if nxt in by_addr:
                leaders.add(nxt)

    leaders = sorted(leaders)

    # ---- slice instructions into blocks ------------------------------
    blocks: dict[int, BasicBlock] = {}
    for idx, lead in enumerate(leaders):
        nxt_lead = leaders[idx + 1] if idx + 1 < len(leaders) else end_addr
        body = [i for i in insns if lead <= i.addr < nxt_lead]
        blocks[lead] = BasicBlock(addr=lead, insns=body)

    # ---- wire up edges ------------------------------------------------
    leader_set = set(leaders)

    def block_starting_at(a: int) -> int | None:
        return a if a in leader_set else None

    for lead, bb in blocks.items():
        term = bb.terminator
        if term is None:
            continue
        fall = bb.end
        if term.op == Op.JMP:
            if term.target in blocks:
                bb.succs.append(term.target)
        elif term.op in _BRANCHES:
            # taken target then fallthrough
            if term.target in blocks:
                bb.succs.append(term.target)
            if fall in blocks:
                bb.succs.append(fall)
        elif term.op in (Op.RET, Op.RET_VOID, Op.HALT):
            pass  # no successors
        else:
            # ordinary instruction at end of block -> fallthrough
            if fall in blocks:
                bb.succs.append(fall)

    # predecessors
    for lead, bb in blocks.items():
        for s in bb.succs:
            blocks[s].preds.append(lead)

    return CFG(blocks=blocks, entry=leaders[0], order=leaders)
