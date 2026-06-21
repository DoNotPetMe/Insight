"""Capstone-backed disassembly for native code.

Wraps Capstone so the rest of Insight deals with a small, stable instruction
type and a single ``Disassembler`` object configured from a BinaryView.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import capstone as cs

from ..core.binary import BinaryView

_ARCH_MAP = {
    "x86": (cs.CS_ARCH_X86, cs.CS_MODE_32),
    "x64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
    "arm": (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
    "arm64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
}


@dataclass
class Insn:
    addr: int
    size: int
    mnemonic: str
    op_str: str
    bytes: bytes
    groups: list = field(default_factory=list)
    # control-flow facts, filled from capstone groups
    is_call: bool = False
    is_jump: bool = False
    is_ret: bool = False
    is_cond: bool = False
    target: int | None = None   # branch/call target if it's an immediate

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {self.op_str}".strip()

    @property
    def end(self) -> int:
        return self.addr + self.size


class Disassembler:
    def __init__(self, view: BinaryView):
        self.view = view
        if view.arch not in _ARCH_MAP:
            raise ValueError(f"unsupported architecture: {view.arch}")
        arch, mode = _ARCH_MAP[view.arch]
        self.md = cs.Cs(arch, mode)
        self.md.detail = True
        self.md.skipdata = True
        self.arch = arch

    def _classify(self, ci) -> Insn:
        groups = list(ci.groups)
        is_call = cs.CS_GRP_CALL in groups
        is_jump = cs.CS_GRP_JUMP in groups
        is_ret = cs.CS_GRP_RET in groups
        # a "jump" with both branch targets (conditional) -> mnemonic test
        is_cond = is_jump and ci.mnemonic not in ("jmp", "b", "br")
        target = None
        try:
            if (is_call or is_jump) and ci.operands:
                op = ci.operands[-1]
                if op.type == cs.CS_OP_IMM:
                    target = op.imm
        except Exception:
            target = None
        return Insn(addr=ci.address, size=ci.size, mnemonic=ci.mnemonic,
                    op_str=ci.op_str, bytes=bytes(ci.bytes), groups=groups,
                    is_call=is_call, is_jump=is_jump, is_ret=is_ret,
                    is_cond=is_cond, target=target)

    def linear(self, addr: int, size: int | None = None):
        """Linearly disassemble starting at a virtual address."""
        seg = self.view.segment_at(addr)
        if seg is None:
            return []
        start = addr - seg.addr
        blob = seg.data[start:start + size] if size else seg.data[start:]
        out = []
        for ci in self.md.disasm(blob, addr):
            out.append(self._classify(ci))
        return out

    def recursive(self, entry: int, max_insns: int = 100000):
        """Recursive-descent disassembly following direct branches/calls.

        Returns instructions keyed by address.  Indirect control flow is not
        followed (it needs data-flow analysis); linear sweep fills the gaps in
        the analysis layer.
        """
        seen: dict[int, Insn] = {}
        worklist = [entry]
        count = 0
        while worklist and count < max_insns:
            addr = worklist.pop()
            if addr in seen:
                continue
            seg = self.view.segment_at(addr)
            if seg is None or not seg.executable:
                continue
            blob = seg.data[addr - seg.addr:]
            for ci in self.md.disasm(blob, addr):
                count += 1
                insn = self._classify(ci)
                seen[insn.addr] = insn
                if insn.is_ret:
                    break
                if insn.is_jump:
                    if insn.target is not None:
                        worklist.append(insn.target)
                    if insn.is_cond:
                        worklist.append(insn.end)  # fallthrough
                    else:
                        break  # unconditional jump ends the run
                    continue
                if insn.is_call and insn.target is not None:
                    worklist.append(insn.target)
                # fallthrough continues the linear run within disasm()
            # capstone stops at decode errors; nothing more to do here
        return seen
