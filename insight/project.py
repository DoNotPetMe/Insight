"""Top-level facade tying the loaders, analyses and decompilers together.

A :class:`Project` auto-detects whether the input is a GameScript VM module or
a native binary and exposes a uniform list of functions, each renderable as
disassembly or pseudocode.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .core import binary as binmod
from .gamescript.module import GSModule
from .gamescript import disassembler as gsdis
from .gamescript.decompiler import decompile_function as gs_decompile
from .gamescript.cfg import build_cfg as gs_build_cfg
from .analysis.program import analyze as native_analyze
from .analysis.strings import find_strings
from .decompiler.native import decompile_native


@dataclass
class FunctionInfo:
    key: str            # stable identifier used by the UI/CLI
    name: str
    addr: int
    size: int
    kind: str           # "script" | "native"


class Project:
    def __init__(self, data: bytes, name: str = "input"):
        self.name = name
        self.data = data
        self.kind = "script" if GSModule.is_module(data) else "native"
        self._gs: GSModule | None = None
        self._prog = None
        self._view = None
        if self.kind == "script":
            self._gs = GSModule.from_bytes(data)
        else:
            self._view = binmod.load(data)
            self._prog = native_analyze(self._view)

    # -- construction ---------------------------------------------------
    @classmethod
    def from_path(cls, path: str) -> "Project":
        import os
        with open(path, "rb") as f:
            return cls(f.read(), name=os.path.basename(path))

    # -- metadata -------------------------------------------------------
    @property
    def arch(self) -> str:
        return "gamescript-vm" if self.kind == "script" else self._view.arch

    @property
    def fmt(self) -> str:
        return "gsvm" if self.kind == "script" else self._view.fmt

    def info(self) -> dict:
        d = {"name": self.name, "kind": self.kind, "format": self.fmt,
             "arch": self.arch, "functions": len(self.functions())}
        if self.kind == "native":
            d["entry"] = hex(self._view.entry)
            d["segments"] = [
                {"name": s.name, "addr": hex(s.addr), "size": len(s.data),
                 "exec": s.executable} for s in self._view.segments]
        else:
            d["strings"] = len(self._gs.strings)
        return d

    # -- functions ------------------------------------------------------
    def functions(self) -> list[FunctionInfo]:
        out = []
        if self.kind == "script":
            for idx, fn in enumerate(self._gs.functions):
                out.append(FunctionInfo(key=f"f{idx}", name=fn.name,
                                        addr=fn.offset, size=len(fn.code),
                                        kind="script"))
        else:
            for addr in self._prog.function_order:
                fn = self._prog.functions[addr]
                out.append(FunctionInfo(key=f"{addr:x}", name=fn.name,
                                        addr=addr, size=fn.size, kind="native"))
        return out

    def _gs_func(self, key: str):
        idx = int(key[1:])
        return self._gs.functions[idx]

    # -- rendering ------------------------------------------------------
    def disassembly(self, key: str) -> list[dict]:
        rows = []
        if self.kind == "script":
            fn = self._gs_func(key)
            for insn in gsdis.disassemble(fn.code):
                rows.append({"addr": f"{insn.addr:#06x}",
                             "bytes": "",
                             "text": gsdis.format_insn(insn, self._gs)})
        else:
            addr = int(key, 16)
            fn = self._prog.functions[addr]
            for insn in fn.insns:
                rows.append({"addr": f"{insn.addr:#x}",
                             "bytes": insn.bytes.hex(),
                             "text": insn.text})
        return rows

    def pseudocode(self, key: str) -> str:
        if self.kind == "script":
            fn = self._gs_func(key)
            return gs_decompile(self._gs, fn).render()
        addr = int(key, 16)
        fn = self._prog.functions[addr]
        return decompile_native(fn, self._view)

    def strings(self):
        if self.kind == "script":
            return [{"addr": f"#{i}", "value": s}
                    for i, s in enumerate(self._gs.strings)]
        return [{"addr": hex(s.addr), "value": s.value}
                for s in find_strings(self._view)]
