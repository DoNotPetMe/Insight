"""A format-neutral view of a loaded program.

``BinaryView`` is what the rest of Insight's native analysis works against, so
the disassembler and analyses don't care whether the input was ELF, PE or a
raw code blob.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..loaders import elf as elf_mod
from ..loaders import pe as pe_mod


@dataclass
class Segment:
    name: str
    addr: int            # virtual address the bytes are mapped at
    data: bytes
    executable: bool

    @property
    def end(self) -> int:
        return self.addr + len(self.data)

    def contains(self, addr: int) -> bool:
        return self.addr <= addr < self.end


@dataclass
class Symbol:
    name: str
    addr: int
    size: int = 0


@dataclass
class BinaryView:
    fmt: str                       # "elf" | "pe" | "raw"
    arch: str                      # "x86" | "x64" | "arm" | "arm64"
    entry: int
    segments: list[Segment] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    raw: bytes = b""

    # -- lookups --------------------------------------------------------
    def segment_at(self, addr: int):
        for s in self.segments:
            if s.contains(addr):
                return s
        return None

    def read(self, addr: int, size: int) -> bytes:
        seg = self.segment_at(addr)
        if seg is None:
            return b""
        off = addr - seg.addr
        return seg.data[off:off + size]

    def executable_segments(self):
        return [s for s in self.segments if s.executable]

    def symbol_at(self, addr: int):
        for s in self.symbols:
            if s.addr == addr:
                return s
        return None

    @property
    def bits(self) -> int:
        return 64 if self.arch in ("x64", "arm64") else 32


def load(data: bytes, arch_hint: str | None = None,
         base: int = 0x400000) -> BinaryView:
    """Detect the container format and build a BinaryView."""
    if elf_mod.is_elf(data):
        return _from_elf(elf_mod.parse(data))
    if pe_mod.is_pe(data):
        return _from_pe(pe_mod.parse(data))
    # raw code blob
    arch = arch_hint or "x64"
    seg = Segment(name=".text", addr=base, data=data, executable=True)
    return BinaryView(fmt="raw", arch=arch, entry=base, segments=[seg], raw=data)


def load_path(path: str, arch_hint: str | None = None) -> BinaryView:
    with open(path, "rb") as f:
        return load(f.read(), arch_hint=arch_hint)


def _from_elf(ef: "elf_mod.ELFFile") -> BinaryView:
    segments = []
    for s in ef.sections:
        if s.size and s.sh_type != 8 and (s.is_executable or s.name in (".text", ".rodata", ".data")):
            segments.append(Segment(name=s.name, addr=s.addr, data=s.data,
                                    executable=s.is_executable))
    symbols = [Symbol(name=s.name, addr=s.value, size=s.size) for s in ef.symbols]
    return BinaryView(fmt="elf", arch=ef.arch, entry=ef.entry,
                      segments=segments, symbols=symbols, raw=ef.raw)


def _from_pe(pf: "pe_mod.PEFile") -> BinaryView:
    segments = []
    for s in pf.sections:
        if s.raw_size:
            segments.append(Segment(name=s.name, addr=s.vaddr, data=s.data,
                                    executable=s.is_executable))
    symbols = [Symbol(name=s.name, addr=s.value, size=s.size) for s in pf.symbols]
    return BinaryView(fmt="pe", arch=pf.arch, entry=pf.entry,
                      segments=segments, symbols=symbols, raw=pf.raw)
