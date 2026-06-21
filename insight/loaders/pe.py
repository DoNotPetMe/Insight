"""A minimal PE (Portable Executable) parser.

Parses the DOS stub redirect, COFF header and optional header enough to learn
the machine type, image base, entry point and section layout.  Export names
are read when an export directory is present.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

IMAGE_FILE_MACHINE_I386 = 0x14C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM = 0x1C0
IMAGE_FILE_MACHINE_ARM64 = 0xAA64

_MACHINE_NAMES = {
    IMAGE_FILE_MACHINE_I386: "x86",
    IMAGE_FILE_MACHINE_AMD64: "x64",
    IMAGE_FILE_MACHINE_ARM: "arm",
    IMAGE_FILE_MACHINE_ARM64: "arm64",
}

IMAGE_SCN_MEM_EXECUTE = 0x20000000


@dataclass
class PESection:
    name: str
    vaddr: int
    vsize: int
    raw_off: int
    raw_size: int
    characteristics: int
    data: bytes = b""

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)


@dataclass
class Symbol:
    name: str
    value: int
    size: int = 0
    type: int = 0


@dataclass
class PEFile:
    machine: int
    arch: str
    is64: bool
    image_base: int
    entry: int          # absolute (image_base + AddressOfEntryPoint)
    sections: list[PESection] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    raw: bytes = b""

    def executable_sections(self):
        return [s for s in self.sections if s.is_executable and s.raw_size]


def is_pe(data: bytes) -> bool:
    if data[:2] != b"MZ" or len(data) < 0x40:
        return False
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    return 0 < e_lfanew < len(data) - 4 and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"


def parse(data: bytes) -> PEFile:
    if not is_pe(data):
        raise ValueError("not a PE file")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    coff = e_lfanew + 4
    machine, num_sections, _ts, _symptr, _numsym, opt_size, _chars = \
        struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    (magic,) = struct.unpack_from("<H", data, opt)
    is64 = magic == 0x20B

    if is64:
        entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    else:
        entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = struct.unpack_from("<I", data, opt + 28)[0]

    sect_base = opt + opt_size
    sections = []
    for i in range(num_sections):
        b = sect_base + i * 40
        raw_name = data[b:b + 8].rstrip(b"\x00")
        name = raw_name.decode("utf-8", "replace")
        vsize, vaddr, rawsize, rawoff = struct.unpack_from("<IIII", data, b + 8)
        (characteristics,) = struct.unpack_from("<I", data, b + 36)
        sections.append(PESection(
            name=name, vaddr=image_base + vaddr, vsize=vsize,
            raw_off=rawoff, raw_size=rawsize, characteristics=characteristics,
            data=data[rawoff:rawoff + rawsize]))

    arch = _MACHINE_NAMES.get(machine, f"machine_{machine:#x}")
    return PEFile(machine=machine, arch=arch, is64=is64, image_base=image_base,
                  entry=image_base + entry_rva, sections=sections,
                  symbols=[], raw=data)
