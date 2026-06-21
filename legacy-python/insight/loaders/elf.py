"""A self-contained ELF parser (32/64-bit, little/big endian).

Only the pieces Insight needs are parsed: the header (to learn the machine and
entry point), section headers (to locate code and the symbol table) and the
symbol table (to recover function names).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# e_machine values we map to Insight architectures
EM_386 = 3
EM_X86_64 = 62
EM_ARM = 40
EM_AARCH64 = 183

_MACHINE_NAMES = {
    EM_386: "x86", EM_X86_64: "x64", EM_ARM: "arm", EM_AARCH64: "arm64",
}

SHT_SYMTAB = 2
SHT_DYNSYM = 11
STT_FUNC = 2


@dataclass
class Section:
    name: str
    sh_type: int
    addr: int
    offset: int
    size: int
    entsize: int
    link: int
    flags: int
    data: bytes = b""

    @property
    def is_executable(self) -> bool:
        return bool(self.flags & 0x4)  # SHF_EXECINSTR


@dataclass
class Symbol:
    name: str
    value: int
    size: int
    type: int


@dataclass
class ELFFile:
    is64: bool
    little: bool
    machine: int
    arch: str
    entry: int
    sections: list[Section] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    raw: bytes = b""

    def section_by_name(self, name: str):
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def executable_sections(self):
        return [s for s in self.sections if s.is_executable and s.size]


def is_elf(data: bytes) -> bool:
    return data[:4] == b"\x7fELF"


def parse(data: bytes) -> ELFFile:
    if not is_elf(data):
        raise ValueError("not an ELF file")
    ei_class = data[4]
    ei_data = data[5]
    is64 = ei_class == 2
    little = ei_data == 1
    en = "<" if little else ">"

    if is64:
        # e_type,e_machine,e_version,e_entry,e_phoff,e_shoff,e_flags,
        # e_ehsize,e_phentsize,e_phnum,e_shentsize,e_shnum,e_shstrndx
        (_etype, machine, _ver, entry, _phoff, shoff, _flags, _ehsize,
         _phentsize, _phnum, shentsize, shnum, shstrndx) = struct.unpack_from(
            en + "HHIQQQIHHHHHH", data, 16)
    else:
        (_etype, machine, _ver, entry, _phoff, shoff, _flags, _ehsize,
         _phentsize, _phnum, shentsize, shnum, shstrndx) = struct.unpack_from(
            en + "HHIIIIIHHHHHH", data, 16)

    arch = _MACHINE_NAMES.get(machine, f"machine_{machine}")

    # ---- section headers ---------------------------------------------
    raw_sections = []
    for i in range(shnum):
        base = shoff + i * shentsize
        if is64:
            (name_off, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             sh_link, _info, _align, sh_entsize) = struct.unpack_from(
                en + "IIQQQQIIQQ", data, base)
        else:
            (name_off, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             sh_link, _info, _align, sh_entsize) = struct.unpack_from(
                en + "IIIIIIIIII", data, base)
        raw_sections.append((name_off, sh_type, sh_flags, sh_addr, sh_offset,
                             sh_size, sh_link, sh_entsize))

    # section header string table
    shstr_off = raw_sections[shstrndx][4] if shstrndx < len(raw_sections) else 0
    shstr_size = raw_sections[shstrndx][5] if shstrndx < len(raw_sections) else 0
    shstr = data[shstr_off:shstr_off + shstr_size]

    def cstr(blob: bytes, off: int) -> str:
        end = blob.find(b"\x00", off)
        return blob[off:end].decode("utf-8", "replace") if end >= 0 else ""

    sections: list[Section] = []
    for (name_off, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link,
         sh_entsize) in raw_sections:
        sec = Section(
            name=cstr(shstr, name_off), sh_type=sh_type, addr=sh_addr,
            offset=sh_offset, size=sh_size, entsize=sh_entsize, link=sh_link,
            flags=sh_flags,
            data=data[sh_offset:sh_offset + sh_size] if sh_type != 8 else b"")
        sections.append(sec)

    # ---- symbols ------------------------------------------------------
    symbols: list[Symbol] = []
    for sec in sections:
        if sec.sh_type not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        strtab = sections[sec.link].data if sec.link < len(sections) else b""
        entsize = sec.entsize or (24 if is64 else 16)
        count = sec.size // entsize if entsize else 0
        for i in range(count):
            base = i * entsize
            if is64:
                st_name, st_info, _st_other, _shndx, st_value, st_size = \
                    struct.unpack_from(en + "IBBHQQ", sec.data, base)
            else:
                st_name, st_value, st_size, st_info, _st_other, _shndx = \
                    struct.unpack_from(en + "IIIBBH", sec.data, base)
            stype = st_info & 0xF
            nm = cstr(strtab, st_name)
            if nm and stype == STT_FUNC and st_value:
                symbols.append(Symbol(name=nm, value=st_value, size=st_size,
                                      type=stype))

    return ELFFile(is64=is64, little=little, machine=machine, arch=arch,
                   entry=entry, sections=sections, symbols=symbols, raw=data)
