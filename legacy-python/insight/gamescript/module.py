"""Reading and writing GameScript VM modules (the on-disk container)."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import isa


@dataclass
class GSFunction:
    name: str
    nargs: int
    nlocals: int
    code: bytes
    # filled in by the loader; offset of the body within the code blob.
    offset: int = 0


@dataclass
class GSModule:
    strings: list[str] = field(default_factory=list)
    functions: list[GSFunction] = field(default_factory=list)

    # -- string pool helpers --------------------------------------------
    def intern(self, s: str) -> int:
        if s in self.strings:
            return self.strings.index(s)
        self.strings.append(s)
        return len(self.strings) - 1

    def string(self, idx: int) -> str:
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return f"str_{idx}"

    # -- serialisation ---------------------------------------------------
    def to_bytes(self) -> bytes:
        # Intern every function name first so the string pool is complete
        # before it is written out.
        name_indices = [self.intern(fn.name) for fn in self.functions]

        out = bytearray()
        out += isa.MAGIC
        out += struct.pack("<H", len(self.strings))
        for s in self.strings:
            raw = s.encode("utf-8")
            out += struct.pack("<H", len(raw)) + raw

        # Lay code bodies out back-to-back and record their offsets.
        code_blob = bytearray()
        records = []
        for fn, name_idx in zip(self.functions, name_indices):
            offset = len(code_blob)
            code_blob += fn.code
            records.append((name_idx, fn.nargs, fn.nlocals,
                            offset, len(fn.code)))

        out += struct.pack("<H", len(self.functions))
        for name_idx, nargs, nlocals, offset, length in records:
            out += struct.pack("<HBBII", name_idx, nargs, nlocals, offset, length)
        out += code_blob
        return bytes(out)

    @classmethod
    def from_bytes(cls, data: bytes) -> "GSModule":
        if data[:4] != isa.MAGIC:
            raise ValueError("not a GameScript module (bad magic)")
        pos = 4
        (nstr,) = struct.unpack_from("<H", data, pos)
        pos += 2
        strings = []
        for _ in range(nstr):
            (ln,) = struct.unpack_from("<H", data, pos)
            pos += 2
            strings.append(data[pos:pos + ln].decode("utf-8", "replace"))
            pos += ln

        (nfunc,) = struct.unpack_from("<H", data, pos)
        pos += 2
        records = []
        for _ in range(nfunc):
            name_idx, nargs, nlocals, offset, length = struct.unpack_from(
                "<HBBII", data, pos)
            pos += 12
            records.append((name_idx, nargs, nlocals, offset, length))

        code_blob = data[pos:]
        functions = []
        for name_idx, nargs, nlocals, offset, length in records:
            body = code_blob[offset:offset + length]
            functions.append(GSFunction(
                name=strings[name_idx] if name_idx < len(strings) else f"fn_{name_idx}",
                nargs=nargs, nlocals=nlocals, code=body, offset=offset))

        mod = cls(strings=strings, functions=functions)
        return mod

    @staticmethod
    def is_module(data: bytes) -> bool:
        return data[:4] == isa.MAGIC
