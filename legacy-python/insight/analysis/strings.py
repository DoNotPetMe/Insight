"""Recover printable strings from a binary's segments."""

from __future__ import annotations

from dataclasses import dataclass

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09}


@dataclass
class FoundString:
    addr: int
    value: str
    segment: str


def find_strings(view, min_len: int = 4):
    out = []
    for seg in view.segments:
        data = seg.data
        i = 0
        n = len(data)
        while i < n:
            if data[i] in _PRINTABLE:
                j = i
                while j < n and data[j] in _PRINTABLE:
                    j += 1
                if j - i >= min_len:
                    out.append(FoundString(addr=seg.addr + i,
                                           value=data[i:j].decode("ascii", "replace"),
                                           segment=seg.name))
                i = j
            else:
                i += 1
    return out
