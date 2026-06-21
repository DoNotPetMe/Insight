"""Live process-memory inspection — the "scan while playing" capability.

Two backends:

* a native Linux backend over ``/proc/<pid>/maps`` + ``/proc/<pid>/mem`` (no
  third-party dependency, used for tests and Linux hosts), and
* a cross-platform backend built on **PyMemoryEditor** (MIT) for Windows and
  macOS, used automatically when that package is installed.

Only use this on software you are authorised to inspect (your own builds, or
games you own for personal modding/research).  Reading another process's memory
typically requires elevated privileges.
"""

from __future__ import annotations

import os
import platform
import struct
from dataclasses import dataclass


@dataclass
class Region:
    start: int
    end: int
    perms: str
    path: str = ""

    @property
    def size(self):
        return self.end - self.start

    @property
    def readable(self):
        return "r" in self.perms


@dataclass
class ProcessInfo:
    pid: int
    name: str


def list_processes():
    """Enumerate running processes (pid, name)."""
    out = []
    if os.path.isdir("/proc"):
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/comm") as f:
                    name = f.read().strip()
            except OSError:
                name = "?"
            out.append(ProcessInfo(int(entry), name))
        return sorted(out, key=lambda p: p.pid)
    # non-Linux: try PyMemoryEditor's helpers if present
    try:
        import psutil  # optional
        for p in psutil.process_iter(["pid", "name"]):
            out.append(ProcessInfo(p.info["pid"], p.info["name"] or "?"))
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Linux /proc backend
# ---------------------------------------------------------------------------
class _LinuxBackend:
    def __init__(self, pid: int):
        self.pid = pid
        self._mem = open(f"/proc/{pid}/mem", "rb", 0)

    def regions(self):
        regs = []
        with open(f"/proc/{self.pid}/maps") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 5:
                    continue
                rng, perms = parts[0], parts[1]
                path = parts[5] if len(parts) >= 6 else ""
                a, b = rng.split("-")
                regs.append(Region(int(a, 16), int(b, 16), perms, path))
        return regs

    def read(self, addr: int, size: int) -> bytes:
        try:
            self._mem.seek(addr)
            return self._mem.read(size)
        except (OSError, ValueError, OverflowError):
            return b""

    def close(self):
        try:
            self._mem.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Cross-platform PyMemoryEditor backend
# ---------------------------------------------------------------------------
class _PMEBackend:
    def __init__(self, pid: int):
        from PyMemoryEditor import OpenProcess
        self._proc = OpenProcess(pid=pid)

    def regions(self):
        out = []
        try:
            for info in self._proc.get_memory_regions():
                base = info.get("address", info.get("base", 0))
                size = info.get("size", info.get("region_size", 0))
                out.append(Region(base, base + size, "r--"))
        except Exception:
            pass
        return out

    def read(self, addr: int, size: int) -> bytes:
        try:
            return bytes(self._proc.read_process_memory(addr, bytes, size))
        except Exception:
            return b""

    def close(self):
        try:
            self._proc.close()
        except Exception:
            pass


def _make_backend(pid: int):
    if platform.system() == "Linux" and os.path.exists(f"/proc/{pid}/mem"):
        return _LinuxBackend(pid)
    try:
        return _PMEBackend(pid)
    except Exception as exc:
        raise RuntimeError(
            "no usable memory backend (install PyMemoryEditor on this platform)"
        ) from exc


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------
class LiveSession:
    """An attached process you can read and scan.

    ``authorized=True`` is required as an explicit acknowledgement that you have
    permission to inspect the target process.
    """

    _CHUNK = 1 << 20  # 1 MiB scan window

    def __init__(self, pid: int, authorized: bool = False):
        if not authorized:
            raise PermissionError(
                "refusing to attach without authorized=True — only inspect "
                "processes you own or are permitted to analyse")
        self.pid = pid
        self.backend = _make_backend(pid)

    # context manager sugar
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def regions(self):
        return self.backend.regions()

    def read(self, addr: int, size: int) -> bytes:
        return self.backend.read(addr, size)

    def _iter_readable(self, want_writable=False):
        for r in self.backend.regions():
            if not r.readable:
                continue
            if want_writable and "w" not in r.perms:
                continue
            if r.path in ("[vvar]", "[vsyscall]"):
                continue
            yield r

    def scan_bytes(self, needle: bytes, limit: int = 1000, writable_only=False):
        """Return addresses where ``needle`` appears in mapped memory."""
        hits = []
        for r in self._iter_readable(writable_only):
            addr = r.start
            overlap = len(needle) - 1
            while addr < r.end:
                chunk = self.read(addr, min(self._CHUNK, r.end - addr))
                if not chunk:
                    break
                base = 0
                while True:
                    i = chunk.find(needle, base)
                    if i < 0:
                        break
                    hits.append(addr + i)
                    if len(hits) >= limit:
                        return hits
                    base = i + 1
                addr += len(chunk) - overlap if len(chunk) > overlap else len(chunk)
        return hits

    def scan_string(self, text: str, encoding="utf-8", **kw):
        return self.scan_bytes(text.encode(encoding), **kw)

    def scan_int(self, value: int, size: int = 4, signed=True, **kw):
        fmt = {1: "b", 2: "h", 4: "i", 8: "q"}[size]
        if not signed:
            fmt = fmt.upper()
        return self.scan_bytes(struct.pack("<" + fmt, value), **kw)

    def close(self):
        self.backend.close()
