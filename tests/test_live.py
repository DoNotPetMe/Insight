"""Tests for the live memory-scanning module.

The scan tests target the test process's own memory, so they need no external
game and run anywhere ``/proc`` is available (Linux). They skip elsewhere.
"""

import ctypes
import os
import platform
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from insight.live import memscan

_LINUX = platform.system() == "Linux" and os.path.exists("/proc/self/mem")


def test_authorization_required():
    with pytest.raises(PermissionError):
        memscan.LiveSession(os.getpid(), authorized=False)


def test_list_processes_includes_self():
    procs = memscan.list_processes()
    assert any(p.pid == os.getpid() for p in procs)


@pytest.mark.skipif(not _LINUX, reason="needs Linux /proc memory backend")
def test_scan_string_finds_marker():
    # keep a unique marker alive in this process's memory
    marker = b"INSIGHT_LIVE_TEST_MARKER_d3adb33f"
    holder = ctypes.create_string_buffer(marker)
    with memscan.LiveSession(os.getpid(), authorized=True) as s:
        assert s.regions(), "expected mapped regions"
        hits = s.scan_bytes(marker, limit=10)
        assert hits, "marker should be found in own memory"
    assert holder.raw.startswith(marker)


@pytest.mark.skipif(not _LINUX, reason="needs Linux /proc memory backend")
def test_scan_int_roundtrips():
    value = 0x4D2  # 1234
    holder = ctypes.c_int32(value)
    addr = ctypes.addressof(holder)
    with memscan.LiveSession(os.getpid(), authorized=True) as s:
        raw = s.read(addr, 4)
        assert int.from_bytes(raw, "little") == value
