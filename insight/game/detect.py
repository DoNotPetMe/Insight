"""Detect which engine produced a game, from a file or an install directory.

Detection combines container magic bytes (for single files) with directory
fingerprints (the layout shipped games have on disk).  The result is ranked by
confidence with the concrete evidence that triggered it, so the UI can explain
*why* it thinks a target is e.g. Unity IL2CPP.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import engines


@dataclass
class Detection:
    engine_id: str
    confidence: float          # 0..1
    evidence: list = field(default_factory=list)
    variant: str = ""          # e.g. "IL2CPP" / "Mono"

    @property
    def engine(self):
        return engines.get(self.engine_id)


# ---- single-file container magic -----------------------------------------
_MAGIC = [
    (b"UnityFS", "unity", "asset bundle"),
    (b"FORM", "gamemaker", "data.win FORM container"),
    (b"GDPC", "godot", ".pck archive"),
    (b"RPA-3.0", "renpy", ".rpa archive"),
    (b"IWAD", "idtech", "WAD archive"),
    (b"PWAD", "idtech", "WAD archive"),
    (b"GSV1", "gamescript", "GameScript VM module"),
]

_UNREAL_PAK_MAGIC = b"\xE1\x12\x6F\x5A"  # 0x5A6F12E1, found in the pak footer


def detect_bytes(data: bytes, name: str = "") -> list[Detection]:
    out = []
    head = data[:32]
    for magic, eid, what in _MAGIC:
        if head.startswith(magic):
            out.append(Detection(eid, 0.95, [f"magic {magic!r} ({what})"]))
    # Unreal pak: magic sits near the end of the file
    if _UNREAL_PAK_MAGIC in data[-205:]:
        out.append(Detection("unreal", 0.9, ["Unreal .pak footer magic"]))
    # extension hints
    low = name.lower()
    ext_hint = {
        ".pak": ("unreal", "pak archive"), ".uasset": ("unreal", "uasset"),
        ".pck": ("godot", "pck"), ".rpa": ("renpy", "rpa"),
        ".rpyc": ("renpy", "compiled script"), ".vpk": ("source", "vpk"),
        ".wad": ("idtech", "wad"), ".pk3": ("idtech", "pk3"),
        ".rpgmvp": ("rpgmaker", "encrypted asset"), ".gsv": ("gamescript", "module"),
    }
    for ext, (eid, what) in ext_hint.items():
        if low.endswith(ext) and not any(d.engine_id == eid for d in out):
            out.append(Detection(eid, 0.6, [f"extension {ext} ({what})"]))
    return _rank(out)


# ---- directory fingerprints ----------------------------------------------
def detect_dir(path: str) -> list[Detection]:
    try:
        entries = os.listdir(path)
    except OSError:
        return []
    names = set(entries)
    lower = {e.lower() for e in entries}
    out: list[Detection] = []

    def has(*needles):
        return [n for n in entries if any(s in n.lower() for s in needles)]

    # --- Unity ---
    data_dirs = [e for e in entries if e.endswith("_Data") and
                 os.path.isdir(os.path.join(path, e))]
    unity_ev, variant = [], ""
    if data_dirs:
        unity_ev.append(f"{data_dirs[0]}/ data folder")
    if "UnityPlayer.dll" in names:
        unity_ev.append("UnityPlayer.dll")
    if "GameAssembly.dll" in names or "libil2cpp.so" in lower:
        unity_ev.append("IL2CPP runtime (GameAssembly/libil2cpp)")
        variant = "IL2CPP"
    for d in data_dirs:
        managed = os.path.join(path, d, "Managed")
        if os.path.isdir(managed) and any(
                f == "Assembly-CSharp.dll" for f in os.listdir(managed)):
            unity_ev.append(f"{d}/Managed/Assembly-CSharp.dll")
            variant = variant or "Mono"
        meta = os.path.join(path, d, "il2cpp_data", "Metadata",
                            "global-metadata.dat")
        if os.path.exists(meta):
            unity_ev.append("global-metadata.dat")
            variant = "IL2CPP"
    if unity_ev:
        out.append(Detection("unity", min(0.99, 0.6 + 0.1 * len(unity_ev)),
                             unity_ev, variant))

    # --- Unreal ---
    unreal_ev = []
    if any(os.path.isdir(os.path.join(path, e)) and e in ("Engine",) for e in entries):
        unreal_ev.append("Engine/ tree")
    paks = has(".pak")
    if paks:
        unreal_ev.append(f"{len(paks)} .pak archive(s)")
    if any(os.path.isdir(os.path.join(path, e, "Binaries", "Win64"))
           for e in entries if os.path.isdir(os.path.join(path, e))):
        unreal_ev.append("<Game>/Binaries/Win64")
    if unreal_ev:
        out.append(Detection("unreal", min(0.95, 0.55 + 0.12 * len(unreal_ev)),
                             unreal_ev))

    # --- GameMaker ---
    gm = [n for n in entries if n.lower() in
          ("data.win", "game.unx", "game.ios", "game.droid")]
    if gm or has("audiogroup"):
        out.append(Detection("gamemaker", 0.85, [f"{gm[0]}" if gm else "audiogroup*.dat"]))

    # --- Godot ---
    godot_ev = []
    if "project.godot" in lower:
        godot_ev.append("project.godot")
    pcks = has(".pck")
    if pcks:
        godot_ev.append(f"{len(pcks)} .pck archive(s)")
    if godot_ev:
        out.append(Detection("godot", 0.85, godot_ev))

    # --- Ren'Py ---
    if "renpy" in lower or has(".rpa") or has(".rpyc"):
        out.append(Detection("renpy", 0.8, ["renpy/ or .rpa/.rpyc files"]))

    # --- RPG Maker MV/MZ ---
    if "www" in lower and os.path.isdir(os.path.join(path, "www", "data")):
        out.append(Detection("rpgmaker", 0.85, ["www/data/*.json"]))
    elif any(e.endswith(".rpgproject") for e in entries):
        out.append(Detection("rpgmaker", 0.8, [".rpgproject"]))

    # --- Source ---
    if "gameinfo.txt" in lower or has(".vpk"):
        out.append(Detection("source", 0.8, ["gameinfo.txt or .vpk"]))

    # --- Construct ---
    if has("c2runtime.js", "c3runtime.js"):
        out.append(Detection("construct", 0.8, ["c2/c3runtime.js"]))

    return _rank(out)


def detect_path(path: str) -> list[Detection]:
    if os.path.isdir(path):
        return detect_dir(path)
    try:
        with open(path, "rb") as f:
            data = f.read(1 << 20)  # 1 MB is plenty for magic + pak footer
            # also read the tail for unreal pak footer
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size > len(data):
                f.seek(max(0, size - 256))
                data = data + f.read()
    except OSError:
        return []
    return detect_bytes(data, os.path.basename(path))


def _rank(dets: list[Detection]) -> list[Detection]:
    merged: dict[str, Detection] = {}
    for d in dets:
        if d.engine_id in merged:
            cur = merged[d.engine_id]
            cur.confidence = max(cur.confidence, d.confidence)
            cur.evidence += d.evidence
            cur.variant = cur.variant or d.variant
        else:
            merged[d.engine_id] = d
    return sorted(merged.values(), key=lambda d: -d.confidence)
