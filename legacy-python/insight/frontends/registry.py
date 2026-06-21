"""How Insight decompiles each engine's gameplay logic.

Every engine runtime maps to one of a few decompilation *strategies*, all of
which share the same back end (CFG → expression recovery → the structuring
engine in ``decompiler.structuring`` → C-like pseudocode):

* ``native``    — machine code, via the Capstone disassembler + native lifter
                  (covers Unity IL2CPP, Unreal C++, Source, id Tech).
* ``stackvm``   — a stack/register bytecode, lifted exactly like GameScript
                  (covers GameMaker GML, Godot GDScript, Unreal Blueprint).
* ``il``        — .NET CIL from managed assemblies (Unity Mono).
* ``script``    — already human-readable source/data (RPG Maker, Construct).

This registry lets the UI tell the user precisely how a given target will be
handled, and which path is fully implemented today versus staged behind an
external unpacker.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FrontendInfo:
    strategy: str
    status: str          # "ready" | "partial" | "planned"
    detail: str


# keyed by engine id (see game.engines)
FRONTENDS: dict[str, FrontendInfo] = {
    "gamescript": FrontendInfo("stackvm", "ready",
        "Reference stack-VM front end; full expression + control-flow recovery."),
    "unity": FrontendInfo("native", "ready",
        "IL2CPP native code decompiles through the native lifter; Mono CIL "
        "front end is staged (dnlib/ILSpy interop)."),
    "unreal": FrontendInfo("native", "partial",
        "Native modules decompile today; Blueprint bytecode reuses the stack-VM "
        "pipeline once kismet bytecode is decoded."),
    "gamemaker": FrontendInfo("stackvm", "partial",
        "GML bytecode plugs into the shared stack-VM structurer; container "
        "parsing via UndertaleModTool."),
    "godot": FrontendInfo("stackvm", "partial",
        "GDScript bytecode plugs into the shared stack-VM structurer; .pck "
        "extraction via Godot RE Tools."),
    "renpy": FrontendInfo("script", "partial",
        ".rpyc disassembly through the Python-AST path (unrpyc-compatible)."),
    "rpgmaker": FrontendInfo("script", "ready",
        "Logic ships as readable JS/JSON — inspected directly, no decompile."),
    "source": FrontendInfo("native", "ready",
        "Engine/game modules decompile through the native lifter."),
    "construct": FrontendInfo("script", "ready",
        "Runtime ships as readable JS/JSON — inspected directly."),
    "idtech": FrontendInfo("native", "ready",
        "Engine binary decompiles natively; ACS/ZScript staged."),
}


def for_engine(engine_id: str) -> FrontendInfo | None:
    return FRONTENDS.get(engine_id)
