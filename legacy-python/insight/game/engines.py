"""Registry of game engines, their runtime formats, and the free/open-source
tools that handle them.

Insight uses this both to explain *what* a target is and to route ingestion to
the right extractor.  Tool references are open-source projects; where a project
is a usable Python library it is marked with ``pip`` so Insight can call it
directly when installed.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EngineTool:
    name: str
    url: str
    purpose: str            # "assets" | "scripts" | "both"
    pip: str | None = None  # importable module name if a usable Python lib


@dataclass(frozen=True)
class Engine:
    id: str
    name: str
    runtime: str            # what gameplay logic compiles to
    insight_support: str    # what Insight can do natively today
    tools: tuple = field(default_factory=tuple)


ENGINES: dict[str, Engine] = {}


def _reg(engine: Engine):
    ENGINES[engine.id] = engine
    return engine


_reg(Engine(
    id="unity",
    name="Unity",
    runtime="Mono/.NET IL (Assembly-CSharp.dll) or IL2CPP native (GameAssembly)",
    insight_support="IL2CPP native code → Insight's native disassembler/lifter; "
                    "Mono IL routed to an IL front end; assets via UnityPy.",
    tools=(
        EngineTool("UnityPy", "https://github.com/K0lb3/UnityPy", "assets", pip="UnityPy"),
        EngineTool("AssetStudio", "https://github.com/Perfare/AssetStudio", "assets"),
        EngineTool("AssetRipper", "https://github.com/AssetRipper/AssetRipper", "both"),
        EngineTool("Il2CppDumper", "https://github.com/Perfare/Il2CppDumper", "scripts"),
        EngineTool("Il2CppInspectorRedux", "https://github.com/LukeFZ/Il2CppInspectorRedux", "scripts"),
        EngineTool("ILSpy / ICSharpCode.Decompiler", "https://github.com/icsharpcode/ILSpy", "scripts"),
    ),
))

_reg(Engine(
    id="unreal",
    name="Unreal Engine",
    runtime="Native C++ plus Blueprint bytecode; assets in .pak/.uasset",
    insight_support="Native modules → native disassembler; Blueprint bytecode "
                    "routed to a stack-VM front end; assets via CUE4Parse/pyUE4Parse.",
    tools=(
        EngineTool("CUE4Parse", "https://github.com/FabianFG/CUE4Parse", "assets"),
        EngineTool("FModel", "https://github.com/4sval/FModel", "assets"),
        EngineTool("pyUE4Parse", "https://github.com/MinshuG/pyUE4Parse", "assets", pip="UE4Parse"),
        EngineTool("UnrealExporter", "https://github.com/luk-gg/UnrealExporter", "assets"),
    ),
))

_reg(Engine(
    id="gamemaker",
    name="GameMaker (Studio)",
    runtime="GML bytecode (VM) or YYC native; packed in data.win (FORM container)",
    insight_support="GML bytecode routed to Insight's stack-VM front end; "
                    "container parsing/extraction via UndertaleModTool.",
    tools=(
        EngineTool("UndertaleModTool", "https://github.com/UnderminersTeam/UndertaleModTool", "both"),
    ),
))

_reg(Engine(
    id="godot",
    name="Godot",
    runtime="GDScript bytecode (or native GDExtension); assets packed in .pck (GDPC)",
    insight_support="GDScript bytecode routed to Insight's stack-VM front end; "
                    ".pck extraction via Godot RE Tools (gdsdecomp).",
    tools=(
        EngineTool("Godot RE Tools (gdsdecomp)", "https://github.com/GDRETools/gdsdecomp", "both"),
    ),
))

_reg(Engine(
    id="renpy",
    name="Ren'Py",
    runtime="Python-derived script compiled to .rpyc; archives in .rpa",
    insight_support="Archive listing; .rpyc disassembly routed through the "
                    "Python-AST front end (unrpyc-compatible).",
    tools=(
        EngineTool("unrpyc", "https://github.com/CensoredUsername/unrpyc", "scripts"),
        EngineTool("rpatool", "https://github.com/Shizmob/rpatool", "assets"),
    ),
))

_reg(Engine(
    id="rpgmaker",
    name="RPG Maker (MV/MZ)",
    runtime="JavaScript plus JSON data (www/data/*.json); images may be .rpgmvp",
    insight_support="Direct JSON/JS inspection; no decompilation needed (logic "
                    "ships as readable JS/JSON).",
    tools=(
        EngineTool("RPG Maker MV/MZ decrypter", "https://github.com/Petschko/Java-RPG-Maker-MV-Decrypter", "assets"),
    ),
))

_reg(Engine(
    id="source",
    name="Source Engine",
    runtime="Native C++; content in .vpk, maps in .bsp",
    insight_support="Native disassembler on modules; VPK/BSP listing.",
    tools=(
        EngineTool("VPKEdit", "https://github.com/craftablescience/VPKEdit", "assets"),
        EngineTool("VRAD/BSP tools (bspsrc)", "https://github.com/ata4/bspsrc", "assets"),
    ),
))

_reg(Engine(
    id="construct",
    name="Construct 2/3",
    runtime="JavaScript runtime (c2runtime.js / c3runtime.js) plus data.json",
    insight_support="Direct JS/JSON inspection; project data is readable.",
    tools=(),
))

_reg(Engine(
    id="idtech",
    name="id Tech / Doom-derived",
    runtime="Native; content in WAD/PK3; logic in ACS/DECORATE/ZScript",
    insight_support="WAD/PK3 listing; native disassembler on the engine binary.",
    tools=(
        EngineTool("SLADE", "https://github.com/sirjuddington/SLADE", "both"),
    ),
))


def get(engine_id: str) -> Engine | None:
    return ENGINES.get(engine_id)
