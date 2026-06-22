//! Registry of game engines, their runtimes, and the free/open-source tools
//! that handle them.

pub struct Tool {
    pub name: &'static str,
    pub url: &'static str,
    pub purpose: &'static str,
}

pub struct Engine {
    pub id: &'static str,
    pub name: &'static str,
    pub runtime: &'static str,
    pub support: &'static str,
    pub tools: &'static [Tool],
}

macro_rules! tool {
    ($n:expr, $u:expr, $p:expr) => {
        Tool { name: $n, url: $u, purpose: $p }
    };
}

pub static ENGINES: &[Engine] = &[
    Engine {
        id: "unity",
        name: "Unity",
        runtime: "Mono/.NET IL (Assembly-CSharp.dll) or IL2CPP native (GameAssembly)",
        support: "IL2CPP native code decompiles through Insight's native lifter; assets via UnityPy.",
        tools: &[
            tool!("UnityPy", "https://github.com/K0lb3/UnityPy", "assets"),
            tool!("AssetRipper", "https://github.com/AssetRipper/AssetRipper", "both"),
            tool!("Il2CppDumper", "https://github.com/Perfare/Il2CppDumper", "scripts"),
            tool!("Il2CppInspectorRedux", "https://github.com/LukeFZ/Il2CppInspectorRedux", "scripts"),
            tool!("ILSpy", "https://github.com/icsharpcode/ILSpy", "scripts"),
        ],
    },
    Engine {
        id: "unreal",
        name: "Unreal Engine",
        runtime: "Native C++ plus Blueprint bytecode; assets in .pak/.uasset",
        support: "Native modules decompile via the native lifter; Blueprint bytecode is staged.",
        tools: &[
            tool!("CUE4Parse", "https://github.com/FabianFG/CUE4Parse", "assets"),
            tool!("FModel", "https://github.com/4sval/FModel", "assets"),
            tool!("pyUE4Parse", "https://github.com/MinshuG/pyUE4Parse", "assets"),
        ],
    },
    Engine {
        id: "gamemaker",
        name: "GameMaker (Studio)",
        runtime: "GML bytecode (VM) or YYC native; packed in data.win (FORM container)",
        support: "Container parsing/extraction via UndertaleModTool; GML lifting is staged.",
        tools: &[tool!("UndertaleModTool", "https://github.com/UnderminersTeam/UndertaleModTool", "both")],
    },
    Engine {
        id: "godot",
        name: "Godot",
        runtime: "GDScript bytecode (or native GDExtension); assets in .pck (GDPC)",
        support: ".pck extraction via Godot RE Tools; GDScript lifting is staged.",
        tools: &[tool!("Godot RE Tools (gdsdecomp)", "https://github.com/GDRETools/gdsdecomp", "both")],
    },
    Engine {
        id: "renpy",
        name: "Ren'Py",
        runtime: "Python-derived script compiled to .rpyc; archives in .rpa",
        support: "Archive listing; .rpyc via unrpyc-compatible path.",
        tools: &[
            tool!("unrpyc", "https://github.com/CensoredUsername/unrpyc", "scripts"),
            tool!("rpatool", "https://github.com/Shizmob/rpatool", "assets"),
        ],
    },
    Engine {
        id: "rpgmaker",
        name: "RPG Maker (MV/MZ)",
        runtime: "JavaScript plus JSON data (www/data/*.json)",
        support: "Logic ships as readable JS/JSON — inspect directly.",
        tools: &[tool!("RPG Maker MV/MZ decrypter", "https://github.com/Petschko/Java-RPG-Maker-MV-Decrypter", "assets")],
    },
    Engine {
        id: "chrome",
        name: "Chrome Engine (Techland)",
        runtime: "Native C++; content in numbered dataN.pak archives plus .scr scripts",
        support: "Native disassembler on the engine binary; pak/.scr listing. Techland \
                  ships official mod tools (ChromED / Developer Tools) for some titles.",
        tools: &[tool!("Dying Light Developer Tools (ChromED)", "https://store.steampowered.com/app/352380/", "both")],
    },
    Engine {
        id: "source",
        name: "Source Engine",
        runtime: "Native C++; content in .vpk, maps in .bsp",
        support: "Native disassembler on modules; VPK/BSP listing.",
        tools: &[
            tool!("VPKEdit", "https://github.com/craftablescience/VPKEdit", "assets"),
            tool!("bspsrc", "https://github.com/ata4/bspsrc", "assets"),
        ],
    },
    Engine {
        id: "construct",
        name: "Construct 2/3",
        runtime: "JavaScript runtime (c2/c3runtime.js) plus data.json",
        support: "Project data is readable JS/JSON.",
        tools: &[],
    },
    Engine {
        id: "idtech",
        name: "id Tech / Doom-derived",
        runtime: "Native; content in WAD/PK3; logic in ACS/DECORATE/ZScript",
        support: "WAD/PK3 listing; native disassembler on the engine binary.",
        tools: &[tool!("SLADE", "https://github.com/sirjuddington/SLADE", "both")],
    },
    Engine {
        id: "gamescript",
        name: "GameScript VM",
        runtime: "Reference stack-VM bytecode",
        support: "Full stack-VM decompilation (prototype front end).",
        tools: &[],
    },
];

pub fn get(id: &str) -> Option<&'static Engine> {
    ENGINES.iter().find(|e| e.id == id)
}
