//! Launch helpers: turn a discovered map/level into the right way to load it
//! for the detected engine, and (optionally) start the game with those options.
//!
//! Insight surfaces the identifier and the engine's documented loading
//! mechanism (launch arguments and/or an in-game console command), and can
//! spawn the game executable for you. It cannot force content into a protected
//! process — for engines without a launch/console path (Unity, GameMaker, …)
//! the plan points at the appropriate mod tool instead.

use std::path::{Path, PathBuf};

use walkdir::WalkDir;

#[derive(Clone)]
pub struct LaunchPlan {
    pub program: Option<PathBuf>,
    pub args: Vec<String>,
    pub console_cmd: String,
    pub note: String,
    /// whether launching with these args is expected to load the target
    pub can_launch: bool,
}

fn looks_like_installer(name: &str) -> bool {
    let n = name.to_lowercase();
    ["unins", "redist", "setup", "crashreport", "crashpad", "vc_", "dxweb", "dxsetup", "install", "eac", "battleye"]
        .iter()
        .any(|p| n.contains(p))
}

/// Best guess at the main game executable in a folder: the largest .exe that
/// isn't an installer/redistributable, searched a few levels deep.
pub fn find_game_exe(dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(PathBuf, u64)> = None;
    for entry in WalkDir::new(dir).max_depth(3).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        let is_exe = p.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("exe")).unwrap_or(false);
        if !is_exe {
            continue;
        }
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if looks_like_installer(&name) {
            continue;
        }
        let sz = entry.metadata().map(|m| m.len()).unwrap_or(0);
        if best.as_ref().map(|(_, b)| sz > *b).unwrap_or(true) {
            best = Some((p.to_path_buf(), sz));
        }
    }
    best.map(|(p, _)| p)
}

/// Build a load plan for `target` (a map/level/scene id) on the given engine.
pub fn plan(engine_id: &str, exe: Option<PathBuf>, target: &str) -> LaunchPlan {
    // strip an extension and any leading path for console commands
    let bare = target
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(target)
        .trim_end_matches('"');

    match engine_id {
        "source" => LaunchPlan {
            program: exe,
            args: vec!["+map".into(), bare.into()],
            console_cmd: format!("map {bare}"),
            note: "Source: launches straight into the map, or paste the console command (~).".into(),
            can_launch: true,
        },
        "unreal" => LaunchPlan {
            program: exe,
            args: vec![target.into()],
            console_cmd: format!("open {bare}"),
            note: "Unreal: passes the map on the command line, or use the console (~): open <map>.".into(),
            can_launch: true,
        },
        "idtech" => LaunchPlan {
            program: exe,
            args: vec!["+map".into(), bare.into()],
            console_cmd: format!("map {bare}"),
            note: "id Tech / Doom-derived: +map on launch, or `map <name>` in the console.".into(),
            can_launch: true,
        },
        "chrome" => LaunchPlan {
            program: exe,
            args: vec!["-DEVELOPER".into()],
            console_cmd: bare.to_string(),
            note: "Chrome Engine (Dying Light): launch can enable developer mode (-DEVELOPER); load \
                   dev maps from the in-game developer console or open the project in ChromED."
                .into(),
            can_launch: true,
        },
        "godot" => LaunchPlan {
            program: exe,
            args: vec![],
            console_cmd: format!("get_tree().change_scene_to_file(\"res://{target}\")"),
            note: "Godot: load via a mod/autoload script with change_scene_to_file().".into(),
            can_launch: false,
        },
        "unity" => LaunchPlan {
            program: exe,
            args: vec![],
            console_cmd: format!("SceneManager.LoadScene(\"{bare}\")"),
            note: "Unity: load with a BepInEx/MelonLoader mod calling SceneManager.LoadScene.".into(),
            can_launch: false,
        },
        "gamemaker" => LaunchPlan {
            program: exe,
            args: vec![],
            console_cmd: format!("room_goto({bare})"),
            note: "GameMaker: patch a room_goto via UndertaleModTool.".into(),
            can_launch: false,
        },
        _ => LaunchPlan {
            program: exe,
            args: vec![],
            console_cmd: bare.into(),
            note: "Try the game's developer console or its mod tools to load this.".into(),
            can_launch: false,
        },
    }
}

/// Spawn the game with the plan's program and arguments.
pub fn launch(program: &Path, args: &[String]) -> Result<(), String> {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    if let Some(parent) = program.parent() {
        cmd.current_dir(parent);
    }
    cmd.spawn().map(|_| ()).map_err(|e| format!("could not launch: {e}"))
}
