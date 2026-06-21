//! Detect which engine produced a game, from a file or an install directory.

use std::fs;
use std::path::Path;

#[derive(Clone)]
pub struct Detection {
    pub engine_id: String,
    pub name: String,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub variant: String,
}

const MAGIC: &[(&[u8], &str, &str)] = &[
    (b"UnityFS", "unity", "asset bundle"),
    (b"FORM", "gamemaker", "data.win FORM container"),
    (b"GDPC", "godot", ".pck archive"),
    (b"RPA-3.0", "renpy", ".rpa archive"),
    (b"IWAD", "idtech", "WAD archive"),
    (b"PWAD", "idtech", "WAD archive"),
    (b"GSV1", "gamescript", "GameScript VM module"),
];

const UNREAL_PAK_MAGIC: &[u8] = &[0xE1, 0x12, 0x6F, 0x5A];

fn name_of(id: &str) -> String {
    super::engines::get(id).map(|e| e.name.to_string()).unwrap_or_else(|| id.to_string())
}

fn det(id: &str, conf: f32, ev: &str) -> Detection {
    Detection {
        engine_id: id.to_string(),
        name: name_of(id),
        confidence: conf,
        evidence: vec![ev.to_string()],
        variant: String::new(),
    }
}

pub fn detect_bytes(data: &[u8], name: &str) -> Vec<Detection> {
    let mut out = Vec::new();
    let head = &data[..data.len().min(32)];
    for (magic, id, what) in MAGIC {
        if head.starts_with(magic) {
            out.push(det(id, 0.95, &format!("magic {what}")));
        }
    }
    let tail = &data[data.len().saturating_sub(205)..];
    if tail.windows(4).any(|w| w == UNREAL_PAK_MAGIC) {
        out.push(det("unreal", 0.9, "Unreal .pak footer magic"));
    }
    let low = name.to_lowercase();
    for (ext, id, what) in [
        (".pak", "unreal", "pak archive"),
        (".uasset", "unreal", "uasset"),
        (".pck", "godot", "pck"),
        (".rpa", "renpy", "rpa"),
        (".rpyc", "renpy", "compiled script"),
        (".vpk", "source", "vpk"),
        (".wad", "idtech", "wad"),
        (".gsv", "gamescript", "module"),
    ] {
        if low.ends_with(ext) && !out.iter().any(|d| d.engine_id == id) {
            out.push(det(id, 0.6, &format!("extension {ext} ({what})")));
        }
    }
    rank(out)
}

pub fn detect_dir(path: &Path) -> Vec<Detection> {
    let Ok(rd) = fs::read_dir(path) else { return Vec::new() };
    let entries: Vec<String> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let has = |needle: &str| entries.iter().any(|e| e.to_lowercase().contains(needle));
    let mut out: Vec<Detection> = Vec::new();

    // Unity
    let data_dirs: Vec<&String> = entries
        .iter()
        .filter(|e| e.ends_with("_Data") && path.join(e).is_dir())
        .collect();
    let mut unity_ev = Vec::new();
    let mut variant = String::new();
    if let Some(d) = data_dirs.first() {
        unity_ev.push(format!("{d}/ data folder"));
    }
    if entries.iter().any(|e| e == "UnityPlayer.dll") {
        unity_ev.push("UnityPlayer.dll".into());
    }
    if has("gameassembly.dll") || has("libil2cpp") {
        unity_ev.push("IL2CPP runtime".into());
        variant = "IL2CPP".into();
    }
    for d in &data_dirs {
        if path.join(d).join("Managed").join("Assembly-CSharp.dll").exists() {
            unity_ev.push(format!("{d}/Managed/Assembly-CSharp.dll"));
            if variant.is_empty() {
                variant = "Mono".into();
            }
        }
        if path.join(d).join("il2cpp_data").join("Metadata").join("global-metadata.dat").exists() {
            unity_ev.push("global-metadata.dat".into());
            variant = "IL2CPP".into();
        }
    }
    if !unity_ev.is_empty() {
        let conf = (0.6 + 0.1 * unity_ev.len() as f32).min(0.99);
        out.push(Detection { engine_id: "unity".into(), name: name_of("unity"), confidence: conf, evidence: unity_ev, variant });
    }

    // Unreal
    let mut ue = Vec::new();
    if entries.iter().any(|e| e == "Engine" && path.join(e).is_dir()) {
        ue.push("Engine/ tree".into());
    }
    let paks = entries.iter().filter(|e| e.to_lowercase().ends_with(".pak")).count();
    if paks > 0 {
        ue.push(format!("{paks} .pak archive(s)"));
    }
    if !ue.is_empty() {
        let conf = (0.55 + 0.12 * ue.len() as f32).min(0.95);
        out.push(Detection { engine_id: "unreal".into(), name: name_of("unreal"), confidence: conf, evidence: ue, variant: String::new() });
    }

    // GameMaker
    if entries.iter().any(|e| matches!(e.to_lowercase().as_str(), "data.win" | "game.unx" | "game.ios")) || has("audiogroup") {
        out.push(det("gamemaker", 0.85, "data.win / audiogroup*.dat"));
    }
    // Godot
    let mut godot = Vec::new();
    if has("project.godot") {
        godot.push("project.godot".into());
    }
    let pcks = entries.iter().filter(|e| e.to_lowercase().ends_with(".pck")).count();
    if pcks > 0 {
        godot.push(format!("{pcks} .pck archive(s)"));
    }
    if !godot.is_empty() {
        out.push(Detection { engine_id: "godot".into(), name: name_of("godot"), confidence: 0.85, evidence: godot, variant: String::new() });
    }
    // Ren'Py
    if has("renpy") || has(".rpa") || has(".rpyc") {
        out.push(det("renpy", 0.8, "renpy/ or .rpa/.rpyc files"));
    }
    // RPG Maker
    if path.join("www").join("data").is_dir() {
        out.push(det("rpgmaker", 0.85, "www/data/*.json"));
    }
    // Source
    if has("gameinfo.txt") || has(".vpk") {
        out.push(det("source", 0.8, "gameinfo.txt or .vpk"));
    }
    // Construct
    if has("c2runtime.js") || has("c3runtime.js") {
        out.push(det("construct", 0.8, "c2/c3runtime.js"));
    }
    rank(out)
}

pub fn detect_path(path: &Path) -> Vec<Detection> {
    if path.is_dir() {
        return detect_dir(path);
    }
    let Ok(mut data) = fs::read(path) else { return Vec::new() };
    if data.len() > (1 << 20) + 256 {
        // keep head + tail for magic + pak footer
        let tail = data.split_off(data.len() - 256);
        data.truncate(1 << 20);
        data.extend_from_slice(&tail);
    }
    let name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    detect_bytes(&data, &name)
}

fn rank(dets: Vec<Detection>) -> Vec<Detection> {
    let mut merged: Vec<Detection> = Vec::new();
    for d in dets {
        if let Some(cur) = merged.iter_mut().find(|m| m.engine_id == d.engine_id) {
            cur.confidence = cur.confidence.max(d.confidence);
            cur.evidence.extend(d.evidence);
            if cur.variant.is_empty() {
                cur.variant = d.variant;
            }
        } else {
            merged.push(d);
        }
    }
    merged.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
    merged
}
