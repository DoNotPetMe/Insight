//! A lightweight, engine-aware mod workshop.
//!
//! Insight manages mods in an `InsightMods/` folder inside the game directory.
//! A mod is an editable project folder; "building" it packs the folder into a
//! ZIP-based archive (`.pak` for Chrome Engine / `.pk3` for id Tech, etc.).
//! Built mods can be enabled/disabled (by toggling a `.disabled` suffix) and
//! installed (copied) into a load path you confirm.
//!
//! Fully reliable installation differs per engine; Insight builds and manages
//! the artifacts and tells you where each engine loads them, but never writes
//! into the game's own data folders without an explicit install step.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

#[derive(Clone)]
pub struct ModInfo {
    pub name: String,
    pub project_dir: PathBuf,
    pub built_pak: Option<PathBuf>,
    pub enabled: bool,
    pub files: usize,
    /// the live `dataN.pak` Insight dropped into the game, if installed
    pub installed: Option<PathBuf>,
}

pub fn mods_dir(game_dir: &Path) -> PathBuf {
    game_dir.join("InsightMods")
}

/// The archive extension a given engine loads.
pub fn pak_ext(engine_id: &str) -> &'static str {
    match engine_id {
        "idtech" => "pk3",
        _ => "pak",
    }
}

/// Where this engine loads mod archives from, as guidance for the user.
pub fn install_hint(engine_id: &str) -> &'static str {
    match engine_id {
        "chrome" => "Chrome Engine: place the .pak with a higher dataN number than the game's (e.g. data9.pak) in the game's data folder; it overrides earlier paks.",
        "idtech" => "id Tech / Doom: drop the .pk3 in the game's mod/addons folder.",
        "source" => "Source: install as an addon VPK or loose files under the game's custom/ folder.",
        "unreal" => "Unreal: place a ~mods/*.pak in the game's Content/Paks folder (often needs -fileopenlog or a sig bypass).",
        "godot" => "Godot: ship as an override .pck loaded with --main-pack, or via a mod loader.",
        "unity" => "Unity: install through BepInEx/MelonLoader as a plugin.",
        "gamemaker" => "GameMaker: apply the change to data.win with UndertaleModTool.",
        _ => "Copy the built archive into the game's mod/data load path.",
    }
}

pub fn list_mods(game_dir: &Path) -> Vec<ModInfo> {
    let dir = mods_dir(game_dir);
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(&dir) else { return out };
    for e in rd.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let files = WalkDir::new(&p).into_iter().filter_map(|x| x.ok()).filter(|x| x.file_type().is_file()).count();
        // built artifact: <mods>/<name>.pak or .pak.disabled
        let enabled_pak = dir.join(format!("{name}.pak"));
        let disabled_pak = dir.join(format!("{name}.pak.disabled"));
        let (built_pak, enabled) = if enabled_pak.exists() {
            (Some(enabled_pak), true)
        } else if disabled_pak.exists() {
            (Some(disabled_pak), false)
        } else {
            (None, false)
        };
        let installed = installed_pak(game_dir, &name);
        out.push(ModInfo { name, project_dir: p, built_pak, enabled, files, installed });
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

/// Scaffold a new mod project folder with a readme and a data/ tree.
pub fn new_mod_project(game_dir: &Path, name: &str) -> Result<PathBuf, String> {
    let name = sanitize(name);
    if name.is_empty() {
        return Err("invalid mod name".into());
    }
    let proj = mods_dir(game_dir).join(&name);
    if proj.exists() {
        return Err("a mod with that name already exists".into());
    }
    fs::create_dir_all(proj.join("data")).map_err(|e| e.to_string())?;
    let readme = format!(
        "# {name}\n\nMod project created by Insight.\n\nPut the files you want to \
         override under data/ (mirroring the game's archive layout), then Build \
         to pack them into an archive.\n"
    );
    fs::write(proj.join("README.md"), readme).map_err(|e| e.to_string())?;
    Ok(proj)
}

/// Pack a project folder into a ZIP-based archive at `out`.
pub fn build_pak(src: &Path, out: &Path) -> Result<usize, String> {
    use zip::write::SimpleFileOptions;
    let file = fs::File::create(out).map_err(|e| format!("create {}: {e}", out.display()))?;
    let mut zw = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    let mut count = 0;
    // pack everything under src/data if present, else src itself
    let root = if src.join("data").is_dir() { src.join("data") } else { src.to_path_buf() };
    for entry in WalkDir::new(&root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry.path().strip_prefix(&root).map_err(|e| e.to_string())?
            .to_string_lossy().replace('\\', "/");
        if rel.eq_ignore_ascii_case("README.md") {
            continue;
        }
        zw.start_file(&rel, opts).map_err(|e| e.to_string())?;
        let data = fs::read(entry.path()).map_err(|e| e.to_string())?;
        zw.write_all(&data).map_err(|e| e.to_string())?;
        count += 1;
    }
    zw.finish().map_err(|e| e.to_string())?;
    Ok(count)
}

/// Build a mod project into `<mods>/<name>.pak` (engine-aware extension).
pub fn build_mod(game_dir: &Path, m: &ModInfo, engine_id: &str) -> Result<PathBuf, String> {
    let ext = pak_ext(engine_id);
    let out = mods_dir(game_dir).join(format!("{}.{ext}", m.name));
    let disabled = mods_dir(game_dir).join(format!("{}.{ext}.disabled", m.name));
    let _ = fs::remove_file(&disabled);
    build_pak(&m.project_dir, &out)?;
    Ok(out)
}

/// Toggle a built mod between enabled (`.pak`) and disabled (`.pak.disabled`).
pub fn set_enabled(pak: &Path, enabled: bool) -> Result<PathBuf, String> {
    let s = pak.to_string_lossy().into_owned();
    let (from, to) = if enabled {
        (s.clone(), s.trim_end_matches(".disabled").to_string())
    } else if s.ends_with(".disabled") {
        return Ok(pak.to_path_buf());
    } else {
        (s.clone(), format!("{s}.disabled"))
    };
    if from != to {
        fs::rename(&from, &to).map_err(|e| e.to_string())?;
    }
    Ok(PathBuf::from(to))
}

/// Copy a built archive into a target directory (the install step).
pub fn install_to(pak: &Path, target_dir: &Path) -> Result<PathBuf, String> {
    let name = pak.file_name().ok_or("bad archive name")?;
    let dest = target_dir.join(name);
    fs::copy(pak, &dest).map_err(|e| format!("install: {e}"))?;
    Ok(dest)
}

// ---------------------------------------------------------------------------
// Turnkey Chrome Engine install (drop a live dataN.pak into the game)
// ---------------------------------------------------------------------------
fn parse_data_slot(name: &str) -> Option<u32> {
    let low = name.to_lowercase();
    let stem = low.strip_prefix("data")?.strip_suffix(".pak")?;
    if stem.is_empty() || !stem.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    stem.parse().ok()
}

/// The game's primary data folder — the directory holding the most dataN.pak.
pub fn chrome_data_dir(game_dir: &Path) -> Option<PathBuf> {
    let mut counts: HashMap<PathBuf, usize> = HashMap::new();
    for e in WalkDir::new(game_dir).max_depth(4).into_iter().filter_map(|x| x.ok()) {
        if !e.file_type().is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if parse_data_slot(&name).is_some() {
            if let Some(parent) = e.path().parent() {
                *counts.entry(parent.to_path_buf()).or_default() += 1;
            }
        }
    }
    counts.into_iter().max_by_key(|(_, c)| *c).map(|(p, _)| p)
}

/// The next free `dataN` slot in `dir`, at least `floor`, above all existing
/// paks (higher numbers load last in Chrome Engine, so the mod overrides).
pub fn next_free_slot(dir: &Path, floor: u32) -> u32 {
    let mut max_existing = 0u32;
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            if let Some(n) = parse_data_slot(&e.file_name().to_string_lossy()) {
                max_existing = max_existing.max(n);
            }
        }
    }
    let mut n = (max_existing + 1).max(floor);
    while dir.join(format!("data{n}.pak")).exists() {
        n += 1;
    }
    n
}

/// One-click Chrome Engine install: build the mod and drop it into the game's
/// data folder as a free high-numbered dataN.pak so it goes live immediately.
pub fn chrome_install(game_dir: &Path, m: &ModInfo) -> Result<PathBuf, String> {
    let built = build_mod(game_dir, m, "chrome")?;
    let dir = chrome_data_dir(game_dir).unwrap_or_else(|| game_dir.to_path_buf());
    let slot = next_free_slot(&dir, 50);
    let dest = dir.join(format!("data{slot}.pak"));
    fs::copy(&built, &dest).map_err(|e| format!("install: {e}"))?;
    record_install(game_dir, &m.name, &dest);
    Ok(dest)
}

/// Remove the live dataN.pak Insight installed for this mod (never touches the
/// game's own paks — only files recorded in Insight's manifest).
pub fn chrome_uninstall(game_dir: &Path, name: &str) -> Result<(), String> {
    let mut kept = Vec::new();
    let mut removed = false;
    for (n, path) in read_manifest(game_dir) {
        if n == name {
            let _ = fs::remove_file(&path);
            removed = true;
        } else {
            kept.push((n, path));
        }
    }
    write_manifest(game_dir, &kept);
    if removed {
        Ok(())
    } else {
        Err("nothing installed for this mod".into())
    }
}

fn manifest_path(game_dir: &Path) -> PathBuf {
    mods_dir(game_dir).join("installed.tsv")
}

fn read_manifest(game_dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(data) = fs::read_to_string(manifest_path(game_dir)) else { return Vec::new() };
    data.lines()
        .filter_map(|l| {
            let (n, p) = l.split_once('\t')?;
            Some((n.to_string(), PathBuf::from(p)))
        })
        .collect()
}

fn write_manifest(game_dir: &Path, entries: &[(String, PathBuf)]) {
    let _ = fs::create_dir_all(mods_dir(game_dir));
    let body: String = entries.iter().map(|(n, p)| format!("{n}\t{}\n", p.display())).collect();
    let _ = fs::write(manifest_path(game_dir), body);
}

fn record_install(game_dir: &Path, name: &str, dest: &Path) {
    let mut entries = read_manifest(game_dir);
    entries.retain(|(n, _)| n != name);
    entries.push((name.to_string(), dest.to_path_buf()));
    write_manifest(game_dir, &entries);
}

fn installed_pak(game_dir: &Path, name: &str) -> Option<PathBuf> {
    read_manifest(game_dir)
        .into_iter()
        .find(|(n, p)| n == name && p.exists())
        .map(|(_, p)| p)
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}
