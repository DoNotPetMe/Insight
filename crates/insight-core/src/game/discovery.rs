//! Content-discovery scanner: flag dev rooms, test maps, debug menus,
//! unused/leftover content, cheats, placeholders and beta material.
//!
//! Patterns match a *normalised* form of the text (every run of non-alphanumeric
//! characters becomes one space), so `dev_room`, `dev-room` and `dev room` all
//! match the same way.

use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use regex::{Regex, RegexSet};
use walkdir::WalkDir;

#[derive(Clone)]
pub struct Finding {
    pub category: String,
    pub score: u32,
    pub text: String,
    pub source: String,
    pub matched: String,
}

struct Pat {
    cat: &'static str,
    score: u32,
    re: Regex,
}

struct Patterns {
    pats: Vec<Pat>,
    set: RegexSet,
}

const RAW: &[(&str, u32, &str)] = &[
    ("dev_room", 5, r"\b(dev ?room|developer room|debug room|sandbox|test room|hidden room|dev ?(level|map|area|zone|scene|world|hub)|debug ?(level|map|hub))\b"),
    ("test_map", 5, r"\b((test|debug) (map|level|scene|stage|area|world|zone|room|arena|ground|bed|chamber|hub)|(map|level|scene|lvl) test|test ?lvl|lvl ?test|playground|gr[ae]ybox|whitebox|blockout|blockmesh|proving ground|test ?bed|qa (map|level|test)|demo (level|map|scene|build)|e3 (demo|level|map|build)|gdc (demo|build))\b"),
    ("debug", 4, r"\b(debug ?(menu|mode|draw|build|camera|cam|console|info|overlay|spawn|view|hud|font|text|line|render|log|panel|tool|key|cheat|flag)|dbg|show ?fps|wireframe|developer console|gm debug|free ?cam|noclip|debug only|is ?debug|enable debug|debug enabled)\b"),
    ("unused", 4, r"\b(unused|deprecated|obsolete|leftover|backup|legacy|cut content|scrapped|removed|do not use|old version|do ?not ?ship|not ?used|old (asset|model|map|level|version)|beta only|abandoned|dead code|no longer used|unreferenced|_bak\b|_old\b)\b"),
    ("cheat", 3, r"\b(god ?mode|noclip|infinite (ammo|health|money|stamina|lives)|cheat\w*|invincib\w*|all (items|weapons|guns)|unlock ?all|give (item|weapon|all|money)|fly ?mode|spawn (item|enemy|all)|set (health|money|level)|add (money|xp|item)|kill ?all|teleport|ghost mode|one hit kill|instant win|no ?clip)\b"),
    ("placeholder", 3, r"\b(placeholder|dummy|temp|temporary|wip|tbd|missing (texture|model|mesh|asset)|null asset|no ?texture|error ?tex\w*|do ?not ?use|stub|untitled|default (asset|material|mesh|texture)|new asset|replace ?me|sample text|lorem ipsum)\b"),
    ("beta", 3, r"\b(beta|alpha|prototype|proto|early access|preview|internal (build|use|only)|staging|pre ?release|pre ?alpha|milestone|e3|gdc|demo build|review build|press build|vertical slice|first playable)\b"),
    ("secret", 2, r"\b(secret|easter ?egg|hidden|unlockable|bonus (level|room|stage)|dev ?mode|debug unlock)\b"),
    ("dev_line", 3, r"\b(todo|fixme|hack|xxx|not implemented|unimplemented|do ?not ?(ship|commit|check ?in)|playtest|temp hack|remove (this|me|later)|work in progress|hard ?coded|magic number|kludge|workaround|for testing|test only|debug print|not finished|incomplete|do not edit|placeholder text|assertion failed)\b"),
];

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| {
        let pats: Vec<Pat> = RAW
            .iter()
            .map(|(c, s, rx)| Pat {
                cat: c,
                score: *s,
                re: Regex::new(&format!("(?i){rx}")).unwrap(),
            })
            .collect();
        let set = RegexSet::new(RAW.iter().map(|(_, _, rx)| format!("(?i){rx}"))).unwrap();
        Patterns { pats, set }
    })
}

fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev_space = false;
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_space = false;
        } else if !prev_space {
            out.push(' ');
            prev_space = true;
        }
    }
    out.trim().to_string()
}

fn scan_text(text: &str, source: &str, out: &mut Vec<Finding>) {
    let norm = normalize(text);
    if norm.is_empty() {
        return;
    }
    let p = patterns();
    let matched = p.set.matches(&norm);
    if !matched.matched_any() {
        return;
    }
    for idx in matched.iter() {
        let pat = &p.pats[idx];
        if let Some(m) = pat.re.find(&norm) {
            out.push(Finding {
                category: pat.cat.to_string(),
                score: pat.score,
                text: text.chars().take(200).collect(),
                source: source.to_string(),
                matched: m.as_str().to_string(),
            });
        }
    }
}

pub fn scan_strings<'a, I: IntoIterator<Item = &'a str>>(strings: I, source: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for s in strings {
        scan_text(s, source, &mut out);
    }
    out
}

pub fn scan_names<'a, I: IntoIterator<Item = &'a str>>(names: I) -> Vec<Finding> {
    let mut out = Vec::new();
    for n in names {
        scan_text(n, "filename", &mut out);
    }
    out
}

pub fn scan_directory(path: &Path, max_files: usize) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, entry) in WalkDir::new(path).into_iter().filter_map(|e| e.ok()).enumerate() {
        if i > max_files {
            break;
        }
        let rel = entry.path().strip_prefix(path).unwrap_or(entry.path());
        scan_text(&rel.to_string_lossy(), "filename", &mut out);
    }
    out
}

// text-like extensions whose contents are worth scanning for dev lines
const TEXT_EXTS: &[&str] = &[
    "txt", "cfg", "ini", "lua", "scr", "xml", "json", "def", "csv", "log", "md",
    "gd", "cs", "js", "yaml", "yml", "toml", "h", "hpp", "c", "cpp", "py", "rpy",
    "material", "shader", "fx", "hlsl", "glsl", "cmd", "list", "table",
];

const MAX_TEXT_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Read small text-like files in a directory tree and scan their contents.
/// Catches dev console commands, debug log lines and TODO/HACK notes that live
/// in scripts and config files rather than in filenames.
pub fn scan_dir_text_files(path: &Path, max_files: usize) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut read = 0usize;
    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if read >= max_files {
            break;
        }
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let ext = p.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase());
        let Some(ext) = ext else { continue };
        if !TEXT_EXTS.contains(&ext.as_str()) {
            continue;
        }
        let too_big = entry.metadata().map(|m| m.len() > MAX_TEXT_FILE_BYTES).unwrap_or(true);
        if too_big {
            continue;
        }
        if let Ok(content) = std::fs::read(p) {
            read += 1;
            let rel = p.strip_prefix(path).unwrap_or(p).to_string_lossy().into_owned();
            for line in String::from_utf8_lossy(&content).lines() {
                scan_text(line, &rel, &mut out);
            }
        }
    }
    out
}

/// Scan the executables (.exe/.dll) in a game folder for embedded strings.
///
/// Many engines (e.g. Chrome Engine / Dying Light) pack level and script data
/// into archives, so the loose file tree is sparse — but the engine binaries
/// still contain level names, console commands and debug strings (often as
/// UTF-16). Largest binaries are scanned first, within a byte budget.
pub fn scan_executables(dir: &Path, max_exes: usize, byte_budget: u64) -> Vec<Finding> {
    let mut exes: Vec<(std::path::PathBuf, u64)> = Vec::new();
    for entry in WalkDir::new(dir).max_depth(3).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        let is_exe = p
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| matches!(e.to_lowercase().as_str(), "exe" | "dll"))
            .unwrap_or(false);
        if is_exe {
            let sz = entry.metadata().map(|m| m.len()).unwrap_or(0);
            exes.push((p.to_path_buf(), sz));
        }
    }
    exes.sort_by(|a, b| b.1.cmp(&a.1)); // largest first — that's the engine

    let mut out = Vec::new();
    let mut budget = byte_budget;
    let mut count = 0;
    for (p, sz) in exes {
        if count >= max_exes || sz == 0 || sz > budget {
            continue;
        }
        if let Ok(data) = std::fs::read(&p) {
            budget = budget.saturating_sub(sz);
            count += 1;
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let src = format!("exe:{name}");
            let strings = crate::strings::scan_bytes_for_strings(&data, 5);
            for s in &strings {
                scan_text(s, &src, &mut out);
            }
        }
    }
    out
}

/// Scan inside ZIP-based game archives (Chrome Engine dataN.pak, Quake/Doom
/// .pk3, plain .zip) for entry names and small text-entry contents — this is
/// where packed games keep their level and script names. Archives that aren't
/// ZIP (Unreal/Godot custom formats) are skipped silently.
pub fn scan_archives(dir: &Path, max_archives: usize, name_budget: usize, text_budget: usize) -> Vec<Finding> {
    use std::io::Read;
    let mut out = Vec::new();
    let mut archives = 0usize;
    let mut names_scanned = 0usize;
    let mut text_read = 0usize;

    for entry in WalkDir::new(dir).max_depth(4).into_iter().filter_map(|e| e.ok()) {
        if archives >= max_archives || names_scanned >= name_budget {
            break;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        let ext = p.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase());
        let Some(ext) = ext else { continue };
        if !matches!(ext.as_str(), "pak" | "pk3" | "pk4" | "zip" | "pkz" | "obb") {
            continue;
        }
        let Ok(file) = std::fs::File::open(p) else { continue };
        let Ok(mut zip) = zip::ZipArchive::new(file) else { continue }; // not a ZIP
        archives += 1;
        let arch = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let src = format!("pak:{arch}");

        let names: Vec<String> = zip.file_names().map(|s| s.to_string()).collect();
        for name in &names {
            if names_scanned >= name_budget {
                break;
            }
            names_scanned += 1;
            scan_text(name, &src, &mut out);
        }
        for name in &names {
            if text_read >= text_budget {
                break;
            }
            let low = name.to_lowercase();
            if !TEXT_EXTS.iter().any(|e| low.ends_with(&format!(".{e}"))) {
                continue;
            }
            if let Ok(mut zf) = zip.by_name(name) {
                if zf.size() > MAX_TEXT_FILE_BYTES {
                    continue;
                }
                let mut buf = Vec::new();
                if zf.read_to_end(&mut buf).is_ok() {
                    text_read += 1;
                    let esrc = format!("{src} ▸ {name}");
                    for line in String::from_utf8_lossy(&buf).lines() {
                        scan_text(line, &esrc, &mut out);
                    }
                }
            }
        }
    }
    out
}

const MAX_FINDINGS: usize = 8000;

// Substrings that mark a finding as third-party middleware/SDK noise rather
// than game content (Epic Online Services, FMOD, licences, URLs, …).
const NOISE_TEXT: &[&str] = &[
    "epicgames", "eos_", "eossdk", "fmod", "license", "copyright", "derivativ",
    "redistribut", "errors.com", "://", "openssl", "zlib", "libcurl", "sandbox_id",
    "invalid_sandbox", "sandbox_not_allowed", "sandbox_at_capacity", "missing_permission",
    "query mods", "$sandbox", "www.", "(c)", "all rights reserved",
];
const NOISE_SOURCE: &[&str] = &[
    "eossdk", "fmod", "steam_api", "openssl", "third_party", "crashpad",
    "d3dcompiler", "amd_ags", "nvngx", "galaxy", "discord",
];

/// True if a finding is almost certainly middleware/SDK noise, not game content.
pub fn is_noise(f: &Finding) -> bool {
    let t = f.text.to_lowercase();
    if NOISE_TEXT.iter().any(|n| t.contains(n)) {
        return true;
    }
    let s = f.source.to_lowercase();
    NOISE_SOURCE.iter().any(|n| s.contains(n))
}

/// True if a finding looks like a loadable map/level/asset identifier — the
/// kind of thing worth trying to load into the game.
pub fn looks_actionable(f: &Finding) -> bool {
    let t = f.text.to_lowercase();
    let exty = [".map", ".scr", ".lvl", ".lua", ".pak", ".unity", ".umap", ".level"]
        .iter()
        .any(|e| t.ends_with(e));
    let pathy = t.contains('/') || t.contains('\\');
    let mapy = (t.contains("map") || t.contains("level") || t.contains("demo")
        || t.contains("scene") || t.contains("world") || t.contains("_ot_") || t.contains("arena"))
        && f.text.len() < 70
        && f.text.split_whitespace().count() <= 2;
    matches!(f.category.as_str(), "dev_room" | "test_map" | "unused" | "secret" | "beta")
        && (exty || pathy || mapy)
}

fn rank(f: &Finding) -> i32 {
    let mut r = f.score as i32 * 3;
    if looks_actionable(f) {
        r += 30;
    }
    if is_noise(f) {
        r -= 25;
    }
    r
}

/// De-duplicate, rank (real content first, noise last) and cap the result.
pub fn report(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| rank(b).cmp(&rank(a)).then(b.score.cmp(&a.score)));
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert((f.category.clone(), f.text.clone(), f.source.clone())));
    findings.truncate(MAX_FINDINGS);
    findings
}
