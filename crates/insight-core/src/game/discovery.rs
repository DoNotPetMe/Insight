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

const MAX_FINDINGS: usize = 8000;

/// De-duplicate, sort by descending score, and cap the result.
pub fn report(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| b.score.cmp(&a.score));
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert((f.category.clone(), f.text.clone(), f.source.clone())));
    findings.truncate(MAX_FINDINGS);
    findings
}
