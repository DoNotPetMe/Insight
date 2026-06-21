//! Content-discovery scanner: flag dev rooms, test maps, debug menus,
//! unused/leftover content, cheats, placeholders and beta material.
//!
//! Patterns match a *normalised* form of the text (every run of non-alphanumeric
//! characters becomes one space), so `dev_room`, `dev-room` and `dev room` all
//! match the same way.

use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;
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

fn patterns() -> &'static [Pat] {
    static P: OnceLock<Vec<Pat>> = OnceLock::new();
    P.get_or_init(|| {
        let raw: &[(&str, u32, &str)] = &[
            ("dev_room", 5, r"\b(dev ?room|developer room|debug room|sandbox|test room|hidden room)\b"),
            ("test_map", 5, r"\b((test|debug) (map|level|scene|stage|area|world|zone|room)|\w+ test|map test|playground|gr[ae]ybox|whitebox)\b"),
            ("debug", 4, r"\b(debug menu|debug mode|debug draw|dbg|show fps|wireframe|developer console|gm debug|debug build)\b"),
            ("unused", 4, r"\b(unused|deprecated|obsolete|leftover|backup|legacy|cut content|scrapped|removed|do not use|old version)\b"),
            ("cheat", 3, r"\b(god ?mode|noclip|infinite (ammo|health|money)|cheat|invincib\w*|all items|unlock all|give item|fly mode)\b"),
            ("placeholder", 3, r"\b(placeholder|dummy|temp|temporary|wip|tbd|todo|fixme|missing (texture|model)|null asset|notexture|errortex|donotuse)\b"),
            ("beta", 3, r"\b(beta|alpha|prototype|proto|early access|preview|internal build|staging)\b"),
            ("secret", 2, r"\b(secret|easter egg|hidden|unlockable|bonus (level|room))\b"),
        ];
        raw.iter()
            .map(|(c, s, rx)| Pat {
                cat: c,
                score: *s,
                re: Regex::new(&format!("(?i){rx}")).unwrap(),
            })
            .collect()
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
    for p in patterns() {
        if let Some(m) = p.re.find(&norm) {
            out.push(Finding {
                category: p.cat.to_string(),
                score: p.score,
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

/// De-duplicate and sort findings by descending score.
pub fn report(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| b.score.cmp(&a.score));
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert((f.category.clone(), f.text.clone(), f.source.clone())));
    findings
}
