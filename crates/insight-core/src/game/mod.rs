//! Game-platform awareness: engine detection, the tool registry, and the
//! content-discovery scanner.

pub mod detect;
pub mod discovery;
pub mod engines;

use std::path::Path;

pub use detect::Detection;
pub use discovery::Finding;
pub use engines::{Engine, Tool};

pub struct GameReport {
    pub detections: Vec<Detection>,
    pub discovery: Vec<Finding>,
}

impl GameReport {
    pub fn best(&self) -> Option<&Detection> {
        self.detections.first()
    }
    pub fn engine(&self) -> Option<&'static Engine> {
        self.best().and_then(|d| engines::get(&d.engine_id))
    }
    /// (category, count) pairs, highest count first.
    pub fn discovery_summary(&self) -> Vec<(String, usize)> {
        let mut counts: Vec<(String, usize)> = Vec::new();
        for f in &self.discovery {
            if let Some(e) = counts.iter_mut().find(|(c, _)| *c == f.category) {
                e.1 += 1;
            } else {
                counts.push((f.category.clone(), 1));
            }
        }
        counts.sort_by(|a, b| b.1.cmp(&a.1));
        counts
    }
}

/// Detect the engine and scan for notable content. `strings` are pre-recovered
/// strings from the loaded binary (used when `path` is a single file).
pub fn analyze_game(path: &Path, strings: &[String]) -> GameReport {
    let detections = detect::detect_path(path);
    let mut findings = Vec::new();
    if path.is_dir() {
        findings.extend(discovery::scan_directory(path, 20000));
    } else {
        findings.extend(discovery::scan_strings(strings.iter().map(|s| s.as_str()), "string"));
        if let Some(name) = path.file_name() {
            findings.extend(discovery::scan_names([name.to_string_lossy().as_ref()]));
        }
    }
    GameReport {
        detections,
        discovery: discovery::report(findings),
    }
}
