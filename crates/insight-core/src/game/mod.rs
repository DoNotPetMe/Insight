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

/// Detect the engine and scan for notable content.
///
/// `raw` is the bytes of the opened file (when `path` is a single file), reused
/// to avoid a second read. For a single file Insight scans the file's ASCII and
/// UTF-16 strings, its name, and the filenames of the surrounding game folder;
/// for a folder it scans every filename plus the contents of small text files.
pub fn analyze_game(path: &Path, raw: Option<&[u8]>) -> GameReport {
    let detections = detect::detect_path(path);
    let mut findings = Vec::new();

    if path.is_dir() {
        findings.extend(discovery::scan_directory(path, 80_000));
        findings.extend(discovery::scan_dir_text_files(path, 6_000));
    } else {
        if let Some(data) = raw {
            let strings = crate::strings::scan_bytes_for_strings(data, 4);
            findings.extend(discovery::scan_strings(strings.iter().map(|s| s.as_str()), "string"));
        }
        if let Some(name) = path.file_name() {
            findings.extend(discovery::scan_names([name.to_string_lossy().as_ref()]));
        }
        // the dev rooms / test maps usually live as files around the .exe
        if let Some(parent) = path.parent() {
            if parent.as_os_str().len() > 0 {
                findings.extend(discovery::scan_directory(parent, 80_000));
            }
        }
    }

    GameReport {
        detections,
        discovery: discovery::report(findings),
    }
}
