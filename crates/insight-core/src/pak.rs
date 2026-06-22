//! Extracting files out of ZIP-based game archives (Chrome Engine `.pak`,
//! Quake/Doom `.pk3`, plain `.zip`).
//!
//! This is what turns a discovery into something you can actually open: pull a
//! map's folder out of a `dataN.pak` to a loose directory, then open the
//! resulting `.map` in the game's editor (e.g. ChromED's Document ▸ Open).

use std::io::Read;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

/// All archives in the game folder whose file name matches `basename`
/// (there can be several, e.g. data0.pak in different folders).
pub fn find_archives(game_dir: &Path, basename: &str) -> Vec<PathBuf> {
    let want = basename.to_lowercase();
    WalkDir::new(game_dir)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.file_name().to_string_lossy().to_lowercase() == want)
        .map(|e| e.path().to_path_buf())
        .collect()
}

/// Directory prefix of an archive entry (with trailing slash), or "" at root.
pub fn parent_prefix(entry: &str) -> String {
    let norm = entry.replace('\\', "/");
    match norm.rfind('/') {
        Some(i) => norm[..=i].to_string(),
        None => String::new(),
    }
}

fn safe_join(dest_root: &Path, entry: &str) -> Option<PathBuf> {
    // prevent path traversal out of dest_root
    let mut p = dest_root.to_path_buf();
    for comp in entry.replace('\\', "/").split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            return None;
        }
        p.push(comp);
    }
    Some(p)
}

/// Extract every entry whose name starts with `prefix` into `dest_root`,
/// preserving the relative layout. Returns the number of files written.
pub fn extract_prefix(archive: &Path, prefix: &str, dest_root: &Path) -> Result<usize, String> {
    let file = std::fs::File::open(archive).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| format!("not a readable archive: {e}"))?;
    let names: Vec<String> = zip.file_names().map(|s| s.to_string()).collect();
    let pfx = prefix.replace('\\', "/").to_lowercase();
    let mut count = 0;
    for name in names {
        if !name.replace('\\', "/").to_lowercase().starts_with(&pfx) {
            continue;
        }
        let Ok(mut zf) = zip.by_name(&name) else { continue };
        if !zf.is_file() {
            continue;
        }
        let Some(out) = safe_join(dest_root, &name) else { continue };
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut buf = Vec::new();
        if zf.read_to_end(&mut buf).is_ok() {
            std::fs::write(&out, &buf).map_err(|e| e.to_string())?;
            count += 1;
        }
    }
    Ok(count)
}

/// Extract a single entry into `dest_root`.
pub fn extract_entry(archive: &Path, entry: &str, dest_root: &Path) -> Result<PathBuf, String> {
    let file = std::fs::File::open(archive).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| format!("not a readable archive: {e}"))?;
    let mut zf = zip.by_name(entry).map_err(|_| format!("{entry} not in {}", archive.display()))?;
    let out = safe_join(dest_root, entry).ok_or("unsafe path")?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut buf = Vec::new();
    zf.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    std::fs::write(&out, &buf).map_err(|e| e.to_string())?;
    Ok(out)
}

pub struct Extracted {
    pub files: usize,
    pub dest: PathBuf,
    pub archive: PathBuf,
}

/// Locate the archive named `basename` that contains `entry` and extract the
/// entry's whole containing folder (so a map comes out with its siblings).
pub fn extract_folder_for(
    game_dir: &Path,
    basename: &str,
    entry: &str,
    dest_root: &Path,
    whole_folder: bool,
) -> Result<Extracted, String> {
    let archives = find_archives(game_dir, basename);
    if archives.is_empty() {
        return Err(format!("archive {basename} not found under the game folder"));
    }
    let target = if whole_folder { parent_prefix(entry) } else { entry.to_string() };
    let entry_norm = entry.replace('\\', "/");

    for arc in archives {
        let Ok(file) = std::fs::File::open(&arc) else { continue };
        let Ok(zip) = zip::ZipArchive::new(file) else { continue };
        let has = zip.file_names().any(|n| n.replace('\\', "/").eq_ignore_ascii_case(&entry_norm));
        drop(zip);
        if !has {
            continue;
        }
        let files = if whole_folder {
            extract_prefix(&arc, &target, dest_root)?
        } else {
            extract_entry(&arc, entry, dest_root).map(|_| 1)?
        };
        return Ok(Extracted { files, dest: dest_root.to_path_buf(), archive: arc });
    }
    Err(format!("could not find {entry} inside any {basename}"))
}

/// Parse a discovery `source` string like `pak:data0.pak ▸ scripts/x.scr`
/// (or `pak:data0.pak`) into (archive_basename, entry). For the bare form the
/// finding's own text is the entry path.
pub fn parse_pak_source<'a>(source: &'a str, text: &'a str) -> Option<(String, String)> {
    let rest = source.strip_prefix("pak:")?;
    if let Some((arch, entry)) = rest.split_once(" ▸ ") {
        Some((arch.trim().to_string(), entry.trim().to_string()))
    } else {
        Some((rest.trim().to_string(), text.to_string()))
    }
}
