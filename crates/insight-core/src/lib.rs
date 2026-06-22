//! Insight analysis engine: load a binary, disassemble it, and recover
//! functions / basic blocks / strings.  UI-agnostic and dependency-light so it
//! can run on a background thread.

pub mod analysis;
pub mod decompiler;
pub mod disasm;
pub mod game;
pub mod launch;
pub mod live;
pub mod loader;
pub mod mods;
pub mod pak;
pub mod strings;

pub use analysis::{analyze, Analysis, Function};
pub use decompiler::{decompile, decompile_lines};
pub use disasm::{Flow, Insn};
pub use loader::{Arch, Program, Segment, Symbol};
pub use strings::{find_strings, scan_bytes_for_strings, FoundString};

/// A fully analysed target: everything the UI needs to render.
pub struct Project {
    pub program: Program,
    pub functions: Vec<Function>,
    pub strings: Vec<FoundString>,
}

impl Project {
    /// Analyse raw file bytes, reporting coarse progress through `progress`.
    pub fn analyze(data: &[u8], mut progress: impl FnMut(f32, &str)) -> Project {
        progress(0.0, "parsing container");
        let program = loader::load(data);
        let analysis = analysis::analyze(&program, &mut progress);
        progress(0.97, "scanning strings");
        let strings = strings::find_strings(&program, 4);
        progress(1.0, "ready");
        Project {
            program,
            functions: analysis.functions,
            strings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // a tiny position-independent x86-64 function: xor eax,eax; ret
    const CODE: &[u8] = &[0x31, 0xc0, 0xc3];

    #[test]
    fn disassembles_raw_blob() {
        let insns = disasm::disasm(CODE, 0x1000, 64);
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].mnemonic, "xor");
        assert!(matches!(insns[1].flow, Flow::Return));
    }

    #[test]
    fn analyses_raw_blob_into_a_function() {
        let proj = Project::analyze(CODE, |_, _| {});
        assert_eq!(proj.program.arch, Arch::X64);
        assert_eq!(proj.functions.len(), 1);
        assert!(proj.functions[0].insns.len() >= 2);
    }

    #[test]
    fn decompiles_to_pseudocode() {
        let proj = Project::analyze(CODE, |_, _| {});
        let func = &proj.functions[0];
        let code = decompiler::decompile(func, &proj.program);
        assert!(code.contains("void "));
        assert!(code.contains("return;"));
        // xor eax, eax  ->  eax ^= eax;
        assert!(code.contains("^="));
    }

    #[test]
    fn detects_engine_from_magic() {
        let d = game::detect::detect_bytes(b"GSV1....", "x.gsv");
        assert_eq!(d[0].engine_id, "gamescript");
        let g = game::detect::detect_bytes(b"GDPC\x01\x00", "x.pck");
        assert_eq!(g[0].engine_id, "godot");
    }

    #[test]
    fn extracts_ascii_and_utf16_strings() {
        // ASCII marker, then "DEVROOM" as UTF-16LE (double-null separated)
        let mut data = b"junk\x00\x01load_test_map\x00\x00".to_vec();
        for c in b"DEVROOM" {
            data.push(*c);
            data.push(0);
        }
        let strings = strings::scan_bytes_for_strings(&data, 4);
        assert!(strings.iter().any(|s| s == "load_test_map"));
        assert!(strings.iter().any(|s| s == "DEVROOM"), "should find UTF-16 string in {strings:?}");
    }

    #[test]
    fn analyze_game_directory_finds_content_and_chrome() {
        use std::fs;
        let dir = std::env::temp_dir().join(format!("insight_game_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("levels")).unwrap();
        // Chrome Engine signature
        fs::write(dir.join("data0.pak"), b"x").unwrap();
        fs::write(dir.join("data1.pak"), b"x").unwrap();
        // discoverable filenames
        fs::write(dir.join("levels").join("test_level_01.scr"), b"").unwrap();
        fs::write(dir.join("levels").join("dev_room.scr"), b"").unwrap();
        fs::write(dir.join("levels").join("unused_boss_OLD.msh"), b"").unwrap();
        // dev line inside a text file
        fs::write(dir.join("notes.txt"), b"// TODO: remove this debug menu before ship\n").unwrap();

        let rep = game::analyze_game(&dir, None);
        assert_eq!(rep.best().map(|d| d.engine_id.as_str()), Some("chrome"));
        let cats: std::collections::HashSet<_> =
            rep.discovery.iter().map(|f| f.category.clone()).collect();
        for c in ["test_map", "dev_room", "unused", "dev_line", "debug"] {
            assert!(cats.contains(c), "missing {c} in {cats:?}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mod_workshop_roundtrip() {
        let game = std::env::temp_dir().join(format!("insight_mods_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&game);
        std::fs::create_dir_all(&game).unwrap();

        let proj = mods::new_mod_project(&game, "My Cool Mod").unwrap();
        std::fs::write(proj.join("data").join("level.scr"), b"hi").unwrap();

        let listed = mods::list_mods(&game);
        assert_eq!(listed.len(), 1);
        let m = &listed[0];
        assert_eq!(m.name, "My_Cool_Mod");
        assert!(!m.enabled && m.built_pak.is_none());

        let pak = mods::build_mod(&game, m, "chrome").unwrap();
        assert!(pak.exists() && pak.extension().unwrap() == "pak");
        // it's a real ZIP containing our file
        let mut z = zip::ZipArchive::new(std::fs::File::open(&pak).unwrap()).unwrap();
        assert!(z.by_name("level.scr").is_ok());

        let disabled = mods::set_enabled(&pak, false).unwrap();
        assert!(disabled.to_string_lossy().ends_with(".disabled"));
        let relisted = mods::list_mods(&game);
        assert!(!relisted[0].enabled && relisted[0].built_pak.is_some());

        let _ = std::fs::remove_dir_all(&game);
    }

    #[test]
    fn chrome_turnkey_install() {
        let game = std::env::temp_dir().join(format!("insight_install_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&game);
        std::fs::create_dir_all(game.join("DW")).unwrap();
        std::fs::write(game.join("DW").join("data0.pak"), b"x").unwrap();
        std::fs::write(game.join("DW").join("data1.pak"), b"x").unwrap();

        let proj = mods::new_mod_project(&game, "Skybox").unwrap();
        std::fs::write(proj.join("data").join("sky.scr"), b"hi").unwrap();
        let m = mods::list_mods(&game).into_iter().next().unwrap();

        let dest = mods::chrome_install(&game, &m).unwrap();
        assert_eq!(dest.parent().unwrap(), game.join("DW")); // dropped in the data dir
        assert_eq!(dest.file_name().unwrap(), "data50.pak"); // free slot above floor
        assert!(dest.exists());
        assert!(mods::list_mods(&game)[0].installed.is_some());

        mods::chrome_uninstall(&game, "Skybox").unwrap();
        assert!(!dest.exists());
        assert!(mods::list_mods(&game)[0].installed.is_none());
        // the game's own paks are untouched
        assert!(game.join("DW").join("data0.pak").exists());
        let _ = std::fs::remove_dir_all(&game);
    }

    #[test]
    fn extracts_map_folder_from_pak() {
        use std::io::Write;
        let game = std::env::temp_dir().join(format!("insight_extract_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&game);
        std::fs::create_dir_all(game.join("DW")).unwrap();
        let pak = game.join("DW").join("data3.pak");
        let mut zw = zip::ZipWriter::new(std::fs::File::create(&pak).unwrap());
        let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zw.start_file("data/maps/devroom/devroom.map", opts).unwrap();
        zw.write_all(b"MAP").unwrap();
        zw.start_file("data/maps/devroom/info.scr", opts).unwrap();
        zw.write_all(b"INFO").unwrap();
        zw.start_file("data/maps/other/other.map", opts).unwrap();
        zw.write_all(b"X").unwrap();
        zw.finish().unwrap();

        let dest = game.join("InsightExtracted");
        let (arch, entry) = pak::parse_pak_source("pak:data3.pak", "data/maps/devroom/devroom.map").unwrap();
        let res = pak::extract_folder_for(&game, &arch, &entry, &dest, true).unwrap();
        assert_eq!(res.files, 2); // the whole devroom folder, not "other"
        assert!(dest.join("data/maps/devroom/devroom.map").exists());
        assert!(dest.join("data/maps/devroom/info.scr").exists());
        assert!(!dest.join("data/maps/other/other.map").exists());
        let _ = std::fs::remove_dir_all(&game);
    }

    #[test]
    fn scans_inside_zip_pak_archives() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("insight_pak_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // a Chrome-Engine-style data0.pak is a ZIP archive
        let pak = dir.join("data0.pak");
        let mut zw = zip::ZipWriter::new(std::fs::File::create(&pak).unwrap());
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zw.start_file("levels/dev_room_secret.scr", opts).unwrap();
        zw.write_all(b"// nothing").unwrap();
        zw.start_file("scripts/devtools.scr", opts).unwrap();
        zw.write_all(b"// TODO: hide the debug menu\nspawn_item god_mode\n").unwrap();
        zw.finish().unwrap();

        let found = game::discovery::report(game::discovery::scan_archives(&dir, 10, 100000, 100));
        let cats: std::collections::HashSet<_> = found.iter().map(|f| f.category.clone()).collect();
        assert!(cats.contains("dev_room"), "name inside pak: {cats:?}");
        assert!(cats.contains("dev_line") || cats.contains("debug"), "content inside pak: {cats:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discovery_flags_categories() {
        let names = ["test_map_arena", "DEV_ROOM", "unused_enemy_OLD", "god_mode", "main_menu"];
        let found = game::discovery::report(game::discovery::scan_names(names));
        let cats: Vec<String> = found.iter().map(|f| f.category.clone()).collect();
        for c in ["test_map", "dev_room", "unused", "cheat"] {
            assert!(cats.iter().any(|x| x == c), "missing {c} in {cats:?}");
        }
    }

    #[test]
    fn live_requires_authorization() {
        let pid = std::process::id();
        assert!(live::LiveSession::open(pid, false).is_err());
    }

    #[test]
    fn live_lists_self() {
        let procs = live::list_processes();
        assert!(procs.iter().any(|p| p.pid == std::process::id()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_scans_own_memory() {
        // a unique marker kept alive on the heap
        let marker = b"INSIGHT_RUST_MARKER_c0ffee99".to_vec();
        let pid = std::process::id();
        let session = live::LiveSession::open(pid, true).expect("attach self");
        assert!(!session.regions().is_empty());
        let hits = session.scan_bytes(&marker, 10);
        assert!(!hits.is_empty(), "should find the marker in own memory");
        // keep marker alive past the scan
        assert_eq!(&marker[..6], b"INSIGH");
    }

    #[test]
    fn decompiler_recovers_if_structure() {
        // xor eax,eax; test edi,edi; je +2; inc eax; ret
        let code: &[u8] = &[0x31, 0xc0, 0x85, 0xff, 0x74, 0x02, 0xff, 0xc0, 0xc3];
        let proj = Project::analyze(code, |_, _| {});
        let func = proj.functions.iter().max_by_key(|f| f.insns.len()).unwrap();
        let out = decompiler::decompile(func, &proj.program);
        assert!(out.contains("if ("), "expected an if in:\n{out}");
        assert!(out.contains("edi"), "condition should mention edi:\n{out}");
        assert!(out.contains("eax++"), "expected inc lifted:\n{out}");
        assert!(!out.contains("goto"), "structured output shouldn't need goto:\n{out}");
    }

    #[test]
    fn finds_strings() {
        let data = b"\x00\x00hello world\x00\x00";
        let prog = loader::load(data);
        // loader treats unknown bytes as a raw code blob; strings still scan it
        let s = strings::find_strings(&prog, 4);
        assert!(s.iter().any(|f| f.value.contains("hello world")));
    }
}
