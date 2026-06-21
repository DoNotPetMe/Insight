//! Insight analysis engine: load a binary, disassemble it, and recover
//! functions / basic blocks / strings.  UI-agnostic and dependency-light so it
//! can run on a background thread.

pub mod analysis;
pub mod decompiler;
pub mod disasm;
pub mod game;
pub mod live;
pub mod loader;
pub mod strings;

pub use analysis::{analyze, Analysis, Function};
pub use decompiler::{decompile, decompile_lines};
pub use disasm::{Flow, Insn};
pub use loader::{Arch, Program, Segment, Symbol};
pub use strings::{find_strings, FoundString};

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
    fn finds_strings() {
        let data = b"\x00\x00hello world\x00\x00";
        let prog = loader::load(data);
        // loader treats unknown bytes as a raw code blob; strings still scan it
        let s = strings::find_strings(&prog, 4);
        assert!(s.iter().any(|f| f.value.contains("hello world")));
    }
}
