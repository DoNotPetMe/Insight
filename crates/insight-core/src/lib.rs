//! Insight analysis engine: load a binary, disassemble it, and recover
//! functions / basic blocks / strings.  UI-agnostic and dependency-light so it
//! can run on a background thread.

pub mod analysis;
pub mod disasm;
pub mod loader;
pub mod strings;

pub use analysis::{analyze, Analysis, Function};
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
    fn finds_strings() {
        let data = b"\x00\x00hello world\x00\x00";
        let prog = loader::load(data);
        // loader treats unknown bytes as a raw code blob; strings still scan it
        let s = strings::find_strings(&prog, 4);
        assert!(s.iter().any(|f| f.value.contains("hello world")));
    }
}
