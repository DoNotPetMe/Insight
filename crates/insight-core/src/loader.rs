//! Container loading: turn raw bytes (PE / ELF / Mach-O, or a raw blob) into a
//! format-neutral [`Program`] the rest of the engine works against.

use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86,
    X64,
    Arm,
    Arm64,
    Unknown,
}

impl Arch {
    pub fn label(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X64 => "x86-64",
            Arch::Arm => "ARM",
            Arch::Arm64 => "AArch64",
            Arch::Unknown => "unknown",
        }
    }
    /// Decoder bitness for the x86 family (0 if not an x86 target).
    pub fn x86_bitness(self) -> u32 {
        match self {
            Arch::X86 => 32,
            Arch::X64 => 64,
            _ => 0,
        }
    }
}

#[derive(Clone)]
pub struct Segment {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub data: Vec<u8>,
    pub exec: bool,
}

impl Segment {
    pub fn end(&self) -> u64 {
        self.addr + self.data.len() as u64
    }
    pub fn contains(&self, va: u64) -> bool {
        va >= self.addr && va < self.end()
    }
}

#[derive(Clone)]
pub struct Symbol {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub is_func: bool,
}

#[derive(Clone)]
pub struct Program {
    pub format: String,
    pub arch: Arch,
    pub entry: u64,
    pub image_base: u64,
    pub segments: Vec<Segment>,
    pub symbols: Vec<Symbol>,
}

impl Program {
    pub fn segment_at(&self, va: u64) -> Option<&Segment> {
        self.segments.iter().find(|s| s.contains(va))
    }
    pub fn symbol_at(&self, va: u64) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.addr == va)
    }
    pub fn read(&self, va: u64, len: usize) -> &[u8] {
        if let Some(seg) = self.segment_at(va) {
            let off = (va - seg.addr) as usize;
            let end = (off + len).min(seg.data.len());
            &seg.data[off..end]
        } else {
            &[]
        }
    }
}

fn map_arch(a: object::Architecture) -> Arch {
    use object::Architecture as A;
    match a {
        A::I386 => Arch::X86,
        A::X86_64 => Arch::X64,
        A::Arm => Arch::Arm,
        A::Aarch64 => Arch::Arm64,
        _ => Arch::Unknown,
    }
}

/// Parse a recognised container, or fall back to treating the bytes as a raw
/// 64-bit code blob loaded at a default base.
pub fn load(data: &[u8]) -> Program {
    match object::File::parse(data) {
        Ok(file) => from_object(&file),
        Err(_) => raw(data),
    }
}

fn from_object(file: &object::File) -> Program {
    let arch = map_arch(file.architecture());
    let image_base = file.relative_address_base();

    let mut segments = Vec::new();
    for section in file.sections() {
        let size = section.size();
        if size == 0 {
            continue;
        }
        let kind = section.kind();
        let exec = matches!(kind, SectionKind::Text);
        // skip pure metadata/uninitialised sections without bytes
        let data = section.data().map(|d| d.to_vec()).unwrap_or_default();
        if data.is_empty() && !exec {
            continue;
        }
        segments.push(Segment {
            name: section.name().unwrap_or("<sec>").to_string(),
            addr: section.address(),
            size,
            data,
            exec,
        });
    }

    let mut symbols = Vec::new();
    for sym in file.symbols() {
        if !sym.is_definition() {
            continue;
        }
        let name = sym.name().unwrap_or("");
        if name.is_empty() {
            continue;
        }
        symbols.push(Symbol {
            name: name.to_string(),
            addr: sym.address(),
            size: sym.size(),
            is_func: sym.kind() == SymbolKind::Text,
        });
    }
    symbols.sort_by_key(|s| s.addr);
    symbols.dedup_by_key(|s| s.addr);

    Program {
        format: format!("{:?}", file.format()),
        arch,
        entry: file.entry(),
        image_base,
        segments,
        symbols,
    }
}

fn raw(data: &[u8]) -> Program {
    const BASE: u64 = 0x40_0000;
    Program {
        format: "Raw".into(),
        arch: Arch::X64,
        entry: BASE,
        image_base: BASE,
        segments: vec![Segment {
            name: ".text".into(),
            addr: BASE,
            size: data.len() as u64,
            data: data.to_vec(),
            exec: true,
        }],
        symbols: Vec::new(),
    }
}
