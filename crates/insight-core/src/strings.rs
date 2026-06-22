//! Printable-string recovery from a program's segments.

use crate::loader::Program;

#[derive(Clone)]
pub struct FoundString {
    pub addr: u64,
    pub value: String,
    pub segment: String,
}

fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

pub fn find_strings(prog: &Program, min_len: usize) -> Vec<FoundString> {
    let mut out = Vec::new();
    for seg in &prog.segments {
        let data = &seg.data;
        let mut i = 0;
        while i < data.len() {
            if printable(data[i]) {
                let start = i;
                while i < data.len() && printable(data[i]) {
                    i += 1;
                }
                if i - start >= min_len {
                    out.push(FoundString {
                        addr: seg.addr + start as u64,
                        value: String::from_utf8_lossy(&data[start..i]).into_owned(),
                        segment: seg.name.clone(),
                    });
                }
            } else {
                i += 1;
            }
        }
    }
    out
}

/// Extract both ASCII and UTF-16LE strings from a raw byte buffer.
///
/// Game binaries (especially on Windows) store much of their text as UTF-16,
/// and useful markers often live in resources/overlays that aren't part of any
/// mapped section — so for discovery we scan the whole file, both encodings.
pub fn scan_bytes_for_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();

    // ASCII runs
    let mut i = 0;
    while i < data.len() {
        if printable(data[i]) {
            let start = i;
            while i < data.len() && printable(data[i]) {
                i += 1;
            }
            if i - start >= min_len {
                out.push(String::from_utf8_lossy(&data[start..i]).into_owned());
            }
        } else {
            i += 1;
        }
    }

    // UTF-16LE runs: (printable, 0x00) pairs
    let mut i = 0;
    while i + 1 < data.len() {
        if printable(data[i]) && data[i + 1] == 0 {
            let start = i;
            let mut s = String::new();
            while i + 1 < data.len() && printable(data[i]) && data[i + 1] == 0 {
                s.push(data[i] as char);
                i += 2;
            }
            if s.len() >= min_len {
                out.push(s);
            }
            if i == start {
                i += 2;
            }
        } else {
            i += 1;
        }
    }
    out
}

