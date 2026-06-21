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
