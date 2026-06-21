//! Function discovery and basic-block carving over disassembled code.

use std::collections::{BTreeMap, BTreeSet};

use crate::disasm::{disasm, Flow, Insn};
use crate::loader::{Arch, Program};

#[derive(Clone)]
pub struct Function {
    pub addr: u64,
    pub name: String,
    pub insns: Vec<Insn>,
    /// addresses that begin a basic block (for the listing's block markers)
    pub block_starts: BTreeSet<u64>,
    pub calls: Vec<u64>,
}

impl Function {
    pub fn size(&self) -> u64 {
        match (self.insns.first(), self.insns.last()) {
            (Some(f), Some(l)) => l.end() - f.addr,
            _ => 0,
        }
    }
}

pub struct Analysis {
    pub functions: Vec<Function>,
}

/// Discover and carve functions. `progress` is called with a 0..1 fraction and
/// a short status string so a UI can show movement without blocking.
pub fn analyze(prog: &Program, mut progress: impl FnMut(f32, &str)) -> Analysis {
    let bitness = prog.arch.x86_bitness();
    if bitness == 0 {
        // non-x86: nothing to disassemble yet
        return Analysis { functions: Vec::new() };
    }

    progress(0.05, "disassembling code sections");
    let exec: Vec<_> = prog.segments.iter().filter(|s| s.exec).collect();
    let total: usize = exec.iter().map(|s| s.data.len()).sum::<usize>().max(1);
    let mut done = 0usize;

    // linear sweep each executable segment, indexed by address
    let mut insns: BTreeMap<u64, Insn> = BTreeMap::new();
    let mut seg_ranges: Vec<(u64, u64)> = Vec::new();
    for seg in &exec {
        for insn in disasm(&seg.data, seg.addr, bitness) {
            insns.insert(insn.addr, insn);
        }
        seg_ranges.push((seg.addr, seg.end()));
        done += seg.data.len();
        progress(0.05 + 0.6 * (done as f32 / total as f32), "disassembling");
    }

    let in_exec = |va: u64| seg_ranges.iter().any(|&(a, b)| va >= a && va < b);

    // seeds: symbols, entry, and direct call targets
    progress(0.7, "discovering functions");
    let mut seeds: BTreeSet<u64> = BTreeSet::new();
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    for s in &prog.symbols {
        if s.is_func && in_exec(s.addr) {
            seeds.insert(s.addr);
            names.entry(s.addr).or_insert_with(|| s.name.clone());
        }
    }
    if in_exec(prog.entry) {
        seeds.insert(prog.entry);
        names.entry(prog.entry).or_insert_with(|| "entry".to_string());
    }
    for insn in insns.values() {
        if insn.flow == Flow::Call {
            if let Some(t) = insn.target {
                if in_exec(t) {
                    seeds.insert(t);
                }
            }
        }
    }
    if seeds.is_empty() {
        // no symbols/calls: treat each segment start as one function
        for &(a, _) in &seg_ranges {
            if insns.contains_key(&a) {
                seeds.insert(a);
            }
        }
    }

    // carve: each function spans from its seed to the next seed (or seg end)
    progress(0.85, "carving basic blocks");
    let seed_vec: Vec<u64> = seeds.iter().copied().collect();
    let seed_set: BTreeSet<u64> = seeds.clone();
    let mut functions = Vec::new();

    for (i, &start) in seed_vec.iter().enumerate() {
        let next_seed = seed_vec.get(i + 1).copied().unwrap_or(u64::MAX);
        let seg_end = seg_ranges
            .iter()
            .find(|&&(a, b)| start >= a && start < b)
            .map(|&(_, b)| b)
            .unwrap_or(next_seed);
        let limit = next_seed.min(seg_end);

        let mut body: Vec<Insn> = insns
            .range(start..limit)
            .map(|(_, v)| v.clone())
            .collect();
        // trim trailing padding after a clear terminator at function granularity
        if let Some(pos) = body.iter().position(|i| i.flow == Flow::Return) {
            // keep through the return; drop obvious alignment padding (int3/nop)
            let mut endp = pos + 1;
            while endp < body.len()
                && (body[endp].mnemonic == "int3" || body[endp].mnemonic == "nop")
            {
                endp += 1;
            }
            // only trim if what's left after padding would start a new seed
            if endp < body.len() && seed_set.contains(&body[endp].addr) {
                body.truncate(endp);
            }
        }
        if body.is_empty() {
            continue;
        }

        let block_starts = compute_block_starts(&body);
        let calls = body
            .iter()
            .filter(|i| i.flow == Flow::Call)
            .filter_map(|i| i.target)
            .collect();

        let name = names
            .get(&start)
            .cloned()
            .unwrap_or_else(|| format!("sub_{:x}", start));

        functions.push(Function {
            addr: start,
            name,
            insns: body,
            block_starts,
            calls,
        });
    }

    progress(1.0, "done");
    let _ = Arch::Unknown; // silence unused import path in some builds
    Analysis { functions }
}

fn compute_block_starts(body: &[Insn]) -> BTreeSet<u64> {
    let addr_set: BTreeSet<u64> = body.iter().map(|i| i.addr).collect();
    let mut leaders = BTreeSet::new();
    if let Some(f) = body.first() {
        leaders.insert(f.addr);
    }
    for insn in body {
        match insn.flow {
            Flow::Jump | Flow::CondJump => {
                if let Some(t) = insn.target {
                    if addr_set.contains(&t) {
                        leaders.insert(t);
                    }
                }
                if matches!(insn.flow, Flow::CondJump) && addr_set.contains(&insn.end()) {
                    leaders.insert(insn.end());
                }
            }
            Flow::Return => {
                if addr_set.contains(&insn.end()) {
                    leaders.insert(insn.end());
                }
            }
            _ => {}
        }
    }
    leaders
}
