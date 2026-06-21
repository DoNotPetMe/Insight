//! x86 / x86-64 disassembly via the pure-Rust `iced-x86` decoder.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Normal,
    Call,
    Jump,
    CondJump,
    Return,
    Interrupt,
}

#[derive(Clone)]
pub struct Insn {
    pub addr: u64,
    pub len: u8,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub flow: Flow,
    /// Resolved absolute target for direct branches/calls.
    pub target: Option<u64>,
}

impl Insn {
    pub fn end(&self) -> u64 {
        self.addr + self.len as u64
    }
    pub fn text(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, self.operands)
        }
    }
    pub fn is_terminator(&self) -> bool {
        matches!(self.flow, Flow::Return | Flow::Jump)
    }
}

fn map_flow(fc: FlowControl) -> Flow {
    match fc {
        FlowControl::Call | FlowControl::IndirectCall => Flow::Call,
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => Flow::Jump,
        FlowControl::ConditionalBranch => Flow::CondJump,
        FlowControl::Return => Flow::Return,
        FlowControl::Interrupt => Flow::Interrupt,
        _ => Flow::Normal,
    }
}

/// Linearly disassemble `data`, which is mapped at virtual address `va`.
pub fn disasm(data: &[u8], va: u64, bitness: u32) -> Vec<Insn> {
    if bitness == 0 || data.is_empty() {
        return Vec::new();
    }
    let mut decoder = Decoder::with_ip(bitness, data, va, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_uppercase_hex(false);
    formatter.options_mut().set_space_after_operand_separator(true);

    let mut out = Vec::new();
    let mut instr = Instruction::default();
    let mut text = String::new();
    let mut mnem = String::new();

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        let start = instr.ip();
        let len = instr.len();

        text.clear();
        formatter.format(&instr, &mut text);
        // split mnemonic / operands on the first space
        let (m, ops) = match text.split_once(' ') {
            Some((m, ops)) => (m.to_string(), ops.to_string()),
            None => (text.clone(), String::new()),
        };
        mnem.clear();
        mnem.push_str(&m);

        let flow = map_flow(instr.flow_control());
        let target = match flow {
            Flow::Call | Flow::Jump | Flow::CondJump => {
                if instr.is_ip_rel_memory_operand() {
                    None
                } else {
                    let t = instr.near_branch_target();
                    if t != 0 {
                        Some(t)
                    } else {
                        None
                    }
                }
            }
            _ => None,
        };

        let off = (start - va) as usize;
        let bytes = data
            .get(off..off + len)
            .map(|b| b.to_vec())
            .unwrap_or_default();

        out.push(Insn {
            addr: start,
            len: len as u8,
            bytes,
            mnemonic: mnem.clone(),
            operands: ops,
            flow,
            target,
        });
    }
    out
}
