//! Low-level pseudocode for native functions.
//!
//! A first decompilation layer (ported from the original prototype): each
//! instruction is lifted to a readable C-like statement, `cmp`/`jcc` pairs are
//! folded into `if` conditions, and control flow is rendered with labelled
//! blocks and `goto`.  Full structuring (recovering `if`/`while`) is a larger
//! effort; this makes the recovered logic easy to read and refine by hand.

use crate::analysis::Function;
use crate::disasm::{Flow, Insn};
use crate::loader::Program;

fn jcc_op(m: &str) -> Option<&'static str> {
    Some(match m {
        "je" | "jz" => "==",
        "jne" | "jnz" => "!=",
        "jg" | "jnle" | "ja" => ">",
        "jge" | "jnl" | "jae" => ">=",
        "jl" | "jnge" | "jb" => "<",
        "jle" | "jng" | "jbe" => "<=",
        "js" => "< 0",
        "jns" => ">= 0",
        _ => return None,
    })
}

fn binop(m: &str) -> Option<&'static str> {
    Some(match m {
        "add" => "+=",
        "sub" => "-=",
        "and" => "&=",
        "or" => "|=",
        "xor" => "^=",
        "shl" | "sal" => "<<=",
        "shr" | "sar" => ">>=",
        "imul" | "mul" => "*=",
        _ => return None,
    })
}

fn label(addr: u64) -> String {
    format!("loc_{addr:x}")
}

fn call_name(prog: &Program, target: Option<u64>) -> String {
    match target {
        Some(t) => prog
            .symbol_at(t)
            .map(|s| s.name.clone())
            .unwrap_or_else(|| format!("sub_{t:x}")),
        None => "/* indirect */".to_string(),
    }
}

fn two_ops(insn: &Insn) -> Option<(&str, &str)> {
    insn.operands.split_once(", ")
}

/// Produce pseudocode for one function as a list of lines.
pub fn decompile_lines(func: &Function, prog: &Program) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!(
        "// {} @ {:#x}  ({} instructions)",
        func.name,
        func.addr,
        func.insns.len()
    ));
    out.push(format!("void {}() {{", func.name));

    let mut last_cmp: Option<(String, String)> = None;

    for insn in &func.insns {
        if func.block_starts.contains(&insn.addr) {
            out.push(format!("{}:", label(insn.addr)));
        }
        let m = insn.mnemonic.as_str();
        let stmt = lift(insn, prog, &last_cmp);

        // update compare context
        if m == "cmp" || m == "test" {
            if let Some((a, b)) = two_ops(insn) {
                last_cmp = Some((a.to_string(), b.to_string()));
            }
        } else if jcc_op(m).is_some() {
            last_cmp = None;
        }

        if let Some(s) = stmt {
            out.push(format!("    {s}"));
        }
    }
    out.push("}".to_string());
    out
}

pub fn decompile(func: &Function, prog: &Program) -> String {
    decompile_lines(func, prog).join("\n")
}

fn lift(insn: &Insn, prog: &Program, last_cmp: &Option<(String, String)>) -> Option<String> {
    let m = insn.mnemonic.as_str();
    let ops = &insn.operands;

    if m == "nop" || m.starts_with("nop") {
        return None;
    }
    if matches!(m, "mov" | "movzx" | "movsx" | "movabs" | "movsxd") {
        if let Some((d, s)) = two_ops(insn) {
            return Some(format!("{d} = {s};"));
        }
    }
    if m == "lea" {
        if let Some((d, s)) = two_ops(insn) {
            let inner = s.trim_start_matches('[').trim_end_matches(']');
            return Some(format!("{d} = &({inner});"));
        }
    }
    if let Some(op) = binop(m) {
        if let Some((d, s)) = two_ops(insn) {
            return Some(format!("{d} {op} {s};"));
        }
    }
    match m {
        "inc" => return Some(format!("{ops}++;")),
        "dec" => return Some(format!("{ops}--;")),
        "neg" => return Some(format!("{ops} = -{ops};")),
        "not" => return Some(format!("{ops} = ~{ops};")),
        "push" => return Some(format!("push({ops});")),
        "pop" => return Some(format!("{ops} = pop();")),
        "cmp" | "test" => return Some(format!("// flags = {}", insn.text())),
        "leave" => return Some("/* leave */".to_string()),
        _ => {}
    }

    match insn.flow {
        Flow::Call => {
            let name = call_name(prog, insn.target);
            Some(format!("{name}();"))
        }
        Flow::Return => Some("return;".to_string()),
        Flow::CondJump => {
            let target = insn
                .target
                .map(label)
                .unwrap_or_else(|| ops.clone());
            if let Some(op) = jcc_op(m) {
                if let Some((lhs, rhs)) = last_cmp {
                    let cond = if op.ends_with('0') {
                        format!("{lhs} {op}")
                    } else {
                        format!("{lhs} {op} {rhs}")
                    };
                    return Some(format!("if ({cond}) goto {target};"));
                }
            }
            Some(format!("if ({m}) goto {target};"))
        }
        Flow::Jump => {
            let target = insn
                .target
                .map(label)
                .unwrap_or_else(|| ops.clone());
            Some(format!("goto {target};"))
        }
        _ => Some(format!("__asm(\"{}\");", insn.text())),
    }
}
