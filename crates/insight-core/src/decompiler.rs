//! Decompiler: lift a native function to readable C-like pseudocode.
//!
//! Pipeline: instructions → basic blocks (with recovered branch conditions and
//! frame-variable names) → control-flow structuring (dominator / post-dominator
//! analysis + natural-loop detection) → nested `if`/`else`/`while`.  Anything
//! that cannot be folded into structured form degrades to labels and `goto`
//! rather than failing.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;

use regex::Regex;

use crate::analysis::Function;
use crate::disasm::{Flow, Insn};
use crate::loader::Program;

const EXIT: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// instruction → statement lifting
// ---------------------------------------------------------------------------
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

fn call_name(prog: &Program, target: Option<u64>) -> String {
    match target {
        Some(t) => prog
            .symbol_at(t)
            .map(|s| s.name.clone())
            .unwrap_or_else(|| format!("sub_{t:x}")),
        None => "/* indirect */".to_string(),
    }
}

/// Rename frame-relative memory operands to readable variables:
/// `[rbp - 0x18]` → `local_18`, `[rbp + 0x10]` → `arg_10`, `[rsp + 8]` → `var_8`.
fn rename_operands(s: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(?:(?:byte|word|dword|qword|xmmword|tbyte) ptr )?\[(rbp|ebp|rsp|esp)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]").unwrap()
    });
    re.replace_all(s, |c: &regex::Captures| {
        let reg = &c[1];
        let sign = &c[2];
        let raw = &c[3];
        let off = if let Some(h) = raw.strip_prefix("0x") {
            i64::from_str_radix(h, 16).unwrap_or(0)
        } else {
            raw.parse::<i64>().unwrap_or(0)
        };
        match (reg, sign) {
            ("rbp" | "ebp", "-") => format!("local_{off:x}"),
            ("rbp" | "ebp", "+") => format!("arg_{off:x}"),
            _ => format!("var_{off:x}"),
        }
    })
    .into_owned()
}

/// Lift a non-control instruction to a statement (control flow is handled by
/// the CFG); returns `None` for instructions with no data effect to print.
fn lift_data(insn: &Insn, prog: &Program) -> Option<String> {
    let m = insn.mnemonic.as_str();
    if m == "nop" || m.starts_with("nop") || m == "cmp" || m == "test" || m == "leave" {
        return None;
    }
    let ops = rename_operands(&insn.operands);
    let two = ops.split_once(", ");

    if matches!(m, "mov" | "movzx" | "movsx" | "movabs" | "movsxd" | "movaps" | "movdqa") {
        if let Some((d, s)) = two {
            return Some(format!("{d} = {s};"));
        }
    }
    if m == "lea" {
        if let Some((d, s)) = two {
            let inner = s.trim_start_matches('[').trim_end_matches(']');
            return Some(format!("{d} = &({inner});"));
        }
    }
    if let Some(op) = binop(m) {
        if let Some((d, s)) = two {
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
        _ => {}
    }
    match insn.flow {
        Flow::Call => Some(format!("{}();", call_name(prog, insn.target))),
        Flow::Return | Flow::Jump | Flow::CondJump => None,
        _ => Some(format!("__asm(\"{} {}\");", m, ops).replace(" \");", "\");")),
    }
}

// ---------------------------------------------------------------------------
// conditions / blocks
// ---------------------------------------------------------------------------
#[derive(Clone)]
struct Cond {
    lhs: String,
    op: String,
    rhs: String,
}

impl Cond {
    fn render(&self) -> String {
        if self.rhs.is_empty() {
            format!("{} {}", self.lhs, self.op)
        } else {
            format!("{} {} {}", self.lhs, self.op, self.rhs)
        }
    }
    fn negate(&self) -> Cond {
        let op = match self.op.as_str() {
            "==" => "!=",
            "!=" => "==",
            "<" => ">=",
            ">=" => "<",
            ">" => "<=",
            "<=" => ">",
            "< 0" => ">= 0",
            ">= 0" => "< 0",
            other => other,
        };
        Cond { lhs: self.lhs.clone(), op: op.to_string(), rhs: self.rhs.clone() }
    }
}

#[derive(Clone)]
enum Term {
    End,
    Jump(u64),
    Fall(u64),
    Cond(Cond, u64, u64), // (cond, true_succ, false_succ)
}

struct Block {
    stmts: Vec<String>,
    term: Term,
}

impl Block {
    fn succs(&self) -> Vec<u64> {
        match &self.term {
            Term::End => vec![],
            Term::Jump(t) | Term::Fall(t) => vec![*t],
            Term::Cond(_, a, b) => vec![*a, *b],
        }
    }
}

fn build_blocks(func: &Function, prog: &Program) -> (BTreeMap<u64, Block>, u64) {
    let leaders: Vec<u64> = func.block_starts.iter().copied().collect();
    let leaderset: &BTreeSet<u64> = &func.block_starts;
    let mut blocks = BTreeMap::new();

    for (i, &lead) in leaders.iter().enumerate() {
        let next = leaders.get(i + 1).copied().unwrap_or(u64::MAX);
        let body: Vec<&Insn> = func.insns.iter().filter(|x| x.addr >= lead && x.addr < next).collect();

        let mut stmts = Vec::new();
        let mut last_cmp: Option<(String, String)> = None;
        let mut term = Term::End;
        let mut terminated = false;

        for insn in &body {
            let m = insn.mnemonic.as_str();
            if m == "cmp" || m == "test" {
                let ops = rename_operands(&insn.operands);
                if let Some((a, b)) = ops.split_once(", ") {
                    if m == "test" {
                        // `test x, y` sets ZF from (x & y); compare that to 0
                        last_cmp = if a == b {
                            Some((a.to_string(), "0".to_string()))
                        } else {
                            Some((format!("({a} & {b})"), "0".to_string()))
                        };
                    } else {
                        last_cmp = Some((a.to_string(), b.to_string()));
                    }
                }
                continue;
            }
            match insn.flow {
                Flow::CondJump => {
                    let op = jcc_op(m).unwrap_or("?");
                    let cond = match &last_cmp {
                        Some((l, r)) if op.ends_with('0') => Cond { lhs: l.clone(), op: op.to_string(), rhs: String::new() },
                        Some((l, r)) => Cond { lhs: l.clone(), op: op.to_string(), rhs: r.clone() },
                        None => Cond { lhs: format!("({m})"), op: String::new(), rhs: String::new() },
                    };
                    let fall = insn.end();
                    match insn.target.filter(|t| leaderset.contains(t)) {
                        Some(t) => term = Term::Cond(cond, t, fall),
                        None => term = Term::Fall(fall),
                    }
                    terminated = true;
                    break;
                }
                Flow::Jump => {
                    match insn.target.filter(|t| leaderset.contains(t)) {
                        Some(t) => term = Term::Jump(t),
                        None => {
                            stmts.push(format!("{}();  // tail call", call_name(prog, insn.target)));
                            term = Term::End;
                        }
                    }
                    terminated = true;
                    break;
                }
                Flow::Return => {
                    stmts.push("return;".to_string());
                    term = Term::End;
                    terminated = true;
                    break;
                }
                _ => {
                    if let Some(s) = lift_data(insn, prog) {
                        stmts.push(s);
                    }
                }
            }
        }
        if !terminated {
            term = if next != u64::MAX { Term::Fall(next) } else { Term::End };
        }
        blocks.insert(lead, Block { stmts, term });
    }

    (blocks, func.addr)
}

// ---------------------------------------------------------------------------
// dominators (Cooper–Harvey–Kennedy)
// ---------------------------------------------------------------------------
fn dominators(nodes: &[u64], succs: &HashMap<u64, Vec<u64>>, entry: u64) -> HashMap<u64, u64> {
    let mut preds: HashMap<u64, Vec<u64>> = HashMap::new();
    for &n in nodes {
        preds.entry(n).or_default();
    }
    for &n in nodes {
        if let Some(ss) = succs.get(&n) {
            for &s in ss {
                preds.entry(s).or_default().push(n);
            }
        }
    }

    // postorder via explicit stack, then reverse for RPO
    let mut visited = HashSet::new();
    let mut post = Vec::new();
    let mut stack = vec![(entry, false)];
    while let Some((n, processed)) = stack.pop() {
        if processed {
            post.push(n);
            continue;
        }
        if !visited.insert(n) {
            continue;
        }
        stack.push((n, true));
        if let Some(ss) = succs.get(&n) {
            for &s in ss {
                if !visited.contains(&s) {
                    stack.push((s, false));
                }
            }
        }
    }
    let rpo: Vec<u64> = post.iter().rev().copied().collect();
    let rpo_index: HashMap<u64, usize> = rpo.iter().enumerate().map(|(i, &n)| (n, i)).collect();

    let mut idom: HashMap<u64, u64> = HashMap::new();
    idom.insert(entry, entry);

    let intersect = |mut a: u64, mut b: u64, idom: &HashMap<u64, u64>| -> u64 {
        while a != b {
            while rpo_index[&a] > rpo_index[&b] {
                a = idom[&a];
            }
            while rpo_index[&b] > rpo_index[&a] {
                b = idom[&b];
            }
        }
        a
    };

    let mut changed = true;
    while changed {
        changed = false;
        for &n in &rpo {
            if n == entry {
                continue;
            }
            let mut new_idom: Option<u64> = None;
            for &p in &preds[&n] {
                if idom.contains_key(&p) {
                    new_idom = Some(match new_idom {
                        Some(cur) => intersect(p, cur, &idom),
                        None => p,
                    });
                }
            }
            if let Some(ni) = new_idom {
                if idom.get(&n) != Some(&ni) {
                    idom.insert(n, ni);
                    changed = true;
                }
            }
        }
    }
    idom
}

fn dominates(idom: &HashMap<u64, u64>, mut node: u64, target: u64) -> bool {
    loop {
        if node == target {
            return true;
        }
        match idom.get(&node) {
            Some(&p) if p != node => node = p,
            _ => return false,
        }
    }
}

#[derive(Clone)]
struct Loop {
    header: u64,
    nodes: HashSet<u64>,
    follow: Option<u64>,
}

// ---------------------------------------------------------------------------
// structuring
// ---------------------------------------------------------------------------
enum Stmt {
    Line(String),
    Label(u64),
    Goto(u64),
    Break,
    If { cond: String, then: Vec<Stmt>, els: Vec<Stmt> },
    While { cond: String, body: Vec<Stmt> },
}

struct Structurer {
    blocks: BTreeMap<u64, Block>,
    ipdom: HashMap<u64, u64>,
    loops: HashMap<u64, Loop>,
    emitted: HashSet<u64>,
    entry: u64,
}

impl Structurer {
    fn new(blocks: BTreeMap<u64, Block>, entry: u64) -> Self {
        let nodes: Vec<u64> = blocks.keys().copied().collect();
        let succs: HashMap<u64, Vec<u64>> =
            blocks.iter().map(|(&a, b)| (a, b.succs())).collect();

        let idom = dominators(&nodes, &succs, entry);
        let reachable: HashSet<u64> = idom.keys().copied().collect();

        // natural loops from back edges
        let mut loops: HashMap<u64, Loop> = HashMap::new();
        for &n in &nodes {
            if !reachable.contains(&n) {
                continue;
            }
            for &s in &succs[&n] {
                if reachable.contains(&s) && dominates(&idom, n, s) {
                    let body = natural_loop(s, n, &succs, &reachable);
                    loops.entry(s)
                        .and_modify(|l| l.nodes.extend(body.iter().copied()))
                        .or_insert(Loop { header: s, nodes: body, follow: None });
                }
            }
        }
        for lp in loops.values_mut() {
            lp.follow = loop_follow(lp, &succs);
        }

        // post-dominators: dominators on the reversed graph with a virtual EXIT
        let mut rsuccs: HashMap<u64, Vec<u64>> = HashMap::new();
        rsuccs.insert(EXIT, Vec::new());
        for &n in &nodes {
            rsuccs.entry(n).or_default();
        }
        for &n in &nodes {
            if succs[&n].is_empty() {
                rsuccs.get_mut(&EXIT).unwrap().push(n);
            }
            for &s in &succs[&n] {
                rsuccs.entry(s).or_default().push(n);
            }
        }
        let rnodes: Vec<u64> = rsuccs.keys().copied().collect();
        let ipdom = dominators(&rnodes, &rsuccs, EXIT);

        Structurer { blocks, ipdom, loops, emitted: HashSet::new(), entry }
    }

    fn ipdom_of(&self, n: u64) -> Option<u64> {
        match self.ipdom.get(&n) {
            Some(&p) if p != EXIT && p != n => Some(p),
            _ => None,
        }
    }

    fn run(&mut self) -> Vec<Stmt> {
        let e = self.entry;
        self.structure(Some(e), None, None)
    }

    fn structure(&mut self, start: Option<u64>, stop: Option<u64>, loop_h: Option<u64>) -> Vec<Stmt> {
        let mut out = Vec::new();
        let mut cur = start;
        while let Some(c) = cur {
            if Some(c) == stop {
                break;
            }
            if let Some(h) = loop_h {
                let lp = &self.loops[&h];
                if c == lp.header && Some(c) != start {
                    break; // back edge → end of iteration
                }
                if Some(c) == lp.follow {
                    out.push(Stmt::Break);
                    break;
                }
            }
            if self.emitted.contains(&c) {
                out.push(Stmt::Goto(c));
                break;
            }
            if self.loops.contains_key(&c) && loop_h != Some(c) {
                let follow = self.loops[&c].follow;
                let mut s = self.structure_loop(c);
                out.append(&mut s);
                cur = follow;
                continue;
            }

            self.emitted.insert(c);
            out.push(Stmt::Label(c));
            let (stmts, term) = {
                let b = &self.blocks[&c];
                (b.stmts.clone(), b.term.clone())
            };
            for s in stmts {
                out.push(Stmt::Line(s));
            }
            match term {
                Term::End => cur = None,
                Term::Jump(t) | Term::Fall(t) => cur = Some(t),
                Term::Cond(cond, tt, ff) => {
                    let follow = self.ipdom_of(c);
                    let then_b = self.structure(Some(tt), follow, loop_h);
                    let else_b = self.structure(Some(ff), follow, loop_h);
                    if !then_b.is_empty() && else_b.is_empty() {
                        out.push(Stmt::If { cond: cond.render(), then: then_b, els: vec![] });
                    } else if then_b.is_empty() && !else_b.is_empty() {
                        out.push(Stmt::If { cond: cond.negate().render(), then: else_b, els: vec![] });
                    } else {
                        out.push(Stmt::If { cond: cond.render(), then: then_b, els: else_b });
                    }
                    cur = follow;
                }
            }
        }
        out
    }

    fn structure_loop(&mut self, header: u64) -> Vec<Stmt> {
        self.emitted.insert(header);
        let lp = self.loops[&header].clone();
        let (stmts, term) = {
            let b = &self.blocks[&header];
            (b.stmts.clone(), b.term.clone())
        };

        if let Term::Cond(cond, tt, ff) = term {
            let in_true = lp.nodes.contains(&tt);
            let while_cond = if in_true { cond.clone() } else { cond.negate() };
            let body_entry = if in_true { tt } else { ff };
            let body = self.structure(Some(body_entry), None, Some(header));
            if stmts.is_empty() {
                vec![Stmt::While { cond: while_cond.render(), body }]
            } else {
                // header recomputes the test each iteration → keep it inside
                let mut inner: Vec<Stmt> = stmts.into_iter().map(Stmt::Line).collect();
                inner.push(Stmt::If { cond: while_cond.negate().render(), then: vec![Stmt::Break], els: vec![] });
                inner.extend(body);
                vec![Stmt::While { cond: "true".to_string(), body: inner }]
            }
        } else {
            let entry = match term {
                Term::Jump(t) | Term::Fall(t) => Some(t),
                _ => None,
            };
            let mut body: Vec<Stmt> = stmts.into_iter().map(Stmt::Line).collect();
            body.extend(self.structure(entry, None, Some(header)));
            vec![Stmt::While { cond: "true".to_string(), body }]
        }
    }
}

fn natural_loop(header: u64, tail: u64, succs: &HashMap<u64, Vec<u64>>, reachable: &HashSet<u64>) -> HashSet<u64> {
    let mut preds: HashMap<u64, Vec<u64>> = HashMap::new();
    for &n in reachable {
        for &s in succs.get(&n).map(|v| v.as_slice()).unwrap_or(&[]) {
            if reachable.contains(&s) {
                preds.entry(s).or_default().push(n);
            }
        }
    }
    let mut body = HashSet::new();
    body.insert(header);
    body.insert(tail);
    let mut stack = vec![tail];
    while let Some(n) = stack.pop() {
        if let Some(ps) = preds.get(&n) {
            for &p in ps {
                if body.insert(p) {
                    stack.push(p);
                }
            }
        }
    }
    body
}

fn loop_follow(lp: &Loop, succs: &HashMap<u64, Vec<u64>>) -> Option<u64> {
    let mut exits: HashMap<u64, usize> = HashMap::new();
    for &n in &lp.nodes {
        for &s in succs.get(&n).map(|v| v.as_slice()).unwrap_or(&[]) {
            if !lp.nodes.contains(&s) {
                *exits.entry(s).or_default() += 1;
            }
        }
    }
    exits.into_iter().max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0))).map(|(k, _)| k)
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------
fn collect_gotos(stmts: &[Stmt], set: &mut HashSet<u64>) {
    for s in stmts {
        match s {
            Stmt::Goto(a) => {
                set.insert(*a);
            }
            Stmt::If { then, els, .. } => {
                collect_gotos(then, set);
                collect_gotos(els, set);
            }
            Stmt::While { body, .. } => collect_gotos(body, set),
            _ => {}
        }
    }
}

fn pad(indent: usize) -> String {
    "    ".repeat(indent)
}

fn render(stmts: &[Stmt], indent: usize, out: &mut Vec<String>, labels: &HashSet<u64>) {
    for s in stmts {
        match s {
            Stmt::Line(t) => out.push(format!("{}{}", pad(indent), t)),
            Stmt::Label(a) => {
                if labels.contains(a) {
                    out.push(format!("{}loc_{:x}:", pad(indent.saturating_sub(1)), a));
                }
            }
            Stmt::Goto(a) => out.push(format!("{}goto loc_{:x};", pad(indent), a)),
            Stmt::Break => out.push(format!("{}break;", pad(indent))),
            Stmt::If { cond, then, els } => {
                out.push(format!("{}if ({}) {{", pad(indent), cond));
                render(then, indent + 1, out, labels);
                if !els.is_empty() {
                    out.push(format!("{}}} else {{", pad(indent)));
                    render(els, indent + 1, out, labels);
                }
                out.push(format!("{}}}", pad(indent)));
            }
            Stmt::While { cond, body } => {
                out.push(format!("{}while ({}) {{", pad(indent), cond));
                render(body, indent + 1, out, labels);
                out.push(format!("{}}}", pad(indent)));
            }
        }
    }
}

pub fn decompile_lines(func: &Function, prog: &Program) -> Vec<String> {
    let mut out = vec![format!(
        "// {} @ {:#x}  ({} instructions)",
        func.name,
        func.addr,
        func.insns.len()
    )];
    if func.insns.is_empty() {
        out.push(format!("void {}() {{}}", func.name));
        return out;
    }
    let (blocks, entry) = build_blocks(func, prog);
    let mut st = Structurer::new(blocks, entry);
    let body = st.run();

    let mut labels = HashSet::new();
    collect_gotos(&body, &mut labels);

    out.push(format!("void {}() {{", func.name));
    let mut lines = Vec::new();
    render(&body, 1, &mut lines, &labels);
    out.extend(lines);
    out.push("}".to_string());
    out
}

pub fn decompile(func: &Function, prog: &Program) -> String {
    decompile_lines(func, prog).join("\n")
}
