# Insight

**Insight** is an interactive binary-analysis and decompilation platform. It
loads a program, disassembles it, reconstructs control flow, and lifts the
result into readable C-like pseudocode — in a terminal or a browser.

It has two analysis front ends that share one decompiler and UI:

| Front end | Input | What you get |
|-----------|-------|--------------|
| **Native** | ELF / PE executables, or raw code blobs (x86, x64, ARM, ARM64) | function discovery, basic blocks, disassembly, and lifted low-level pseudocode |
| **Script VM** | compiled **GameScript** bytecode modules | full decompilation back to structured pseudocode (`if`/`else`, `while`, calls, expressions) |

The Script-VM front end is aimed squarely at **game modding and discovery**:
many engines ship their gameplay logic as compiled bytecode for an embedded
scripting VM. Insight models such a VM end to end so those compiled scripts can
be turned back into clean, editable pseudocode — making it far easier to
understand quest logic, AI behaviour, and tunables, and to mod them.

> Insight is an original, clean-room project for studying software you are
> authorised to analyse (your own builds, CTF challenges, malware research,
> interoperability, modding of games you own). It is not a clone of, and does
> not reuse code or data from, any existing product.

---

## Quick start

```bash
pip install -r requirements.txt          # capstone + flask
python samples/build_samples.py          # writes samples/demo.gsv

# explore from the terminal
python -m insight.cli info       samples/demo.gsv
python -m insight.cli list       samples/demo.gsv
python -m insight.cli decompile  samples/demo.gsv --func update_enemy
python -m insight.cli disasm     samples/demo.gsv --func sum_to

# ...or in the browser
python -m insight.cli serve      samples/demo.gsv      # http://127.0.0.1:8000
```

Native binaries work the same way:

```bash
python -m insight.cli decompile /path/to/program --func main
python -m insight.cli serve     /path/to/program
```

### Example

A compiled script blob in `samples/demo.gsv` decompiles to:

```c
function update_enemy(arg0, arg1) {
    local v2, v3;
    v2 = getHealth(arg0);
    if (v2 < 20) {
        playAnim(arg0, "flee");
        setSpeed(arg0, clamp(getSpeed(arg0) * 2, 1, 10));
    } else {
        v3 = findPlayer();
        moveToward(arg0, v3, arg1);
    }
    return v2;
}
```

—recovered entirely from bytecode: expressions, engine/API calls, an
inter-script call (`clamp`), and the `if`/`else` structure.

---

## How it works

```
                 ┌── loaders (elf / pe / raw) ──┐
   bytes ───────►│  GameScript module reader    │
                 └──────────────┬───────────────┘
                                ▼
          ┌─────────────────────────────────────────┐
          │  disassembly  (Capstone / GS decoder)    │
          ▼                                          ▼
   function discovery & CFG            basic blocks + CFG (bytecode)
          ▼                                          ▼
   low-level lifting                   symbolic stack execution
   (asm → C-like statements)           (recover expression trees)
          ▼                                          ▼
   structured / labelled view          control-flow structuring
                                       (if / else / while)
          └───────────────► C-like AST ◄────────────┘
                                ▼
                     pseudocode  +  web UI
```

### Native front end
* **Loaders** (`insight/loaders/`) — self-contained ELF and PE parsers extract
  sections, the entry point and the symbol table; raw blobs are also accepted.
* **Disassembler** (`insight/disasm/`) — a thin wrapper over
  [Capstone](https://www.capstone-engine.org/) with recursive-descent and
  linear modes, exposing a small instruction type with control-flow facts.
* **Analysis** (`insight/analysis/`) — discovers functions from symbols, the
  entry point and call targets, then carves each into basic blocks / a CFG, and
  recovers strings.
* **Lifter** (`insight/decompiler/native.py`) — turns instructions into
  readable C-like statements, folds `cmp`/`jcc` pairs into `if` conditions, and
  renders control flow with labelled blocks and `goto`.

Full native decompilation (type and variable recovery, full re-structuring) is
a large, ongoing effort; the native lifter is an honest first layer that makes
the recovered logic easy to read and refine by hand.

### Script-VM front end
The **GameScript VM** is a small stack machine documented in
`insight/gamescript/isa.py`. The decompiler (`insight/gamescript/decompiler.py`)
runs a complete pipeline:

1. **CFG construction** from the bytecode.
2. **Symbolic stack execution** per block to rebuild expression trees,
   assignments, and calls (with operator-precedence-aware printing).
3. **Control-flow structuring** using dominator / post-dominator analysis and
   natural-loop detection to recover `if`/`else` and `while`; irreducible flow
   degrades gracefully to labels and `goto` instead of failing.

Because the format is fully specified, the round trip
*source → bytecode → pseudocode* is exercised directly by the test-suite.

---

## The GameScript VM

A module file (`*.gsv`, magic `GSV1`) holds a string pool plus a table of
functions; each function is a stream of stack-machine instructions. The
instruction set covers constants, locals and globals, arithmetic / comparison /
bitwise ops, branches (`jmp`, `jz`, `jnz`), script calls (`call`), host/engine
API calls (`syscall`), and returns. See `insight/gamescript/isa.py` for the
full opcode table and encoding, and `insight/gamescript/assembler.py` for a
builder used to assemble test inputs and the sample module.

---

## Command reference

| Command | Description |
|---------|-------------|
| `insight info FILE` | format, architecture, segments, function/strings counts |
| `insight list FILE` | list discovered functions |
| `insight disasm FILE [--func KEY]` | disassembly (all functions, or one) |
| `insight decompile FILE [--func KEY]` | recovered pseudocode |
| `insight strings FILE` | recovered strings |
| `insight serve FILE [--host H] [--port N]` | interactive web UI |

`--func` accepts either a function name or the key shown by `list`.

---

## Project layout

```
insight/
  cli.py                 command-line interface
  project.py             format-detecting facade over both front ends
  core/binary.py         BinaryView: a format-neutral program model
  loaders/               elf.py, pe.py (self-contained parsers)
  disasm/engine.py       Capstone-backed disassembler
  analysis/              function discovery, CFG, strings
  decompiler/
    ast_nodes.py         shared C-like AST + pseudocode emitter
    native.py            native lifter
  gamescript/
    isa.py               VM instruction set & module format spec
    module.py            container reader/writer
    assembler.py         body builder (labels + branch fixups)
    disassembler.py      bytecode decoder
    cfg.py               basic blocks / CFG
    decompiler.py        symbolic execution + structuring → pseudocode
  web/                   Flask app, templates, static assets
samples/build_samples.py builds samples/demo.gsv
tests/                   pytest suite (script + native + web)
```

## Running the tests

```bash
pip install -r requirements.txt pytest
python -m pytest
```

The native tests compile a tiny C program with `gcc`/`cc`; they skip
automatically if no compiler is present.

## License

MIT — see `pyproject.toml`.
