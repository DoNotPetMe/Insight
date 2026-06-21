# Insight

**Insight** is an interactive binary-analysis and decompilation platform built
for **game modding and discovery**. It identifies the engine behind a game,
unpacks it, disassembles and decompiles its logic into readable C-like
pseudocode, hunts down hidden content (dev rooms, test maps, unused/debug
content), and can even scan a game's memory while it runs — from a terminal, a
browser, or a native desktop app.

### Analysis front ends (one shared decompiler & UI)

| Front end | Input | What you get |
|-----------|-------|--------------|
| **Native** | ELF / PE executables, raw blobs (x86, x64, ARM, ARM64) — incl. Unity **IL2CPP**, Unreal C++, Source | function discovery, CFG, disassembly, lifted pseudocode |
| **Script VM** | stack/register bytecode (the reference **GameScript** VM; GML, GDScript, Blueprint plug into the same pipeline) | full structured pseudocode (`if`/`else`, `while`, calls, expressions) |

### Game-platform awareness

Insight detects the engine, tells you exactly how it will decompile that
engine's logic, points you at the right free/open-source unpacker, and (for
Unity) ingests assets in-process via UnityPy:

| Engine | Runtime | How Insight handles it | Recommended free tool |
|--------|---------|------------------------|-----------------------|
| **Unity** | Mono IL / IL2CPP native | IL2CPP → native lifter; assets via UnityPy | UnityPy, Il2CppDumper, AssetRipper, ILSpy |
| **Unreal** | C++ + Blueprint bytecode | native lifter; Blueprint → stack-VM pipeline | CUE4Parse / FModel, pyUE4Parse |
| **GameMaker** | GML bytecode | GML → stack-VM pipeline | UndertaleModTool |
| **Godot** | GDScript bytecode | GDScript → stack-VM pipeline | Godot RE Tools (gdsdecomp) |
| **Ren'Py** | compiled `.rpyc` | Python-AST path | unrpyc, rpatool |
| **RPG Maker** | JS + JSON | read directly (already source) | MV/MZ decrypter |
| **Source** | native + VPK/BSP | native lifter | VPKEdit, bspsrc |
| **Construct** | JS runtime | read directly | — |
| **id Tech / Doom** | native + WAD/PK3 | native lifter | SLADE |

> Insight is an original, clean-room project for studying software you are
> authorised to analyse: your own builds, CTF challenges, security research,
> interoperability, and **modding games you own**. It does not reuse code or
> data from, and is not a clone of, any existing product. The third-party tools
> above are independent open-source projects, linked for convenience.

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

### Working with whole games

```bash
# identify the engine and how Insight will decompile it
python -m insight.cli detect    "/path/to/Game"
# point me at the right open-source unpacker (marks Python libs you have)
python -m insight.cli tools     "/path/to/Game"
# hunt for dev rooms, test maps, unused/debug content, cheats, placeholders
python -m insight.cli discover  "/path/to/Game"
```

### Scanning a running game

```bash
python -m insight.cli procs                              # list processes
python -m insight.cli memscan 12345 --string "100/100" --authorize
python -m insight.cli memscan 12345 --int 1000 --size 4 --authorize
```

`--authorize` is required as an explicit acknowledgement that you are permitted
to inspect that process. Reading another process's memory usually needs elevated
privileges. Use it only on games you own.

### Desktop app

```bash
pip install -r requirements-full.txt    # adds PySide6, UnityPy, PyMemoryEditor
python -m insight.desktop                # native windowed app
```

The desktop app has **Overview** (engine + tools), **Code** (functions →
disassembly/pseudocode), **Discovery**, and **Live** (attach + memory scan)
tabs. A real **`Insight.exe`** is produced by the GitHub Actions
`Build Windows app` workflow (a Windows runner — PyInstaller can't
cross-compile), downloadable as the `Insight-windows` artifact, or build it
yourself on Windows with `pyinstaller packaging/insight.spec`.

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
| `insight detect PATH` | identify the game engine + decompiler strategy |
| `insight tools PATH` | recommended open-source unpackers for the engine |
| `insight discover PATH` | flag dev rooms / test maps / unused / debug content |
| `insight procs` | list running processes |
| `insight memscan PID --string S \| --int N --authorize` | scan live process memory |

`--func` accepts either a function name or the key shown by `list`. `PATH` may
be a single file or a whole game install directory.

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
    structuring.py       engine-neutral if/else + loop recovery (shared core)
    native.py            native lifter
  gamescript/            reference stack-VM front end (isa/module/assembler/
                         disassembler/cfg/decompiler)
  frontends/registry.py  per-engine decompiler strategy + status
  game/
    engines.py           engine registry + open-source tool references
    detect.py            engine detection (file magic + directory fingerprints)
    unpack.py            asset/script ingestion (UnityPy in-process)
    discovery.py         dev-room / test-map / unused-content scanner
    target.py            high-level game-target facade
  live/memscan.py        live process-memory scanning (Linux /proc + PyMemoryEditor)
  desktop/app.py         PySide6 native desktop application
  web/                   Flask app, templates, static assets
packaging/insight.spec   PyInstaller build → Insight.exe
.github/workflows/       Windows CI that builds and uploads the .exe
samples/build_samples.py builds samples/demo.gsv
tests/                   pytest suite (script, native, web, game, live)
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
