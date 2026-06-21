# Insight

**Insight** is a native binary-analysis and reverse-engineering desktop
application. It loads a program (PE / ELF / Mach-O, or a raw blob), disassembles
it, recovers functions, basic blocks and strings, and presents them in a fast,
professional dark UI — built for studying and modding games you own.

It is written in **Rust** (engine + GUI) and compiles to a single
self-contained executable. Analysis runs on a background thread, so loading a
large game executable never freezes the window.

> Use Insight on software you are authorised to analyse: your own builds, CTF
> challenges, security research, interoperability, and modding games you own.
> It is an original, clean-room project and not a clone of any existing product.

---

## Features

- **Multi-format loader** — PE, ELF and Mach-O via the `object` crate; unknown
  inputs are treated as a raw code blob.
- **Accurate disassembly** — x86 / x86-64 through the pure-Rust `iced-x86`
  decoder (no C toolchain needed to build).
- **Function & block recovery** — seeds from symbols, the entry point and call
  targets; each function is carved into basic blocks.
- **Decompiler / pseudocode** — each function is lifted to readable C-like
  pseudocode: assignments, `cmp`/`jcc` folded into `if` conditions, resolved
  `call` names, and labelled blocks with `goto`.
- **Game-engine detection** — identifies Unity (Mono/IL2CPP), Unreal,
  GameMaker, Godot, Ren'Py, RPG Maker, Source, Construct and id Tech from file
  magic and install-folder fingerprints, with the recommended open-source
  unpacker for each.
- **Content discovery** — flags dev rooms, test maps, debug menus, unused /
  leftover content, cheats, placeholders and beta material from strings and
  filenames.
- **Live memory scanning** — attach to a running game and scan its memory for a
  string or integer (Linux `/proc` and Windows `ReadProcessMemory`), gated
  behind an explicit authorisation check.
- **Professional UI** — function list with live filter, virtualized disassembly
  listing with colour-coded mnemonics, click-to-navigate call/jump targets,
  plus Pseudocode / Hex / Segments / Strings / Game / Discovery / Live views.
- **Never freezes** — loading, analysis and memory scans run on worker threads
  that stream progress back to a responsive UI.
- **Single native binary** — ships as one `Insight.exe` (or a Linux/macOS
  binary), no runtime to install.

---

## Get the app

### Download the prebuilt `.exe` (no building)

1. Open the repo on GitHub → **Actions** → latest **Build** run.
2. Download the **`Insight-windows`** artifact.
3. Unzip and run **`Insight.exe`** — nothing else to install.

### Build it yourself

You need the [Rust toolchain](https://rustup.rs) (`rustup`, which gives you
`cargo`).

```bash
git clone https://github.com/donotpetme/insight.git
cd insight
cargo run --release            # builds and launches the app
```

On **Linux** the GUI needs a few system libraries first:

```bash
sudo apt-get install -y libxkbcommon-dev libxkbcommon-x11-0 libgl1-mesa-dev \
  libx11-dev libxrandr-dev libxi-dev libxcursor-dev libxinerama-dev
```

The release binary is written to `target/release/insight` (`insight.exe` on
Windows); copy it anywhere and run it standalone.

---

## Using it

1. **Open a binary** — click **Open…** (Windows/macOS native dialog), type a
   path and press **Load**, or **drag-and-drop** a file onto the window. You can
   also pass it on the command line: `insight path/to/game.exe`.
2. Pick a function from the left list (type in the filter box to narrow it).
3. Read the **Disassembly**; click a green `→ target` to jump to that function.
   Switch to **Hex** for raw bytes, or the **Segments** / **Strings** tabs on
   the left.

The status bar shows the detected format, architecture, entry point and the
function / string counts.

---

## Project layout

```
Cargo.toml                  workspace
crates/
  insight-core/             UI-agnostic analysis engine
    src/loader.rs           PE/ELF/Mach-O → format-neutral Program (object crate)
    src/disasm.rs           x86/x64 disassembly (iced-x86)
    src/analysis.rs         function discovery + basic-block carving
    src/decompiler.rs       instruction lifting → C-like pseudocode
    src/strings.rs          printable-string recovery
    src/game/               engine detection, tool registry, content discovery
    src/live.rs             live process-memory scanning (Linux /proc + Windows)
    src/lib.rs              Project::analyze() + tests
  insight-gui/              eframe/egui desktop app
    src/app.rs              multi-pane UI, listing, navigation, all views
    src/worker.rs           background load + scan threads (keeps UI responsive)
    src/theme.rs            professional dark theme
    src/main.rs             entry point
.github/workflows/build.yml Windows (.exe) + Linux CI
legacy-python/              the earlier Python prototype, kept for reference
```

The `legacy-python/` tree holds the previous Python/Qt prototype that these
Rust features were ported from; it is no longer needed to run Insight.

---

## Development

```bash
cargo test -p insight-core     # engine unit tests
cargo build --release          # optimised build
cargo clippy                   # lints
```

## License

MIT.
