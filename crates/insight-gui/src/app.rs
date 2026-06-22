//! The Insight desktop application shell and views.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;

use egui::{Align, Color32, Layout, RichText, Sense, TextStyle};
use insight_core::game::GameReport;
use insight_core::live::{list_processes, ProcInfo};
use insight_core::Project;

use crate::theme::{self, Palette};
use crate::worker::{spawn_load, spawn_scan, Msg, ScanMsg};

#[derive(PartialEq, Clone, Copy)]
enum ScanKind {
    String,
    Int32,
}

#[derive(PartialEq, Clone, Copy)]
enum LeftTab {
    Functions,
    Segments,
    Strings,
}

#[derive(PartialEq, Clone, Copy)]
enum CenterTab {
    Pseudocode,
    Disassembly,
    Hex,
    Game,
    Discovery,
    Live,
}

pub struct App {
    project: Option<Project>,
    file_name: String,

    rx: Option<Receiver<Msg>>,
    loading: bool,
    progress: f32,
    status: String,
    error: Option<String>,
    path_input: String,

    left_tab: LeftTab,
    center_tab: CenterTab,
    filter: String,
    selected: Option<usize>,
    addr_to_func: HashMap<u64, usize>,
    pending_load: Option<PathBuf>,

    game: Option<GameReport>,

    // discovery view state
    disc_filter: String,
    disc_hide_noise: bool,
    disc_selected: Option<usize>,
    disc_cats: std::collections::HashSet<String>,
    disc_note: String,

    // launch/load state
    loaded_path: Option<PathBuf>,
    game_exe: Option<PathBuf>,
    launch_args: String,
    launch_for: Option<usize>,
    launch_note: String,

    // live-scan state
    procs: Vec<ProcInfo>,
    proc_filter: String,
    selected_pid: Option<u32>,
    scan_value: String,
    scan_kind: ScanKind,
    authorized: bool,
    scanning: bool,
    scan_rx: Option<Receiver<ScanMsg>>,
    scan_hits: Vec<u64>,
    scan_note: String,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);
        Self {
            project: None,
            file_name: String::new(),
            rx: None,
            loading: false,
            progress: 0.0,
            status: String::new(),
            error: None,
            path_input: String::new(),
            left_tab: LeftTab::Functions,
            center_tab: CenterTab::Pseudocode,
            filter: String::new(),
            selected: None,
            addr_to_func: HashMap::new(),
            pending_load: std::env::args().nth(1).map(PathBuf::from),
            game: None,
            disc_filter: String::new(),
            disc_hide_noise: true,
            disc_selected: None,
            disc_cats: std::collections::HashSet::new(),
            disc_note: String::new(),
            loaded_path: None,
            game_exe: None,
            launch_args: String::new(),
            launch_for: None,
            launch_note: String::new(),
            procs: Vec::new(),
            proc_filter: String::new(),
            selected_pid: None,
            scan_value: String::new(),
            scan_kind: ScanKind::String,
            authorized: false,
            scanning: false,
            scan_rx: None,
            scan_hits: Vec::new(),
            scan_note: String::new(),
        }
    }

    fn begin_load(&mut self, path: PathBuf, ctx: &egui::Context) {
        self.file_name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.error = None;
        self.loading = true;
        self.progress = 0.0;
        self.status = "starting".into();
        self.selected = None;
        self.project = None;
        self.game = None;
        self.disc_selected = None;
        self.launch_for = None;
        self.game_exe = None;
        self.loaded_path = Some(path.clone());
        self.rx = Some(spawn_load(path, ctx.clone()));
    }

    fn detect_game_exe(&mut self) {
        let Some(path) = self.loaded_path.clone() else { return };
        self.game_exe = if path.is_dir() {
            insight_core::launch::find_game_exe(&path)
        } else if path.extension().map(|e| e.eq_ignore_ascii_case("exe")).unwrap_or(false) {
            Some(path)
        } else {
            path.parent().and_then(insight_core::launch::find_game_exe)
        };
    }

    fn poll_scan(&mut self) {
        let mut done = false;
        if let Some(rx) = &self.scan_rx {
            if let Ok(msg) = rx.try_recv() {
                match msg {
                    ScanMsg::Done(hits) => {
                        self.scan_note = format!("{} hit(s)", hits.len());
                        self.scan_hits = hits;
                    }
                    ScanMsg::Error(e) => self.scan_note = format!("error: {e}"),
                }
                self.scanning = false;
                done = true;
            }
        }
        if done {
            self.scan_rx = None;
        }
    }

    fn poll(&mut self) {
        let mut finished = false;
        let mut did_load = false;
        if let Some(rx) = &self.rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    Msg::Progress(f, s) => {
                        self.progress = f;
                        self.status = s;
                    }
                    Msg::Done(loaded, _path) => {
                        let loaded = *loaded;
                        if let Some(proj) = loaded.project {
                            self.addr_to_func = proj
                                .functions
                                .iter()
                                .enumerate()
                                .map(|(i, f)| (f.addr, i))
                                .collect();
                            self.selected =
                                if proj.functions.is_empty() { None } else { Some(0) };
                            self.project = Some(proj);
                        } else {
                            // a game folder: no single binary, jump to the Game view
                            self.center_tab = CenterTab::Game;
                        }
                        self.game = Some(loaded.game);
                        self.loading = false;
                        finished = true;
                        did_load = true;
                    }
                    Msg::Error(e) => {
                        self.error = Some(e);
                        self.loading = false;
                        finished = true;
                    }
                }
            }
        }
        if finished {
            self.rx = None;
        }
        if did_load {
            self.detect_game_exe();
        }
    }

    fn navigate_to(&mut self, addr: u64) {
        if let Some(&idx) = self.addr_to_func.get(&addr) {
            self.selected = Some(idx);
            self.center_tab = CenterTab::Disassembly;
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(p) = self.pending_load.take() {
            if p.exists() {
                self.begin_load(p, ctx);
            }
        }
        self.poll();
        self.poll_scan();

        // drag-and-drop
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        if let Some(p) = dropped.into_iter().next() {
            self.begin_load(p, ctx);
        }

        // move project/game out so panels can mutate `self` freely (no clash)
        let project = self.project.take();
        let game = self.game.take();

        self.top_bar(ctx);
        self.status_bar(ctx, project.as_ref());
        self.left_panel(ctx, project.as_ref());
        self.central_panel(ctx, project.as_ref(), game.as_ref());

        self.project = project;
        self.game = game;

        if self.loading {
            ctx.request_repaint();
        }
    }
}

/// Version + build identifier. In CI the commit SHA is embedded so a running
/// app can be matched to an exact build; locally it shows "dev".
fn build_tag() -> String {
    let sha = option_env!("GITHUB_SHA").unwrap_or("dev");
    let short = &sha[..sha.len().min(7)];
    format!("v{} · {}", env!("CARGO_PKG_VERSION"), short)
}

impl App {
    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top")
            .exact_height(44.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.add_space(4.0);
                    ui.label(RichText::new("◢ INSIGHT").strong().size(16.0).color(Palette::ACCENT));
                    ui.add_space(8.0);
                    #[cfg(any(windows, target_os = "macos"))]
                    if ui.button("Open file…").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.begin_load(path, ctx);
                        }
                    }
                    #[cfg(any(windows, target_os = "macos"))]
                    if ui.button("Open game folder…").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_folder() {
                            self.begin_load(path, ctx);
                        }
                    }
                    let go = ui.add(egui::TextEdit::singleline(&mut self.path_input)
                        .hint_text("…or paste a path to a file or game folder")
                        .desired_width(300.0))
                        .lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter));
                    if (ui.button("Load").clicked() || go) && !self.path_input.trim().is_empty() {
                        let p = self.path_input.trim().trim_matches('"').to_string();
                        self.begin_load(PathBuf::from(p), ctx);
                    }
                    ui.separator();
                    if !self.file_name.is_empty() {
                        ui.label(RichText::new(&self.file_name).color(Palette::TEXT));
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.add_space(4.0);
                        ui.label(RichText::new(build_tag()).small().monospace().color(Palette::MUTED));
                    });
                });
            });
    }

    fn status_bar(&mut self, ctx: &egui::Context, project: Option<&Project>) {
        egui::TopBottomPanel::bottom("status")
            .exact_height(26.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    if self.loading {
                        ui.add(egui::Spinner::new().size(14.0));
                        ui.label(RichText::new(format!("{}…", self.status)).color(Palette::MUTED));
                        ui.add(egui::ProgressBar::new(self.progress).desired_width(180.0).rounding(3.0));
                    } else if let Some(err) = &self.error {
                        ui.label(RichText::new(format!("✖ {err}")).color(Palette::MN_RET));
                    } else if let Some(p) = project {
                        chip(ui, "format", &p.program.format);
                        chip(ui, "arch", p.program.arch.label());
                        chip(ui, "entry", &format!("{:#x}", p.program.entry));
                        chip(ui, "functions", &p.functions.len().to_string());
                        chip(ui, "strings", &p.strings.len().to_string());
                    } else {
                        ui.label(RichText::new("ready").color(Palette::MUTED));
                    }
                });
            });
    }

    fn left_panel(&mut self, ctx: &egui::Context, project: Option<&Project>) {
        egui::SidePanel::left("left")
            .resizable(true)
            .default_width(300.0)
            .width_range(220.0..=460.0)
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    tab(ui, &mut self.left_tab, LeftTab::Functions, "Functions");
                    tab(ui, &mut self.left_tab, LeftTab::Segments, "Segments");
                    tab(ui, &mut self.left_tab, LeftTab::Strings, "Strings");
                });
                ui.separator();

                let Some(p) = project else {
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("Open a binary to begin").color(Palette::MUTED));
                    });
                    return;
                };

                match self.left_tab {
                    LeftTab::Functions => self.functions_list(ui, p),
                    LeftTab::Segments => segments_list(ui, p),
                    LeftTab::Strings => strings_list(ui, p),
                }
            });
    }

    fn functions_list(&mut self, ui: &mut egui::Ui, p: &Project) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("🔍");
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("filter…").desired_width(f32::INFINITY));
        });
        ui.add_space(4.0);
        let needle = self.filter.to_lowercase();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for (i, f) in p.functions.iter().enumerate() {
                if !needle.is_empty() && !f.name.to_lowercase().contains(&needle) {
                    continue;
                }
                let selected = self.selected == Some(i);
                let resp = ui.add(FuncRow { name: &f.name, addr: f.addr, size: f.size(), selected });
                if resp.clicked() {
                    self.selected = Some(i);
                    self.center_tab = CenterTab::Disassembly;
                }
            }
        });
    }

    fn central_panel(&mut self, ctx: &egui::Context, project: Option<&Project>, game: Option<&GameReport>) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                tab(ui, &mut self.center_tab, CenterTab::Pseudocode, "Pseudocode");
                tab(ui, &mut self.center_tab, CenterTab::Disassembly, "Disassembly");
                tab(ui, &mut self.center_tab, CenterTab::Hex, "Hex");
                ui.add_space(6.0);
                ui.label(RichText::new("│").color(Palette::BORDER));
                ui.add_space(6.0);
                tab(ui, &mut self.center_tab, CenterTab::Game, "Game");
                tab(ui, &mut self.center_tab, CenterTab::Discovery, "Discovery");
                tab(ui, &mut self.center_tab, CenterTab::Live, "Live");
            });
            ui.separator();

            // global views first (they don't need a loaded binary / selection)
            match self.center_tab {
                CenterTab::Game => return game_view(ui, game),
                CenterTab::Discovery => return self.discovery_view(ui, ctx, game),
                CenterTab::Live => return self.live_view(ui, ctx),
                _ => {}
            }

            let Some(p) = project else {
                ui.centered_and_justified(|ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(160.0);
                        ui.label(RichText::new("Open a game to begin").size(18.0).color(Palette::TEXT));
                        ui.add_space(8.0);
                        ui.label(RichText::new("• “Open game folder…” — best for discovery (scans level names & scripts)").color(Palette::MUTED));
                        ui.label(RichText::new("• “Open file…” — pick the game .exe to disassemble & decompile it").color(Palette::MUTED));
                        ui.label(RichText::new("• or paste a path (right-click a folder ▸ Copy as path) and press Load").color(Palette::MUTED));
                        ui.add_space(6.0);
                        ui.label(RichText::new("Tip: if drag-and-drop does nothing, the app is likely running as Administrator — use the buttons above instead.").small().color(Palette::MUTED));
                    });
                });
                return;
            };
            let Some(sel) = self.selected else {
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new("Select a function").color(Palette::MUTED));
                });
                return;
            };
            let func = &p.functions[sel];
            match self.center_tab {
                CenterTab::Pseudocode => pseudo_view(ui, func, &p.program),
                CenterTab::Disassembly => self.disasm_view(ui, p, sel),
                CenterTab::Hex => hex_view(ui, func),
                _ => {}
            }
        });
    }

    fn live_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.add_space(4.0);
        ui.label(RichText::new("Scan a running process's memory").strong());
        ui.label(RichText::new("Only scan processes you own or are authorised to inspect. Elevated privileges are usually required.").small().color(Palette::MUTED));
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            if ui.button("Refresh processes").clicked() {
                self.procs = list_processes();
            }
            ui.add(egui::TextEdit::singleline(&mut self.proc_filter).hint_text("filter processes…").desired_width(200.0));
        });
        if self.procs.is_empty() {
            self.procs = list_processes();
        }

        ui.add_space(4.0);
        egui::ScrollArea::vertical().max_height(220.0).auto_shrink([false, false]).show(ui, |ui| {
            let needle = self.proc_filter.to_lowercase();
            for p in &self.procs {
                if !needle.is_empty() && !p.name.to_lowercase().contains(&needle) {
                    continue;
                }
                let sel = self.selected_pid == Some(p.pid);
                let txt = format!("{:>7}  {}", p.pid, p.name);
                if ui.selectable_label(sel, RichText::new(txt).monospace()).clicked() {
                    self.selected_pid = Some(p.pid);
                }
            }
        });

        ui.separator();
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("scankind")
                .selected_text(match self.scan_kind {
                    ScanKind::String => "string",
                    ScanKind::Int32 => "int32",
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.scan_kind, ScanKind::String, "string");
                    ui.selectable_value(&mut self.scan_kind, ScanKind::Int32, "int32");
                });
            ui.add(egui::TextEdit::singleline(&mut self.scan_value).hint_text("value to scan for").desired_width(220.0));
            ui.checkbox(&mut self.authorized, "I'm authorised");
            let can = self.selected_pid.is_some() && self.authorized && !self.scanning && !self.scan_value.is_empty();
            if ui.add_enabled(can, egui::Button::new("Scan")).clicked() {
                let needle = match self.scan_kind {
                    ScanKind::String => self.scan_value.as_bytes().to_vec(),
                    ScanKind::Int32 => self.scan_value.trim().parse::<i32>().map(|v| v.to_le_bytes().to_vec()).unwrap_or_default(),
                };
                if needle.is_empty() {
                    self.scan_note = "invalid value".into();
                } else if let Some(pid) = self.selected_pid {
                    self.scanning = true;
                    self.scan_hits.clear();
                    self.scan_note = "scanning…".into();
                    self.scan_rx = Some(spawn_scan(pid, needle, ctx.clone()));
                }
            }
            if self.scanning {
                ui.add(egui::Spinner::new().size(14.0));
            }
            if !self.scan_note.is_empty() {
                ui.label(RichText::new(&self.scan_note).color(Palette::MUTED));
            }
        });

        ui.add_space(4.0);
        let row_h = ui.text_style_height(&TextStyle::Monospace) + 3.0;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, row_h, self.scan_hits.len(), |ui, range| {
            for i in range {
                mono(ui, &format!("{:#018x}", self.scan_hits[i]), Palette::ACCENT);
            }
        });
    }

    fn disasm_view(&mut self, ui: &mut egui::Ui, p: &Project, sel: usize) {
        let func = &p.functions[sel];
        ui.add_space(2.0);
        ui.label(RichText::new(format!("{}   ({:#x} · {} bytes · {} insns)", func.name, func.addr, func.size(), func.insns.len())).strong());
        ui.add_space(4.0);

        let row_h = ui.text_style_height(&TextStyle::Monospace) + 4.0;
        let mut nav: Option<u64> = None;
        egui::ScrollArea::both().auto_shrink([false, false]).show_rows(
            ui,
            row_h,
            func.insns.len(),
            |ui, range| {
                for idx in range {
                    let insn = &func.insns[idx];
                    if insn.addr != func.addr && func.block_starts.contains(&insn.addr) {
                        ui.add_space(3.0);
                    }
                    ui.horizontal(|ui| {
                        mono(ui, &format!("{:016x}", insn.addr), Palette::ADDR);
                        ui.add_space(8.0);
                        let bytes: String = insn.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
                        mono_fixed(ui, &bytes, Palette::BYTES, 230.0);
                        ui.add_space(8.0);
                        mono_fixed(ui, &insn.mnemonic, theme::mn_color(insn.flow), 64.0);
                        if !insn.operands.is_empty() {
                            mono(ui, &insn.operands, Palette::TEXT);
                        }
                        // navigable branch/call target
                        if let Some(t) = insn.target {
                            if let Some(&fi) = self.addr_to_func.get(&t) {
                                ui.add_space(8.0);
                                let label = format!("→ {}", p.functions[fi].name);
                                if ui.add(egui::Label::new(RichText::new(label).monospace().color(Palette::ACCENT)).sense(Sense::click())).clicked() {
                                    nav = Some(t);
                                }
                            }
                        }
                    });
                }
            },
        );
        if let Some(t) = nav {
            self.navigate_to(t);
        }
    }
}

// ---------------------------------------------------------------------------
// small view helpers
// ---------------------------------------------------------------------------
fn chip(ui: &mut egui::Ui, key: &str, val: &str) {
    ui.label(RichText::new(key).small().color(Palette::MUTED));
    ui.label(RichText::new(val).small().monospace().color(Palette::TEXT));
    ui.separator();
}

fn tab<T: PartialEq + Copy>(ui: &mut egui::Ui, current: &mut T, value: T, text: &str) {
    let selected = *current == value;
    let color = if selected { Palette::ACCENT } else { Palette::MUTED };
    if ui.add(egui::Label::new(RichText::new(text).color(color).strong()).sense(Sense::click())).clicked() {
        *current = value;
    }
}

fn mono(ui: &mut egui::Ui, text: &str, color: Color32) {
    ui.label(RichText::new(text).monospace().color(color));
}

fn mono_fixed(ui: &mut egui::Ui, text: &str, color: Color32, width: f32) {
    ui.add_sized([width, ui.text_style_height(&TextStyle::Monospace)], egui::Label::new(RichText::new(text).monospace().color(color)).halign(Align::LEFT));
}

fn segments_list(ui: &mut egui::Ui, p: &Project) {
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        for s in &p.program.segments {
            ui.horizontal(|ui| {
                let c = if s.exec { Palette::MN_JUMP } else { Palette::MUTED };
                mono_fixed(ui, &s.name, Palette::TEXT, 120.0);
                mono(ui, &format!("{:#012x}", s.addr), Palette::ADDR);
                ui.label(RichText::new(format!("{} B", s.size)).small().color(Palette::MUTED));
                ui.label(RichText::new(if s.exec { "x" } else { " " }).small().color(c));
            });
        }
    });
}

fn strings_list(ui: &mut egui::Ui, p: &Project) {
    let row_h = ui.text_style_height(&TextStyle::Monospace) + 4.0;
    egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, row_h, p.strings.len(), |ui, range| {
        for i in range {
            let s = &p.strings[i];
            ui.horizontal(|ui| {
                mono_fixed(ui, &format!("{:#x}", s.addr), Palette::ADDR, 110.0);
                mono(ui, &s.value, Palette::STR);
            });
        }
    });
}

fn game_view(ui: &mut egui::Ui, game: Option<&GameReport>) {
    let Some(g) = game else {
        ui.centered_and_justified(|ui| {
            ui.label(RichText::new("Load a game file or folder to detect its engine").color(Palette::MUTED));
        });
        return;
    };
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        ui.add_space(6.0);
        let Some(d) = g.best() else {
            ui.label(RichText::new("No known engine signature matched.").color(Palette::MUTED));
            return;
        };
        let title = if d.variant.is_empty() {
            d.name.clone()
        } else {
            format!("{} · {}", d.name, d.variant)
        };
        ui.label(RichText::new(title).size(18.0).strong().color(Palette::ACCENT));
        ui.label(RichText::new(format!("{:.0}% confidence", d.confidence * 100.0)).small().color(Palette::MUTED));
        ui.add_space(8.0);

        if let Some(eng) = g.engine() {
            kv(ui, "Runtime", eng.runtime);
            kv(ui, "Insight", eng.support);
        }
        ui.add_space(8.0);
        ui.label(RichText::new("Evidence").strong());
        for e in &d.evidence {
            ui.label(RichText::new(format!("· {e}")).monospace().color(Palette::TEXT));
        }
        ui.add_space(10.0);
        if let Some(eng) = g.engine() {
            if !eng.tools.is_empty() {
                ui.label(RichText::new("Recommended open-source tools").strong());
                for t in eng.tools {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("· {}", t.name)).color(Palette::TEXT));
                        ui.label(RichText::new(format!("({})", t.purpose)).small().color(Palette::MUTED));
                        ui.hyperlink_to(RichText::new(t.url).small().color(Palette::ACCENT), t.url);
                    });
                }
            }
        }
    });
}

impl App {
    fn discovery_view(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context, game: Option<&GameReport>) {
        let Some(g) = game else {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("Load a game folder to scan for dev rooms, test maps & unused content").color(Palette::MUTED));
            });
            return;
        };
        if g.discovery.is_empty() {
            ui.add_space(8.0);
            ui.label(RichText::new("No notable content discovered.").color(Palette::MUTED));
            return;
        }

        // controls row
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.disc_filter).hint_text("filter findings…").desired_width(220.0));
            ui.checkbox(&mut self.disc_hide_noise, "Hide SDK/middleware noise");
            if ui.button("Export…").clicked() {
                self.disc_note = export_findings(&g.discovery);
            }
            if !self.disc_note.is_empty() {
                ui.label(RichText::new(&self.disc_note).small().color(Palette::MUTED));
            }
        });

        // category chips (click to toggle; none selected = show all)
        ui.horizontal_wrapped(|ui| {
            for (cat, n) in g.discovery_summary() {
                let on = self.disc_cats.contains(&cat);
                let col = if on { Palette::ACCENT } else { Palette::MN_JUMP };
                if ui.add(egui::Label::new(RichText::new(format!("{cat} {n}")).small().color(col)).sense(Sense::click())).clicked()
                    && !self.disc_cats.remove(&cat)
                {
                    self.disc_cats.insert(cat);
                }
                ui.add_space(4.0);
            }
            if !self.disc_cats.is_empty() && ui.add(egui::Label::new(RichText::new("✕ clear").small().color(Palette::MUTED)).sense(Sense::click())).clicked() {
                self.disc_cats.clear();
            }
        });
        ui.separator();

        // build filtered index list
        let needle = self.disc_filter.to_lowercase();
        let visible: Vec<usize> = g.discovery.iter().enumerate().filter(|(_, f)| {
            if self.disc_hide_noise && insight_core::game::is_noise(f) {
                return false;
            }
            if !self.disc_cats.is_empty() && !self.disc_cats.contains(&f.category) {
                return false;
            }
            if !needle.is_empty()
                && !f.text.to_lowercase().contains(&needle)
                && !f.matched.to_lowercase().contains(&needle)
                && !f.source.to_lowercase().contains(&needle)
            {
                return false;
            }
            true
        }).map(|(i, _)| i).collect();

        ui.label(RichText::new(format!("{} shown", visible.len())).small().color(Palette::MUTED));

        let row_h = ui.text_style_height(&TextStyle::Body) + 8.0;
        let mut clicked: Option<usize> = None;
        // leave room at the bottom for the selected-finding detail/actions panel
        let reserve = if self.disc_selected.is_some() { 156.0 } else { 40.0 };
        let list_h = (ui.available_height() - reserve).max(120.0);
        egui::ScrollArea::vertical().max_height(list_h).auto_shrink([false, false]).show_rows(ui, row_h, visible.len(), |ui, range| {
            for vi in range {
                let i = visible[vi];
                let f = &g.discovery[i];
                let selected = self.disc_selected == Some(i);
                let star = if insight_core::game::looks_actionable(f) { "★ " } else { "  " };
                let row = ui.horizontal(|ui| {
                    ui.add_sized([16.0, 18.0], egui::Label::new(RichText::new(star).color(Palette::MN_JUMP)).selectable(false));
                    ui.add_sized([96.0, 18.0], egui::Label::new(RichText::new(&f.category).strong().color(Palette::MN_RET)).selectable(false).halign(Align::LEFT));
                    ui.add_sized([140.0, 18.0], egui::Label::new(RichText::new(&f.matched).monospace().color(Palette::STR)).selectable(false).halign(Align::LEFT));
                    ui.label(RichText::new(&f.text).color(if selected { Palette::ACCENT } else { Palette::TEXT }).text_style(TextStyle::Body));
                    ui.label(RichText::new(format!("({})", f.source)).small().color(Palette::MUTED));
                });
                let rect = row.response.rect;
                if selected {
                    let mut bar = rect;
                    bar.set_width(3.0);
                    ui.painter().rect_filled(bar, 0.0, Palette::ACCENT);
                }
                if ui.interact(rect, ui.id().with(("discrow", i)), Sense::click()).clicked() {
                    clicked = Some(i);
                }
            }
        });
        if let Some(i) = clicked {
            self.disc_selected = Some(i);
        }

        // detail / actions for the selected finding
        if let Some(i) = self.disc_selected {
            if let Some(f) = g.discovery.get(i).cloned() {
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Copy").clicked() {
                        ui.ctx().copy_text(f.text.clone());
                        self.disc_note = "copied".into();
                    }
                    ui.label(RichText::new(&f.text).monospace().color(Palette::STR));
                });

                if insight_core::game::looks_actionable(&f) {
                    let eng = g.best().map(|d| d.engine_id.clone()).unwrap_or_default();
                    let plan = insight_core::launch::plan(&eng, self.game_exe.clone(), &f.text);

                    // (re)initialise the editable args when the selection changes
                    if self.launch_for != Some(i) {
                        self.launch_args = plan.args.join(" ");
                        self.launch_for = Some(i);
                        self.launch_note.clear();
                    }

                    ui.add_space(2.0);
                    ui.label(RichText::new(&plan.note).small().color(Palette::MUTED));

                    // console command
                    ui.horizontal(|ui| {
                        if ui.button("Copy console cmd").clicked() {
                            ui.ctx().copy_text(plan.console_cmd.clone());
                            self.launch_note = "console command copied".into();
                        }
                        ui.label(RichText::new(&plan.console_cmd).monospace().color(Palette::MN_JUMP));
                    });

                    // launch row
                    ui.horizontal(|ui| {
                        let exe_label = self.game_exe.as_ref()
                            .and_then(|p| p.file_name())
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "no game .exe found".into());
                        ui.label(RichText::new(format!("Game: {exe_label}")).small().color(Palette::TEXT));
                        #[cfg(any(windows, target_os = "macos"))]
                        if ui.button("Pick .exe…").clicked() {
                            if let Some(p) = rfd::FileDialog::new().add_filter("exe", &["exe"]).pick_file() {
                                self.game_exe = Some(p);
                            }
                        }
                    });
                    if plan.can_launch {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("args:").small().color(Palette::MUTED));
                            ui.add(egui::TextEdit::singleline(&mut self.launch_args).desired_width(300.0).font(TextStyle::Monospace));
                            let ready = self.game_exe.is_some();
                            if ui.add_enabled(ready, egui::Button::new("▶ Launch game")).clicked() {
                                if let Some(exe) = self.game_exe.clone() {
                                    let args: Vec<String> = self.launch_args.split_whitespace().map(|s| s.to_string()).collect();
                                    self.launch_note = match insight_core::launch::launch(&exe, &args) {
                                        Ok(_) => "launched".into(),
                                        Err(e) => e,
                                    };
                                }
                            }
                        });
                    }
                    if !self.launch_note.is_empty() {
                        ui.label(RichText::new(&self.launch_note).small().color(Palette::ACCENT));
                    }
                }
            }
        }
    }
}

fn export_findings(findings: &[insight_core::game::Finding]) -> String {
    let mut csv = String::from("category,matched,source,text\n");
    let esc = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
    for f in findings {
        csv.push_str(&format!("{},{},{},{}\n", f.category, esc(&f.matched), esc(&f.source), esc(&f.text)));
    }
    #[cfg(any(windows, target_os = "macos"))]
    {
        return match rfd::FileDialog::new().set_file_name("insight_discoveries.csv").save_file() {
            Some(path) => match std::fs::write(&path, csv) {
                Ok(_) => format!("saved {}", path.display()),
                Err(e) => format!("save failed: {e}"),
            },
            None => "export cancelled".into(),
        };
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let path = std::env::current_dir().unwrap_or_default().join("insight_discoveries.csv");
        match std::fs::write(&path, csv) {
            Ok(_) => format!("saved {}", path.display()),
            Err(e) => format!("save failed: {e}"),
        }
    }
}

fn kv(ui: &mut egui::Ui, key: &str, val: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{key}: ")).strong().color(Palette::MUTED));
        ui.label(RichText::new(val).color(Palette::TEXT));
    });
}

fn pseudo_view(ui: &mut egui::Ui, func: &insight_core::Function, prog: &insight_core::Program) {
    ui.add_space(2.0);
    ui.label(RichText::new(format!("{}   ({:#x})", func.name, func.addr)).strong());
    ui.add_space(4.0);
    let lines = insight_core::decompile_lines(func, prog);
    let row_h = ui.text_style_height(&TextStyle::Monospace) + 3.0;
    egui::ScrollArea::both().auto_shrink([false, false]).show_rows(ui, row_h, lines.len(), |ui, range| {
        for i in range {
            highlight_line(ui, &lines[i]);
        }
    });
}

const KEYWORDS: &[&str] = &[
    "void", "return", "goto", "if", "else", "while", "for", "push", "pop", "__asm",
];

fn highlight_line(ui: &mut egui::Ui, line: &str) {
    // comments
    if let Some(pos) = line.find("//") {
        let (head, tail) = line.split_at(pos);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            emit_tokens(ui, head);
            ui.label(RichText::new(tail).monospace().color(Palette::MUTED).italics());
        });
        return;
    }
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        emit_tokens(ui, line);
    });
}

fn emit_tokens(ui: &mut egui::Ui, text: &str) {
    let mut word = String::new();
    let flush = |ui: &mut egui::Ui, word: &mut String| {
        if word.is_empty() {
            return;
        }
        let color = if KEYWORDS.contains(&word.as_str()) {
            Palette::MN_RET
        } else if word.starts_with("loc_") || word.starts_with("sub_") {
            Palette::ACCENT
        } else if word.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            Palette::NUM
        } else {
            Palette::TEXT
        };
        ui.label(RichText::new(word.clone()).monospace().color(color));
        word.clear();
    };
    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            word.push(ch);
        } else {
            flush(ui, &mut word);
            ui.label(RichText::new(ch.to_string()).monospace().color(Palette::MUTED));
        }
    }
    flush(ui, &mut word);
}

fn hex_view(ui: &mut egui::Ui, func: &insight_core::Function) {
    let mut bytes = Vec::new();
    let mut base = func.addr;
    if let Some(first) = func.insns.first() {
        base = first.addr;
    }
    for insn in &func.insns {
        bytes.extend_from_slice(&insn.bytes);
    }
    let row_h = ui.text_style_height(&TextStyle::Monospace) + 4.0;
    let rows = bytes.len().div_ceil(16);
    egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, row_h, rows, |ui, range| {
        for row in range {
            let off = row * 16;
            let chunk = &bytes[off..(off + 16).min(bytes.len())];
            let hex: String = chunk.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
            let ascii: String = chunk.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect();
            ui.horizontal(|ui| {
                mono(ui, &format!("{:016x}", base + off as u64), Palette::ADDR);
                ui.add_space(8.0);
                mono_fixed(ui, &hex, Palette::TEXT, 360.0);
                ui.add_space(8.0);
                mono(ui, &ascii, Palette::STR);
            });
        }
    });
}

// a selectable function row widget
struct FuncRow<'a> {
    name: &'a str,
    addr: u64,
    size: u64,
    selected: bool,
}

impl egui::Widget for FuncRow<'_> {
    fn ui(self, ui: &mut egui::Ui) -> egui::Response {
        let desired = egui::vec2(ui.available_width(), 34.0);
        let (rect, resp) = ui.allocate_exact_size(desired, Sense::click());
        let bg = if self.selected {
            Palette::SELECTION
        } else if resp.hovered() {
            Palette::PANEL2
        } else {
            Color32::TRANSPARENT
        };
        ui.painter().rect_filled(rect, 5.0, bg);
        if self.selected {
            let mut bar = rect;
            bar.set_width(3.0);
            ui.painter().rect_filled(bar, 0.0, Palette::ACCENT);
        }
        let p = rect.min + egui::vec2(10.0, 5.0);
        ui.painter().text(p, egui::Align2::LEFT_TOP, self.name, TextStyle::Body.resolve(ui.style()), Palette::TEXT);
        ui.painter().text(
            p + egui::vec2(0.0, 16.0),
            egui::Align2::LEFT_TOP,
            format!("{:#x} · {} B", self.addr, self.size),
            TextStyle::Small.resolve(ui.style()),
            Palette::MUTED,
        );
        resp
    }
}
