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
        self.rx = Some(spawn_load(path, ctx.clone()));
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

        // move the project out so panels can mutate `self` freely (no borrow clash)
        let project = self.project.take();

        self.top_bar(ctx);
        self.status_bar(ctx, project.as_ref());
        self.left_panel(ctx, project.as_ref());
        self.central_panel(ctx, project.as_ref());

        self.project = project;

        if self.loading {
            ctx.request_repaint();
        }
    }
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
                    if ui.button("Open…").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.begin_load(path, ctx);
                        }
                    }
                    let go = ui.add(egui::TextEdit::singleline(&mut self.path_input)
                        .hint_text("path to a binary…  (or drop a file)")
                        .desired_width(320.0))
                        .lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter));
                    if (ui.button("Load").clicked() || go) && !self.path_input.trim().is_empty() {
                        self.begin_load(PathBuf::from(self.path_input.trim().to_string()), ctx);
                    }
                    ui.separator();
                    if !self.file_name.is_empty() {
                        ui.label(RichText::new(&self.file_name).color(Palette::TEXT));
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.add_space(4.0);
                        ui.label(RichText::new("binary analysis & decompilation").small().color(Palette::MUTED));
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

    fn central_panel(&mut self, ctx: &egui::Context, project: Option<&Project>) {
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
                CenterTab::Game => return game_view(ui, self.game.as_ref()),
                CenterTab::Discovery => return discovery_view(ui, self.game.as_ref()),
                CenterTab::Live => return self.live_view(ui, ctx),
                _ => {}
            }

            let Some(p) = project else {
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new("Drop a game .exe / ELF / folder here, or use Open…").size(15.0).color(Palette::MUTED));
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

fn discovery_view(ui: &mut egui::Ui, game: Option<&GameReport>) {
    let Some(g) = game else {
        ui.centered_and_justified(|ui| {
            ui.label(RichText::new("Load a game to scan for dev rooms, test maps & unused content").color(Palette::MUTED));
        });
        return;
    };
    ui.add_space(6.0);
    if g.discovery.is_empty() {
        ui.label(RichText::new("No notable content discovered.").color(Palette::MUTED));
        return;
    }
    ui.horizontal_wrapped(|ui| {
        for (cat, n) in g.discovery_summary() {
            ui.label(RichText::new(format!("{cat}: {n}")).small().color(Palette::MN_JUMP));
            ui.add_space(6.0);
        }
    });
    ui.add_space(6.0);
    let findings = &g.discovery;
    let row_h = ui.text_style_height(&TextStyle::Body) + 8.0;
    egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, row_h, findings.len(), |ui, range| {
        for i in range {
            let f = &findings[i];
            ui.horizontal(|ui| {
                ui.add_sized([110.0, 18.0], egui::Label::new(RichText::new(&f.category).strong().color(Palette::MN_RET)).halign(Align::LEFT));
                ui.add_sized([150.0, 18.0], egui::Label::new(RichText::new(&f.matched).monospace().color(Palette::STR)).halign(Align::LEFT));
                ui.label(RichText::new(&f.text).color(Palette::TEXT));
                ui.label(RichText::new(format!("({})", f.source)).small().color(Palette::MUTED));
            });
        }
    });
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
