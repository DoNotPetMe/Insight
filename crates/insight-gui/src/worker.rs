//! Background workers.
//!
//! Loading/analysis and live memory scans both run on dedicated threads and
//! report back over channels, so the UI thread never blocks — no freezing,
//! even on a large game executable or a wide memory scan.

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::thread;

use insight_core::game::{analyze_game, GameReport};
use insight_core::live::LiveSession;
use insight_core::Project;

pub struct Loaded {
    pub project: Option<Project>,
    pub game: GameReport,
}

pub enum Msg {
    Progress(f32, String),
    Done(Box<Loaded>, PathBuf),
    Error(String),
}

/// Load + analyse a path (a binary file, or a game folder).
pub fn spawn_load(path: PathBuf, repaint: egui::Context) -> Receiver<Msg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        if path.is_dir() {
            let _ = tx.send(Msg::Progress(0.3, "detecting engine".into()));
            repaint.request_repaint();
            let game = analyze_game(&path, &[]);
            let _ = tx.send(Msg::Done(Box::new(Loaded { project: None, game }), path));
        } else {
            match std::fs::read(&path) {
                Ok(data) => {
                    let tx2 = tx.clone();
                    let ctx = repaint.clone();
                    let project = Project::analyze(&data, move |frac, status| {
                        let _ = tx2.send(Msg::Progress(frac * 0.9, status.to_string()));
                        ctx.request_repaint();
                    });
                    let _ = tx.send(Msg::Progress(0.92, "detecting engine".into()));
                    repaint.request_repaint();
                    let strings: Vec<String> =
                        project.strings.iter().map(|s| s.value.clone()).collect();
                    let game = analyze_game(&path, &strings);
                    let _ = tx.send(Msg::Done(
                        Box::new(Loaded { project: Some(project), game }),
                        path,
                    ));
                }
                Err(e) => {
                    let _ = tx.send(Msg::Error(format!("could not read file: {e}")));
                }
            }
        }
        repaint.request_repaint();
    });
    rx
}

pub enum ScanMsg {
    Done(Vec<u64>),
    Error(String),
}

/// Run a live memory scan on its own thread (the session, which may hold a
/// non-Send OS handle, is created and used entirely within that thread).
pub fn spawn_scan(pid: u32, needle: Vec<u8>, repaint: egui::Context) -> Receiver<ScanMsg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        match LiveSession::open(pid, true) {
            Ok(session) => {
                let hits = session.scan_bytes(&needle, 1000);
                let _ = tx.send(ScanMsg::Done(hits));
            }
            Err(e) => {
                let _ = tx.send(ScanMsg::Error(e));
            }
        }
        repaint.request_repaint();
    });
    rx
}
