//! Background analysis worker.
//!
//! Loading and analysing a binary can take a while on a large game executable,
//! so it runs on a dedicated thread and streams progress back over a channel.
//! The UI thread only ever polls (never blocks), so the window stays smooth and
//! responsive — no freezing.

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::thread;

use insight_core::Project;

pub enum Msg {
    Progress(f32, String),
    Done(Box<Project>, PathBuf),
    Error(String),
}

/// Kick off loading `path` on a worker thread; returns the receiver to poll.
pub fn spawn_load(path: PathBuf, repaint: egui::Context) -> Receiver<Msg> {
    let (tx, rx) = channel();
    thread::spawn(move || {
        match std::fs::read(&path) {
            Ok(data) => {
                let tx2 = tx.clone();
                let ctx = repaint.clone();
                let proj = Project::analyze(&data, move |frac, status| {
                    let _ = tx2.send(Msg::Progress(frac, status.to_string()));
                    ctx.request_repaint();
                });
                let _ = tx.send(Msg::Done(Box::new(proj), path));
            }
            Err(e) => {
                let _ = tx.send(Msg::Error(format!("could not read file: {e}")));
            }
        }
        repaint.request_repaint();
    });
    rx
}
