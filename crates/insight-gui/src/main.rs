//! Insight — a professional binary analysis & decompilation desktop app.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod theme;
mod worker;

use app::App;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1320.0, 840.0])
            .with_min_inner_size([900.0, 560.0])
            .with_title("Insight"),
        ..Default::default()
    };
    eframe::run_native("Insight", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
