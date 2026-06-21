//! A restrained, professional dark theme tuned for dense disassembly listings.

use egui::{Color32, FontFamily, FontId, Rounding, Stroke, TextStyle};

pub struct Palette;
impl Palette {
    pub const BG: Color32 = Color32::from_rgb(0x16, 0x18, 0x1d);
    pub const PANEL: Color32 = Color32::from_rgb(0x1c, 0x1f, 0x26);
    pub const PANEL2: Color32 = Color32::from_rgb(0x23, 0x27, 0x30);
    pub const BORDER: Color32 = Color32::from_rgb(0x2c, 0x31, 0x3c);
    pub const TEXT: Color32 = Color32::from_rgb(0xc7, 0xcd, 0xd6);
    pub const MUTED: Color32 = Color32::from_rgb(0x71, 0x7b, 0x8a);
    pub const ACCENT: Color32 = Color32::from_rgb(0x4a, 0xa3, 0xff);
    pub const SELECTION: Color32 = Color32::from_rgb(0x1f, 0x3a, 0x5c);

    // listing token colours
    pub const ADDR: Color32 = Color32::from_rgb(0x6c, 0x75, 0x84);
    pub const BYTES: Color32 = Color32::from_rgb(0x55, 0x5d, 0x6b);
    pub const MN: Color32 = Color32::from_rgb(0x7e, 0xc6, 0xd6);
    pub const MN_CALL: Color32 = Color32::from_rgb(0xc8, 0xa6, 0xff);
    pub const MN_JUMP: Color32 = Color32::from_rgb(0xe6, 0xa3, 0x6b);
    pub const MN_RET: Color32 = Color32::from_rgb(0xf0, 0x84, 0x7c);
    pub const STR: Color32 = Color32::from_rgb(0x9d, 0xd6, 0x8a);
    pub const NUM: Color32 = Color32::from_rgb(0x6f, 0xb8, 0xff);
}

pub fn apply(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();

    style.text_styles = [
        (TextStyle::Heading, FontId::new(17.0, FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(13.5, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(13.5, FontFamily::Proportional)),
        (TextStyle::Small, FontId::new(11.5, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
    ]
    .into();

    let v = &mut style.visuals;
    v.dark_mode = true;
    v.override_text_color = Some(Palette::TEXT);
    v.panel_fill = Palette::PANEL;
    v.window_fill = Palette::BG;
    v.extreme_bg_color = Palette::BG;
    v.faint_bg_color = Palette::PANEL2;
    v.selection.bg_fill = Palette::SELECTION;
    v.selection.stroke = Stroke::new(1.0, Palette::ACCENT);
    v.hyperlink_color = Palette::ACCENT;

    let r = Rounding::same(5.0);
    v.widgets.noninteractive.bg_fill = Palette::PANEL;
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, Palette::TEXT);
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, Palette::BORDER);
    v.widgets.inactive.rounding = r;
    v.widgets.inactive.bg_fill = Palette::PANEL2;
    v.widgets.inactive.weak_bg_fill = Palette::PANEL2;
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, Palette::TEXT);
    v.widgets.hovered.rounding = r;
    v.widgets.hovered.bg_fill = Palette::BORDER;
    v.widgets.hovered.weak_bg_fill = Palette::BORDER;
    v.widgets.active.rounding = r;
    v.widgets.active.bg_fill = Palette::ACCENT;
    v.widgets.active.weak_bg_fill = Palette::SELECTION;
    v.window_rounding = r;
    v.window_stroke = Stroke::new(1.0, Palette::BORDER);

    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 5.0);

    ctx.set_style(style);
}

pub fn mn_color(flow: insight_core::Flow) -> Color32 {
    use insight_core::Flow::*;
    match flow {
        Call => Palette::MN_CALL,
        Jump | CondJump => Palette::MN_JUMP,
        Return => Palette::MN_RET,
        _ => Palette::MN,
    }
}
