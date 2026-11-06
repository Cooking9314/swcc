//! Палитра и типовые блоки интерфейса. Всё рисуем сами, без системных виджетов:
//! цель - единый современный вид на любой машине.
use eframe::egui;
use egui::{Color32, CornerRadius, Margin, RichText, Shadow, Stroke, Vec2};

pub const BG: Color32 = Color32::from_rgb(9, 11, 20);
pub const PANEL: Color32 = Color32::from_rgb(15, 18, 31);
pub const CARD: Color32 = Color32::from_rgb(21, 25, 42);
pub const CARD_SOFT: Color32 = Color32::from_rgb(17, 21, 36);
pub const EDGE: Color32 = Color32::from_rgb(41, 47, 73);
pub const ACCENT: Color32 = Color32::from_rgb(86, 211, 199);
pub const ACCENT_DEEP: Color32 = Color32::from_rgb(37, 99, 132);
pub const VIOLET: Color32 = Color32::from_rgb(129, 118, 245);
pub const TEXT: Color32 = Color32::from_rgb(226, 232, 248);
pub const MUTED: Color32 = Color32::from_rgb(140, 150, 178);
pub const OK: Color32 = Color32::from_rgb(96, 205, 132);
pub const WARN: Color32 = Color32::from_rgb(236, 176, 86);
pub const DANGER: Color32 = Color32::from_rgb(235, 96, 104);

/// Полужирное начертание Inter. В egui `.strong()` меняет только цвет: вес
/// текста берётся из шрифта, поэтому для заголовков нужно отдельное семейство.
pub fn semibold() -> egui::FontFamily {
    egui::FontFamily::Name("Inter SemiBold".into())
}

pub fn heading(text: impl Into<String>, size: f32, color: Color32) -> RichText {
    RichText::new(text.into()).size(size).color(color).family(semibold())
}

/// Единый тёмный стиль: скругления, мягкие тени, воздух между блоками.
pub fn apply(ctx: &egui::Context) {
    let mut style = egui::Style::default();

    let mut v = egui::Visuals::dark();
    v.panel_fill = PANEL;
    v.extreme_bg_color = BG;
    v.window_fill = CARD;
    v.faint_bg_color = CARD_SOFT;
    v.code_bg_color = CARD_SOFT;
    v.hyperlink_color = ACCENT;
    v.warn_fg_color = WARN;
    v.error_fg_color = DANGER;
    v.override_text_color = Some(TEXT);
    v.weak_text_color = Some(MUTED);
    v.window_corner_radius = CornerRadius::same(16);
    v.menu_corner_radius = CornerRadius::same(12);
    v.window_stroke = Stroke::new(1.0, EDGE);
    v.window_shadow = Shadow {
        offset: [0, 10],
        blur: 24,
        spread: 0,
        color: Color32::from_black_alpha(140),
    };
    v.popup_shadow = v.window_shadow;
    v.widgets.noninteractive.bg_fill = CARD;
    v.widgets.noninteractive.weak_bg_fill = CARD;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, EDGE);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.noninteractive.corner_radius = CornerRadius::same(10);
    v.widgets.inactive.bg_fill = CARD_SOFT;
    v.widgets.inactive.weak_bg_fill = CARD_SOFT;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, EDGE);
    v.widgets.inactive.corner_radius = CornerRadius::same(10);
    v.widgets.hovered.bg_fill = Color32::from_rgb(30, 36, 60);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(30, 36, 60);
    v.widgets.hovered.bg_stroke = Stroke::new(1.4, ACCENT);
    v.widgets.hovered.corner_radius = CornerRadius::same(11);
    v.widgets.active.bg_fill = ACCENT_DEEP;
    v.widgets.active.weak_bg_fill = ACCENT_DEEP;
    v.widgets.active.bg_stroke = Stroke::new(1.4, ACCENT);
    v.widgets.active.corner_radius = CornerRadius::same(11);
    v.widgets.open.bg_stroke = Stroke::new(1.4, ACCENT);
    v.selection.bg_fill = ACCENT_DEEP.linear_multiply(0.5);
    v.selection.stroke = Stroke::new(1.5, ACCENT);
    v.striped = false;
    v.slider_trailing_fill = true;
    v.button_frame = true;
    v.collapsing_header_frame = true;
    v.indent_has_left_vline = false;
    v.disabled_alpha = 0.38;
    style.visuals = v;

    style.spacing.item_spacing = Vec2::new(10.0, 8.0);
    style.spacing.button_padding = Vec2::new(14.0, 7.0);
    style.spacing.window_margin = Margin::same(0);
    style.spacing.indent = 18.0;
    style.spacing.interact_size = Vec2::new(24.0, 24.0);

    style
        .text_styles
        .insert(egui::TextStyle::Heading, egui::FontId::new(21.0, semibold()));
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(14.5));
    style
        .text_styles
        .insert(egui::TextStyle::Button, egui::FontId::new(15.0, semibold()));
    style.text_styles.insert(
        egui::TextStyle::Small,
        egui::FontId::proportional(12.0),
    );
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, egui::FontId::monospace(12.5));
    style.spacing.icon_spacing = 8.0;
    ctx.set_global_style(style);
}

/// Карточка-контейнер с фоном, рамкой и тенью.
pub fn card<R>(ui: &mut egui::Ui, fill: Color32, content: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0, EDGE))
        .corner_radius(CornerRadius::same(16))
        .inner_margin(Margin::same(18))
        .shadow(Shadow {
            offset: [0, 4],
            blur: 14,
            spread: 0,
            color: Color32::from_black_alpha(90),
        })
        .show(ui, content)
        .inner
}

/// Плоская подложка без тени - для вложенных блоков.
pub fn slab<R>(ui: &mut egui::Ui, fill: Color32, content: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0, EDGE.linear_multiply(0.7)))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(12))
        .show(ui, content)
        .inner
}

/// Компактная метка-чип.
pub fn chip(ui: &mut egui::Ui, text: impl Into<String>, color: Color32) {
    let text = text.into();
    slab(ui, color.linear_multiply(0.16), |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("●").color(color).size(11.0));
            ui.label(RichText::new(text).color(color).size(12.5).strong());
        });
    });
}

pub fn primary(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    let text = RichText::new(label).strong().size(15.0);
    let button = egui::Button::new(text)
        .fill(if enabled { ACCENT } else { CARD_SOFT })
        .stroke(Stroke::new(1.0, if enabled { ACCENT } else { EDGE }))
        .corner_radius(CornerRadius::same(12))
        .min_size(Vec2::new(0.0, 38.0));
    ui.add_enabled(enabled, button)
}

pub fn accent_secondary(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    let text = RichText::new(label).strong().size(15.0);
    let button = egui::Button::new(text)
        .fill(if enabled { VIOLET } else { CARD_SOFT })
        .stroke(Stroke::new(1.0, if enabled { VIOLET } else { EDGE }))
        .corner_radius(CornerRadius::same(12))
        .min_size(Vec2::new(0.0, 38.0));
    ui.add_enabled(enabled, button)
}

pub fn ghost(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(label).size(14.0))
            .fill(CARD_SOFT)
            .stroke(Stroke::new(1.0, EDGE))
            .corner_radius(CornerRadius::same(11))
            .min_size(Vec2::new(0.0, 32.0)),
    )
}

pub fn danger_ghost(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(label).size(14.0).color(DANGER))
            .fill(CARD_SOFT)
            .stroke(Stroke::new(1.0, DANGER.linear_multiply(0.6)))
            .corner_radius(CornerRadius::same(11))
            .min_size(Vec2::new(0.0, 32.0)),
    )
}

/// Компактная метка-разделитель секций в панелях.
pub fn eyebrow(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(text.to_uppercase())
            .size(11.5)
            .color(MUTED)
            .strong(),
    );
}

pub fn lead(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(15.0).color(TEXT));
}
