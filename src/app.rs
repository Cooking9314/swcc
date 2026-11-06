use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use egui::{Align, Color32, CornerRadius, Frame, Layout, Margin, RichText, Stroke, Vec2};

use crate::agreement::{self, AgreementRecord, ACCEPT_STATEMENT, WARNING};
use crate::icon_data;
use crate::paths::{self, GameRoot};
use crate::scanner::{ScanEvent, ScanOptions, ScanResult, Scanner, Verdict};
use crate::signatures::{Severity, SignatureDb};
use crate::style;
use crate::swcc::Report;

#[derive(PartialEq, Clone, Copy)]
enum Screen {
    Agreement,
    Refused,
    Working,
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Result,
    Method,
}

pub struct App {
    screen: Screen,
    tab: Tab,
    body_text: String,
    checked: bool,
    agreement: Option<AgreementRecord>,
    logo: egui::TextureHandle,

    roots: Vec<GameRoot>,
    drive_roots: Vec<GameRoot>,
    picked: HashSet<usize>,
    deep_archives: bool,
    whole_pc: bool,

    db: Arc<SignatureDb>,
    db_dir: PathBuf,

    scanning: bool,
    rx: Option<Receiver<ScanEvent>>,
    cancel: Option<Arc<AtomicBool>>,
    progress_current: u64,
    progress_note: String,
    progress_phase: &'static str,

    report: Option<Report>,
    status: String,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        style::apply(&cc.egui_ctx);
        setup_fonts(&cc.egui_ctx);
        let logo = cc.egui_ctx.load_texture(
            "swcc-logo",
            egui::ColorImage::from_rgba_unmultiplied(
                [icon_data::ICON_SIZE as usize, icon_data::ICON_SIZE as usize],
                &icon_data::rgba(),
            ),
            egui::TextureOptions::LINEAR,
        );
        let db_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("signatures")))
            .unwrap_or_else(|| PathBuf::from("signatures"));
        let db = Arc::new(SignatureDb::load(db_dir.exists().then_some(db_dir.as_path())));
        let roots = paths::discover_roots();
        let picked = (0..roots.len()).collect::<HashSet<usize>>();
        let drive_roots = paths::computer_roots();
        let status = if roots.is_empty() {
            "Папки Minecraft не найдены - добавь вручную после принятия соглашения.".to_string()
        } else {
            format!(
                "Найдено папок игры: {}, дисков: {}.",
                roots.len(),
                drive_roots.len()
            )
        };
        App {
            screen: Screen::Agreement,
            tab: Tab::Result,
            body_text: agreement::body(),
            checked: false,
            agreement: None,
            logo,
            db_dir,
            roots,
            drive_roots,
            picked,
            deep_archives: true,
            whole_pc: false,
            status,
            scanning: false,
            rx: None,
            cancel: None,
            progress_current: 0,
            progress_note: String::new(),
            progress_phase: "",
            report: None,
            db,
        }
    }

    // -- сканирование -------------------------------------------------------

    fn selected_roots(&self) -> Vec<GameRoot> {
        let mut out: Vec<GameRoot> = self
            .roots
            .iter()
            .enumerate()
            .filter(|(i, _)| self.picked.contains(i))
            .map(|(_, r)| r.clone())
            .collect();
        if self.whole_pc {
            out.extend(self.drive_roots.iter().cloned());
        }
        out
    }

    fn walk_limit(&self) -> u64 {
        let base = self.db.params.max_walk_files;
        if self.whole_pc { base * 8 } else { base }
    }

    fn start_scan(&mut self) {
        if self.scanning {
            return;
        }
        let Some(agreement) = self.agreement.clone() else {
            self.screen = Screen::Agreement;
            return;
        };
        let roots = self.selected_roots();
        if roots.is_empty() {
            self.status = "Не выбрано ни одной папки игры: проверять нечего.".into();
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let db = Arc::clone(&self.db);
        let opts = ScanOptions {
            roots,
            deep_archives: self.deep_archives,
            whole_pc: self.whole_pc,
            ..Default::default()
        };
        let thread_cancel = Arc::clone(&cancel);
        std::thread::spawn(move || {
            let mut scanner = Scanner::new(db.as_ref(), &opts);
            scanner.run(&tx, thread_cancel.as_ref());
        });

        self.rx = Some(rx);
        self.cancel = Some(cancel);
        self.scanning = true;
        self.report = None;
        self.tab = Tab::Result;
        self.progress_current = 0;
        self.progress_note.clear();
        let tail = if self.whole_pc {
            " Диски обходятся по метаданным - это дольше."
        } else {
            ""
        };
        self.status = format!(
            "Проверка запущена (согласие от {}).{tail}",
            agreement.accepted_at
        );
    }

    fn stop_scan(&mut self) {
        if let Some(c) = &self.cancel {
            c.store(true, Ordering::Relaxed);
        }
        self.status = "Прерывание запрошено: ждём остановку обхода…".into();
    }

    fn poll(&mut self) {
        let Some(rx) = self.rx.take() else { return };
        let mut events = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }
        self.rx = Some(rx);
        for ev in events {
            match ev {
                ScanEvent::Progress {
                    phase,
                    current,
                    note,
                } => {
                    self.progress_phase = phase;
                    self.progress_current = current;
                    self.progress_note = note;
                }
                ScanEvent::Finished(result) => {
                    let result: ScanResult = *result;
                    let roots = self.selected_roots();
                    let agreement = self
                        .agreement
                        .clone()
                        .unwrap_or_else(AgreementRecord::sample);
                    let report = Report::build(result, roots, agreement, self.deep_archives);
                    self.status = format!(
                        "Готово за {} мс: {} (балл {}). Отчёт ещё не создан - скачай сам.",
                        report.result.stats.duration_ms,
                        report.result.verdict.ru(),
                        report.result.score
                    );
                    self.report = Some(report);
                    self.scanning = false;
                    self.rx = None;
                    self.cancel = None;
                }
            }
        }
    }

    // -- отчёт: в окне его только скачивают ----------------------------------

    /// Содержимое отчёта в окне не показывается: файл игрок скачивает и
    /// передаёт админу, а разбирает его админ.
    fn save_report(&mut self) {
        let Some(report) = self.report.clone() else {
            self.status = "Сначала выполни проверку.".into();
            return;
        };
        let default_name = format!("{}.swcc", report.id);
        let mut dialog = rfd::FileDialog::new()
            .add_filter("Sunrise Worlds report", &["swcc"])
            .set_file_name(&default_name);
        if let Some(dir) = dirs_downloads() {
            dialog = dialog.set_directory(dir);
        }
        let Some(path) = dialog.save_file() else {
            self.status = "Сохранение отменено - файл не создан.".into();
            return;
        };
        match report.write(&path) {
            Ok(bytes) => {
                self.status = format!(
                    "Отчёт сохранён: {} ({} КБ). Перешли этот файл админу сам.",
                    path.display(),
                    bytes / 1024
                );
            }
            Err(err) => self.status = format!("Не удалось сохранить отчёт: {err}"),
        }
    }

    fn add_root_by_hand(&mut self) {
        let Some(path) = rfd::FileDialog::new().pick_folder() else {
            return;
        };
        match paths::accept_manual_root(&path) {
            Ok(root) => {
                let index = self.roots.len();
                self.roots.push(root);
                self.picked.insert(index);
                self.status = format!("Добавлена папка: {}", path.display());
            }
            Err(reason) => self.status = format!("Папка отклонена: {reason}"),
        }
    }

    fn refresh_roots(&mut self) {
        self.roots = paths::discover_roots();
        self.picked = (0..self.roots.len()).collect();
        self.drive_roots = paths::computer_roots();
        self.status = format!(
            "Найдено папок игры: {}, дисков: {}.",
            self.roots.len(),
            self.drive_roots.len()
        );
    }

    // -- экран соглашения ------------------------------------------------------

    fn view_agreement(&mut self, ui: &mut egui::Ui) {
        let logo = self.logo.clone();
        let body = self.body_text.clone();
        let mut checked = self.checked;
        let mut accept = false;
        let mut refuse = false;

        egui::CentralPanel::default()
            .frame(backdrop())
            .show(ui, |ui| {
                column(ui, 900.0, |ui| {
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        brand(ui, &logo, 56.0);
                        ui.add_space(14.0);
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new("Sunrise Worlds Cheats Checker")
                                    .size(23.0)
                                    .strong()
                                    .color(style::TEXT),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "проверка на признаки читов · локально · без сети · v{}",
                                    crate::scanner::APP_VERSION
                                ))
                                .size(12.5)
                                .color(style::MUTED),
                            );
                        });
                    });
                    ui.add_space(16.0);

                    style::card(ui, style::CARD, |ui| {
                        style::lead(ui, agreement::SUMMARY);
                        ui.add_space(10.0);
                        egui::ScrollArea::vertical()
                            .id_salt("agreement-scroll")
                            .auto_shrink([false, false])
                            .max_height(340.0)
                            .show(ui, |ui| {
                                style::slab(ui, style::BG, |ui| {
                                    ui.add(
                                        egui::TextEdit::multiline(&mut body.as_str())
                                            .interactive(false)
                                            .desired_width(f32::INFINITY)
                                            .font(egui::TextStyle::Monospace),
                                    );
                                });
                            });

                        ui.add_space(12.0);
                        callout(ui, style::WARN, "последствия отказа", WARNING);
                        ui.add_space(10.0);
                        ui.checkbox(&mut checked, ACCEPT_STATEMENT);
                        ui.add_space(12.0);
                        ui.horizontal(|ui| {
                            if style::primary(ui, "Принять и разрешить проверку", checked).clicked()
                            {
                                accept = true;
                            }
                            if style::danger_ghost(ui, "Отказать").clicked() {
                                refuse = true;
                            }
                            if !checked {
                                ui.label(
                                    RichText::new("Кнопки активны после отметки о прочтении.")
                                        .size(12.5)
                                        .color(style::MUTED),
                                );
                            }
                        });
                    });
                    ui.add_space(12.0);
                });
            });

        self.checked = checked;
        if accept && self.agreement.is_none() {
            self.agreement = Some(AgreementRecord::accept());
            self.screen = Screen::Working;
            self.status = "Согласие принято на время этого запуска.".to_string();
        } else if refuse {
            self.screen = Screen::Refused;
        }
    }

    fn view_refused(&mut self, ui: &mut egui::Ui) {
        let logo = self.logo.clone();
        let mut reopen = false;
        let mut quit = false;

        egui::CentralPanel::default()
            .frame(backdrop())
            .show(ui, |ui| {
                column(ui, 720.0, |ui| {
                    ui.add_space(28.0);
                    brand(ui, &logo, 56.0);
                    ui.add_space(16.0);
                    style::card(ui, style::CARD, |ui| {
                        ui.label(
                            RichText::new("Проверка не выполнена")
                                .size(22.0)
                                .strong()
                                .color(style::TEXT),
                        );
                        ui.add_space(8.0);
                        callout(ui, style::DANGER, "что это значит", WARNING);
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new(
                                "На этом экране не сделано ничего: файлы игры не открывались, \
                                 отчёт не создавался, в сеть не выходили - сетевых библиотек в \
                                 программе нет вовсе. Согласие нигде не сохраняется: при \
                                 следующем запуске окно спросит заново.",
                            )
                            .size(13.5)
                            .color(style::MUTED),
                        );
                        ui.add_space(16.0);
                        ui.horizontal(|ui| {
                            if style::primary(ui, "Передумать и прочитать соглашение", true).clicked()
                            {
                                reopen = true;
                            }
                            if style::ghost(ui, "Выйти, не принимая").clicked() {
                                quit = true;
                            }
                        });
                    });
                });
            });

        if reopen {
            self.screen = Screen::Agreement;
        }
        if quit {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    // -- рабочий экран ---------------------------------------------------------

    fn view_main(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("header")
            .exact_size(70.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(panel(
                style::PANEL,
                Margin { left: 18, right: 18, top: 12, bottom: 12 },
            ))
            .show(ui, |ui| self.header_view(ui));

        egui::Panel::bottom("actions")
            .exact_size(64.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(panel(
                style::PANEL,
                Margin { left: 18, right: 18, top: 10, bottom: 12 },
            ))
            .show(ui, |ui| self.action_bar(ui));

        let scanning = self.scanning;
        egui::Panel::bottom("status")
            .exact_size(if scanning { 56.0 } else { 32.0 })
            .resizable(false)
            .show_separator_line(false)
            .frame(panel(
                style::BG,
                Margin { left: 18, right: 18, top: 4, bottom: 8 },
            ))
            .show(ui, |ui| self.status_bar(ui));

        egui::Panel::left("scope")
            .default_size(340.0)
            .min_size(300.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(panel(
                style::PANEL,
                Margin { left: 16, right: 12, top: 16, bottom: 16 },
            ))
            .show(ui, |ui| self.scope_view(ui));

        egui::CentralPanel::default()
            .frame(panel(style::BG, Margin { left: 6, right: 18, top: 16, bottom: 16 }))
            .show(ui, |ui| {
                self.tab_bar(ui);
                egui::ScrollArea::vertical()
                    .id_salt("content")
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.tab {
                        Tab::Result => self.result_view(ui),
                        Tab::Method => self.method_view(ui),
                    });
            });
    }

    fn header_view(&mut self, ui: &mut egui::Ui) {
        let logo = self.logo.clone();
        let db_version = self.db.version.clone();
        let rules = self.db.rule_count();
        let verdict = self.report.as_ref().map(|r| r.result.verdict);
        let scanning = self.scanning;

        ui.horizontal(|ui| {
            brand(ui, &logo, 40.0);
            ui.add_space(10.0);
            ui.vertical(|ui| {
                ui.label(
                    RichText::new("Sunrise Worlds Cheats Checker")
                        .size(17.0)
                        .strong()
                        .color(style::TEXT),
                );
                ui.label(
                    RichText::new(format!(
                        "v{} · база сигнатур {} · правил {} · сеть не используется",
                        crate::scanner::APP_VERSION, db_version, rules
                    ))
                    .size(12.0)
                    .color(style::MUTED),
                );
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if scanning {
                    ui.spinner();
                    ui.label(
                        RichText::new("идёт проверка")
                            .size(13.0)
                            .color(style::MUTED),
                    );
                } else if let Some(verdict) = verdict {
                    let color = verdict_color(verdict);
                    ui.label(
                        RichText::new(verdict.ru().to_uppercase())
                            .size(15.0)
                            .strong()
                            .color(color),
                    );
                    ui.label(RichText::new("●").size(17.0).color(color));
                } else {
                    ui.label(
                        RichText::new("проверка не выполнена")
                            .size(13.0)
                            .color(style::MUTED),
                    );
                }
            });
        });
    }

    fn action_bar(&mut self, ui: &mut egui::Ui) {
        let scanning = self.scanning;
        let can_start = !self.roots.is_empty() || self.whole_pc;
        let ready = self.report.is_some() && !scanning;
        let mut start = false;
        let mut abort = false;
        let mut download = false;

        ui.horizontal(|ui| {
            if scanning {
                if style::danger_ghost(ui, "Прервать проверку").clicked() {
                    abort = true;
                }
            } else if style::primary(ui, "Начать проверку", can_start).clicked() {
                start = true;
            }
            ui.add_space(6.0);
            if style::accent_secondary(ui, "Скачать отчёт .swcc", ready).clicked() {
                download = true;
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new("Файл отчёта передаёшь сам: Discord или лично.")
                        .size(12.0)
                        .color(style::MUTED),
                );
            });
        });

        if start {
            self.start_scan();
        }
        if abort {
            self.stop_scan();
        }
        if download {
            self.save_report();
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        let scanning = self.scanning;
        let limit = self.walk_limit().max(1) as f32;
        let current = self.progress_current;
        let note = self.progress_note.clone();
        let phase = self.progress_phase;
        let text = self.status.clone();

        ui.vertical(|ui| {
            ui.label(RichText::new(text).size(12.5).color(style::MUTED));
            if scanning {
                let ratio = (current as f32 / limit).clamp(0.01, 0.99);
                ui.add(
                    egui::ProgressBar::new(ratio)
                        .animate(true)
                        .fill(style::ACCENT)
                        .text(format!("{phase} · {current} файлов · {note}")),
                );
            }
        });
    }

    fn tab_bar(&mut self, ui: &mut egui::Ui) {
        let tab = self.tab;
        let mut chosen = None;
        ui.horizontal(|ui| {
            for (candidate, label) in [(Tab::Result, "Результат"), (Tab::Method, "Как это работает")]
            {
                let selected = tab == candidate;
                let button = egui::Button::new(
                    RichText::new(label)
                        .size(14.5)
                        .color(if selected { style::TEXT } else { style::MUTED }),
                )
                .fill(if selected { style::CARD } else { style::CARD_SOFT })
                .stroke(Stroke::new(
                    1.0,
                    if selected { style::ACCENT } else { style::EDGE },
                ))
                .corner_radius(CornerRadius::same(12))
                .min_size(Vec2::new(0.0, 34.0));
                if ui.add(button).clicked() {
                    chosen = Some(candidate);
                }
            }
        });
        if let Some(chosen) = chosen {
            self.tab = chosen;
        }
        ui.add_space(12.0);
    }

    fn scope_view(&mut self, ui: &mut egui::Ui) {
        let roots = self.roots.clone();
        let picked = self.picked.clone();
        let drives = self.drive_roots.clone();
        let mut full = self.whole_pc;
        let mut deep = self.deep_archives;
        let mut toggled: Vec<(usize, bool)> = Vec::new();
        let mut refresh = false;
        let mut add = false;

        egui::ScrollArea::vertical()
            .id_salt("scope-scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                style::eyebrow(ui, "папки игры");
                ui.add_space(6.0);
                if roots.is_empty() {
                    ui.label(
                        RichText::new("Автоматически ничего не найдено - добавь папку вручную.")
                            .size(12.5)
                            .color(style::MUTED),
                    );
                }
                for (i, root) in roots.iter().enumerate() {
                    let was_on = picked.contains(&i);
                    let mut on = was_on;
                    style::slab(
                        ui,
                        if on { style::CARD } else { style::CARD_SOFT },
                        |ui| {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut on, "").on_hover_text(&root.path);
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(root.label.clone())
                                            .size(12.5)
                                            .color(if on { style::TEXT } else { style::MUTED }),
                                    );
                                    ui.label(
                                        RichText::new(format!(
                                            "{} · {}",
                                            root.kind.ru(),
                                            shorten_path(&root.path, 30)
                                        ))
                                        .size(11.5)
                                        .color(style::MUTED),
                                    );
                                });
                            });
                        },
                    );
                    if on != was_on {
                        toggled.push((i, on));
                    }
                }

                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if style::ghost(ui, "Обновить").clicked() {
                        refresh = true;
                    }
                    if style::ghost(ui, "Добавить папку…").clicked() {
                        add = true;
                    }
                });

                ui.add_space(18.0);
                style::eyebrow(ui, "объём проверки");
                ui.add_space(6.0);
                style::slab(ui, style::CARD, |ui| {
                    ui.checkbox(&mut full, "Проверить весь компьютер");
                    ui.label(
                        RichText::new(
                            "Диски обходятся по метаданным: имя файла, путь, размер, дата. \
                             Содержимое открывается только там, где имя уже совпало с базой \
                             признаков, а системные папки Windows пропускаются.",
                        )
                        .size(11.5)
                        .color(style::MUTED),
                    );
                    if full {
                        ui.label(
                            RichText::new(format!(
                                "В проверку войдут диски: {}",
                                drives
                                    .iter()
                                    .map(|d| d.path.clone())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ))
                            .size(11.5)
                            .color(style::ACCENT),
                        );
                    }
                });

                ui.add_space(8.0);
                style::slab(ui, style::CARD, |ui| {
                    ui.checkbox(&mut deep, "Глубоко распаковывать архивы");
                    ui.label(
                        RichText::new(
                            "Выключено - быстрее, но переименованный чит можно пропустить.",
                        )
                        .size(11.5)
                        .color(style::MUTED),
                    );
                });

                ui.add_space(18.0);
                style::slab(ui, style::BG, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("✓").size(15.0).color(style::OK));
                        ui.label(
                            RichText::new(
                                "Сети нет. Файл отчёта появляется только после того, как ты сам \
                                 нажмёшь «Скачать отчёт» и выберешь место.",
                            )
                            .size(11.5)
                            .color(style::OK),
                        );
                    });
                });
            });

        for (i, on) in toggled {
            if on {
                self.picked.insert(i);
            } else {
                self.picked.remove(&i);
            }
        }
        if full != self.whole_pc {
            self.whole_pc = full;
            self.status = if full {
                format!(
                    "Проверка всего компьютера: дисков {}. Займёт больше времени.",
                    self.drive_roots.len()
                )
            } else {
                "Проверяются только папки игры.".to_string()
            };
        }
        self.deep_archives = deep;
        if refresh {
            self.refresh_roots();
        }
        if add {
            self.add_root_by_hand();
        }
    }

    fn result_view(&mut self, ui: &mut egui::Ui) {
        let report = self.report.clone();
        let whole_pc = self.whole_pc;
        let disks = self.drive_roots.len();

        let Some(report) = report else {
            style::card(ui, style::CARD, |ui| {
                ui.label(
                    RichText::new("Заключения пока нет")
                        .size(20.0)
                        .strong()
                        .color(style::TEXT),
                );
                ui.add_space(6.0);
                style::lead(
                    ui,
                    "Отметь слева папки игры - и, если нужно, весь компьютер - затем нажми \
                     «Начать проверку». Здесь появится заключение, а файл отчёта нужно будет \
                     скачать и передать админу.",
                );
                ui.add_space(14.0);
                for line in [
                    "Согласие действует только на этот запуск: при следующем окно спросит заново.",
                    "Программа ничего никуда не отправляет - отчёт остаётся у тебя на диске.",
                    "Список найденных файлов, путей и хэшей пишется в файл .swcc, его читает админ.",
                    "Чистый результат не доказывает честность: самописный чит можно не увидеть.",
                ] {
                    ui.label(RichText::new(format!("· {line}")).size(13.5).color(style::MUTED));
                }
            });
            return;
        };

        let result = report.result.clone();
        let color = verdict_color(result.verdict);

        style::card(ui, style::CARD, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("●").size(28.0).color(color));
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(result.verdict.ru())
                            .size(26.0)
                            .strong()
                            .color(color),
                    );
                    let count = if result.findings.is_empty() {
                        "прямых совпадений не найдено".to_string()
                    } else {
                        format!("совпадений с базой: {}", result.findings.len())
                    };
                    ui.label(
                        RichText::new(format!("балл риска {} · {}", result.score, count))
                            .size(13.5)
                            .color(style::TEXT),
                    );
                    ui.label(
                        RichText::new(result.verdict.advice())
                            .size(13.0)
                            .color(style::MUTED),
                    );
                });
            });
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                stat(ui, "файлов просмотрено", &result.stats.files_walked.to_string());
                stat(ui, "находок", &result.findings.len().to_string());
                stat(ui, "отброшено как легитимное", &result.stats.suppressed.to_string());
                stat(ui, "хэшей посчитано", &result.stats.files_hashed.to_string());
            });
            if whole_pc {
                ui.add_space(10.0);
                ui.label(
                    RichText::new(format!(
                        "Режим проверки всего компьютера: дисков {}, системных каталогов \
                         пропущено {}.",
                        disks, result.stats.dirs_pruned_system
                    ))
                    .size(12.5)
                    .color(style::MUTED),
                );
            }
        });

        ui.add_space(12.0);
        style::card(ui, style::CARD_SOFT, |ui| {
            style::eyebrow(ui, "что дальше");
            ui.add_space(6.0);
            style::lead(
                ui,
                "Нажми «Скачать отчёт .swcc» внизу, сохрани файл и перешли его админу. \
                 Подробности находок в окне не показываются - это материал для сверки, \
                 и весь он лежит внутри файла.",
            );
            ui.add_space(12.0);
            severity_chips(ui, &result);
            if !result.warnings.is_empty() {
                ui.add_space(10.0);
                for w in &result.warnings {
                    ui.label(RichText::new(format!("⚠ {w}")).size(12.0).color(style::WARN));
                }
            }
            if result.verdict != Verdict::Clean {
                ui.add_space(12.0);
                callout(
                    ui,
                    style::ACCENT,
                    "помни",
                    "Заключение сканера - повод для ручной проверки, а не автоматический бан. \
                     Решение принимает администрация после сверки файлов.",
                );
            }
        });
    }

    fn method_view(&mut self, ui: &mut egui::Ui) {
        let db = self.db.clone();
        let db_dir = self.db_dir.join("custom.toml");
        let limit = self.walk_limit();
        let whole_pc = self.whole_pc;

        style::card(ui, style::CARD, |ui| {
            ui.label(
                RichText::new("Как ищет проверка")
                    .size(20.0)
                    .strong()
                    .color(style::TEXT),
            );
            ui.add_space(8.0);
            style::lead(
                ui,
                "Сканер сравнивает то, что видит в папках игры, с базой известных признаков \
                 чит-клиентов: имена и пути файлов, содержимое jar-архивов и классы внутри них, \
                 нативные библиотеки, строки запуска лаунчера, хэши файлов.",
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "Каждое совпадение - признак, а не доказательство. Признаки одного семейства \
                     складываются по формуле 1 - (1-c1)(1-c2), а балл ограничен на уровне \
                     семейства: сорок совпадений в одном мусорном каталоге не должны выглядеть \
                     как гарантированный бан.",
                )
                .size(13.5)
                .color(style::MUTED),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Пороги: ≥80 - высокий риск (и не меньше двух признаков, либо уверенность \
                     ≥90%), ≥30 - подозрение, ≥6 - косвенные признаки, иначе чисто.",
                )
                .size(13.5)
                .color(style::MUTED),
            );
        });

        ui.add_space(12.0);
        style::card(ui, style::CARD_SOFT, |ui| {
            style::eyebrow(ui, "база и пределы метода");
            ui.add_space(6.0);
            ui.label(RichText::new(format!("Версия базы: {}", db.version)).size(13.0));
            ui.label(
                RichText::new(format!("Источники: {}", db.sources.join(" + ")))
                    .size(13.0)
                    .color(style::MUTED),
            );
            ui.label(
                RichText::new(format!(
                    "Сигнатур: {} · исключений: {}",
                    db.rule_count(),
                    db.excludes.len()
                ))
                .size(13.0)
                .color(style::MUTED),
            );
            ui.label(
                RichText::new(format!(
                    "Лимиты обхода: {} файлов{}; чтение содержимого до {} МБ, распаковка \
                     архива до {} МБ.",
                    db.params.max_walk_files,
                    if whole_pc {
                        format!(" ({} при проверке всего компьютера)", limit)
                    } else {
                        String::new()
                    },
                    db.params.max_content_bytes / (1024 * 1024),
                    db.params.max_archive_scan_bytes / (1024 * 1024),
                ))
                .size(13.0)
                .color(style::MUTED),
            );
            ui.label(
                RichText::new(format!("Своя база: {}", db_dir.display()))
                    .size(12.0)
                    .color(style::MUTED),
            );
            if !db.warnings.is_empty() {
                ui.add_space(8.0);
                for w in &db.warnings {
                    ui.label(RichText::new(format!("⚠ {w}")).size(12.0).color(style::WARN));
                }
            }

            ui.add_space(14.0);
            style::eyebrow(ui, "приватность");
            ui.add_space(6.0);
            for line in [
                "Никакой сети: в программе нет адреса сервера и она физически не может ничего отправить.",
                "Токены из строк запуска (--accessToken, --xuid, --clientId) вырезаются до записи в отчёт.",
                "Браузер, пароли, переписка, буфер обмена, документы, фото, скриншоты и клавиатура не читаются.",
                "Каталоги assets, libraries, runtime и нативок не обходятся: они огромные и легитимные.",
                "При проверке всего компьютера содержимое файла открывается только после совпадения имени с базой.",
                "Самописный или пересобранный чит можно не увидеть: чистый отчёт - не доказательство честной игры.",
            ] {
                ui.label(RichText::new(format!("· {line}")).size(13.0).color(style::MUTED));
            }
        });
    }
}

// ---------------------------------------------------------------------------
// вспомогательная отрисовка
// ---------------------------------------------------------------------------

fn brand(ui: &mut egui::Ui, logo: &egui::TextureHandle, mark: f32) {
    ui.add(
        egui::Image::from_texture(logo)
            .fit_to_exact_size(Vec2::splat(mark))
            .corner_radius(CornerRadius::same((mark / 5.0) as u8)),
    );
}

fn backdrop() -> Frame {
    Frame::new().fill(style::BG).inner_margin(Margin { left: 24, right: 24, top: 20, bottom: 20 })
}

fn panel(fill: Color32, margin: Margin) -> Frame {
    Frame::new().fill(fill).inner_margin(margin)
}

/// Колонка фиксированной ширины, отцентрированная по горизонтали.
fn column<R>(ui: &mut egui::Ui, max_width: f32, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let avail = ui.available_width();
    let width = avail.min(max_width);
    let pad = (avail - width) * 0.5;
    ui.horizontal(|ui| {
        ui.add_space(pad);
        ui.vertical(|ui| {
            ui.set_width(width);
            add(ui)
        })
        .inner
    })
    .inner
}

fn callout(ui: &mut egui::Ui, color: Color32, title: &str, text: &str) {
    Frame::new()
        .fill(color.linear_multiply(0.12))
        .stroke(Stroke::new(1.0, color.linear_multiply(0.55)))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.label(
                RichText::new(title.to_uppercase())
                    .size(11.5)
                    .strong()
                    .color(color),
            );
            ui.label(RichText::new(text).size(13.0).color(style::TEXT));
        });
}

fn stat(ui: &mut egui::Ui, label: &str, value: &str) {
    style::slab(ui, style::BG, |ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new(label).size(11.0).color(style::MUTED).strong());
            ui.label(RichText::new(value).size(19.0).color(style::TEXT).strong());
        });
    });
}

fn severity_chips(ui: &mut egui::Ui, result: &ScanResult) {
    ui.horizontal(|ui| {
        for sev in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            let count = result.findings.iter().filter(|f| f.severity == sev).count();
            if count == 0 {
                continue;
            }
            style::chip(ui, format!("{} · {}", sev.ru(), count), severity_color(sev));
        }
    });
}

fn verdict_color(verdict: Verdict) -> Color32 {
    match verdict {
        Verdict::HighRisk => style::DANGER,
        Verdict::Suspicious => style::WARN,
        Verdict::LowSignal => Color32::from_rgb(190, 200, 120),
        Verdict::Clean => style::OK,
        Verdict::NoData => style::MUTED,
    }
}

fn severity_color(sev: Severity) -> Color32 {
    match sev {
        Severity::Critical => style::DANGER,
        Severity::High => Color32::from_rgb(236, 140, 86),
        Severity::Medium => Color32::from_rgb(222, 200, 110),
        Severity::Low => Color32::from_rgb(140, 190, 224),
        Severity::Info => style::MUTED,
    }
}

fn shorten_path(path: &str, max: usize) -> String {
    let chars: Vec<char> = path.chars().collect();
    if chars.len() <= max {
        return path.to_string();
    }
    let keep = max.saturating_sub(3);
    let mut out: String = chars[chars.len() - keep..].iter().collect();
    out.insert(0, '…');
    out
}

fn dirs_downloads() -> Option<PathBuf> {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(PathBuf::from)
        .ok()?;
    let downloads = home.join("Downloads");
    Some(if downloads.is_dir() { downloads } else { home })
}

/// Кириллица и моноширинный шрифт: без этого текст соглашения в egui разъезжается,
/// а часть символов пропадает.
fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let candidates = [
        ("segoe", "C:\\Windows\\Fonts\\segoeui.ttf", true),
        ("arial", "C:\\Windows\\Fonts\\arial.ttf", true),
        ("consolas", "C:\\Windows\\Fonts\\consola.ttf", false),
        ("courier", "C:\\Windows\\Fonts\\cour.ttf", false),
    ];
    let mut proportional: Vec<String> = Vec::new();
    let mut monospace: Vec<String> = Vec::new();
    for (key, path, is_proportional) in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert(key.to_owned(), Arc::new(egui::FontData::from_owned(bytes)));
            if is_proportional {
                proportional.push(key.to_owned());
            } else {
                monospace.push(key.to_owned());
            }
        }
    }
    for name in proportional {
        if let Some(list) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
            list.insert(0, name);
        }
    }
    for name in monospace {
        if let Some(list) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
            list.insert(0, name.clone());
            list.push(name);
        }
    }
    ctx.set_fonts(fonts);
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        if self.scanning {
            ctx.request_repaint_after(Duration::from_millis(120));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        match self.screen {
            Screen::Agreement => self.view_agreement(ui),
            Screen::Refused => self.view_refused(ui),
            Screen::Working => self.view_main(ui),
        }
    }
}
