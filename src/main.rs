#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod agreement;
mod icon_data;
mod paths;
mod scanner;
mod signatures;
mod style;
mod swcc;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use eframe::egui;

use scanner::{ScanEvent, ScanOptions, ScanResult, Scanner};
use signatures::SignatureDb;
use swcc::Report;

const HELP: &str = "\
Sunrise Worlds Cheats Checker (swcc)

Запуск без аргументов - окно с соглашением и графический интерфейс.

Команды:
  swcc verify <файл.swcc>
        Проверить целостность полученного отчёта (payload + печать).
        Код возврата 0 - цел, 2 - файл правили или он не .swcc.

  swcc scan <папка игры> [...] --i-accept [--out файл.swcc] [--no-deep] [--full]
        Проверка без окна. Соглашение при этом читается в консоль, а флаг
        --i-accept означает, что игрок согласен: без него сканер не запустится.
        Несколько папок через пробел. --no-deep - не распаковывать архивы.
        --full - дополнительно обойти все диски (по метаданным).

  swcc help
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        None => run_gui(),
        Some("help") | Some("--help") | Some("-h") => {
            println!("{HELP}");
            0
        }
        Some("verify") => cli_verify(&args[1..]),
        Some("scan") => cli_scan(&args[1..]),
        Some(other) => {
            eprintln!("Неизвестная команда: {other}\n");
            eprintln!("{HELP}");
            1
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
}

fn run_gui() -> i32 {
    let viewport = egui::ViewportBuilder::default()
        .with_inner_size([1220.0, 800.0])
        .with_min_inner_size([900.0, 620.0])
        .with_title("Sunrise Worlds Cheats Checker")
        .with_icon(egui::IconData {
            rgba: icon_data::rgba(),
            width: icon_data::ICON_SIZE,
            height: icon_data::ICON_SIZE,
        });
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    match eframe::run_native(
        "Sunrise Worlds Cheats Checker",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    ) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("Не удалось запустить окно: {err}");
            3
        }
    }
}

fn cli_verify(args: &[String]) -> i32 {
    let Some(path) = args.first() else {
        eprintln!("Укажи файл: swcc verify <файл.swcc>");
        return 1;
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("Файл не читается ({path}): {err}");
            return 1;
        }
    };
    let outcome = Report::verify(&text);
    println!("{}", outcome.detail);
    if let Some(report) = outcome.report {
        println_report_summary(&report.result);
        println!(
            "Согласие: {} (текст {}) · папок проверено: {}",
            report.agreement.accepted_at,
            report.agreement.text_version,
            report.roots.len()
        );
    }
    if outcome.intact {
        0
    } else {
        2
    }
}

fn cli_scan(args: &[String]) -> i32 {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut out: Option<PathBuf> = None;
    let mut deep = true;
    let mut accepted = false;
    let mut full = false;
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--out" => out = iter.next().map(PathBuf::from),
            "--no-deep" => deep = false,
            "--full" => full = true,
            "--i-accept" => accepted = true,
            other if other.starts_with("--") => {
                eprintln!("Неизвестный флаг: {other}");
                return 1;
            }
            other => dirs.push(PathBuf::from(other)),
        }
    }

    if dirs.is_empty() {
        dirs = paths::discover_roots()
            .into_iter()
            .map(|r| PathBuf::from(r.path))
            .collect();
        if dirs.is_empty() {
            eprintln!("Папки игры не найдены. Укажи их явно: swcc scan <папка>");
            return 1;
        }
        println!("Автопоиск нашёл папки:");
        for d in &dirs {
            println!("  {}", d.display());
        }
    }

    // Согласие спрашивается и в консольном режиме: без явного флага ничего
    // не читается.
    if !accepted {
        print!("{}", agreement::SUMMARY);
        print!("{}", agreement::body());
        println!("\n{}", agreement::WARNING);
        eprintln!("\nПовтори с --i-accept, если прочитал и согласен.");
        return 4;
    }

    let mut roots = Vec::new();
    for dir in &dirs {
        match paths::accept_manual_root(dir) {
            Ok(root) => roots.push(root),
            Err(reason) => {
                eprintln!("{}: {reason}", dir.display());
                return 1;
            }
        }
    }

    if full {
        let game = roots.len();
        roots.extend(paths::computer_roots());
        println!(
            "Проверка всего компьютера: добавлено дисков {}, папок игры {}",
            roots.len() - game,
            game
        );
    }

    let db_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("signatures")));
    let db = SignatureDb::load(db_dir.as_deref().filter(|d| d.exists()));
    let opts = ScanOptions {
        roots: roots.clone(),
        deep_archives: deep,
        whole_pc: full,
        ..Default::default()
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut scanner = Scanner::new(&db, &opts);
    scanner.run(&tx, cancel.as_ref());

    let mut result: Option<ScanResult> = None;
    while let Ok(ev) = rx.try_recv() {
        if let ScanEvent::Finished(r) = ev {
            result = Some(*r);
        }
    }
    let Some(result) = result else {
        eprintln!("Сканер не вернул результат.");
        return 3;
    };

    println_report_summary(&result);

    let report = Report::build(
        result,
        roots,
        agreement::AgreementRecord::accept(),
        deep,
    );
    let path = out.unwrap_or_else(|| PathBuf::from(format!("{}.swcc", report.id)));
    match report.write(&path) {
        Ok(bytes) => println!(
            "Отчёт: {} ({} КБ) · печать {}",
            path.display(),
            bytes / 1024,
            report.seal()
        ),
        Err(err) => {
            eprintln!("Отчёт не записан: {err}");
            return 3;
        }
    }
    0
}

fn println_report_summary(result: &ScanResult) {
    println!(
        "\n=== {} · балл {} · находок {} · семейств {} · файлов {} · {} мс ===",
        result.verdict.ru(),
        result.score,
        result.findings.len(),
        result.families.len(),
        result.stats.files_walked,
        result.stats.duration_ms
    );
    for f in &result.families {
        println!(
            "  {:<28} {:<10} признач. {:>2} в {:>2} файлах  conf {:.0}%",
            f.family,
            f.severity.ru(),
            f.findings,
            f.distinct_files,
            f.max_confidence * 100.0
        );
    }
    for f in scanner::query(&result.findings, "", signatures::Severity::Medium) {
        println!(
            "  [{}] {} · {} · {}",
            f.severity.ru().to_uppercase(),
            f.family,
            f.location(),
            f.rules
                .iter()
                .map(|r| r.rule.ru())
                .collect::<Vec<_>>()
                .join("+")
        );
    }
    if result.findings.is_empty() {
        println!("  {}\n  {}", result.verdict.advice(), "См. раздел «Пределы метода» в отчёте.");
    }
}
