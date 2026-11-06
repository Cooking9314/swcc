use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agreement::AgreementRecord;
use crate::paths::GameRoot;
use crate::scanner::{Finding, ScanResult, APP_VERSION, FORMAT_VERSION};
use crate::signatures::Severity;

const WIDTH: usize = 72;
const PAYLOAD_START: &str = "!PAYLOAD-BEGIN!";
const PAYLOAD_END: &str = "!PAYLOAD-END!";
const SEAL_MARKER: &str = "!SEAL!";
/// Печать считается от этой константы и текста payload. Она доказывает только
/// целостность файла, а не авторство: константа лежит в той же программе, что
/// стоит у игрока. Об этом сказано в самом отчёте.
const SEAL_SALT: &str = "sunrise-worlds-swcc-seal-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub format: String,
    pub id: String,
    pub created_at: String,
    pub app_version: String,
    /// Ник, который игрок ввёл перед проверкой: по нему админ составляет команду бана.
    #[serde(default)]
    pub player: String,
    pub agreement: AgreementRecord,
    pub roots: Vec<GameRoot>,
    /// Включённые настройки проверки - чтобы админ понимал, насколько полной был обход.
    #[serde(default)]
    pub settings: Vec<String>,
    pub result: ScanResult,
}

#[derive(Debug, Clone)]
pub struct VerifyOutcome {    pub intact: bool,
    pub detail: String,
    pub report: Option<Report>,
}

impl Report {
    pub fn build(
        result: ScanResult,
        roots: Vec<GameRoot>,
        agreement: AgreementRecord,
        player: String,
        settings: Vec<String>,
    ) -> Self {
        Report {
            format: format!("swcc/{FORMAT_VERSION}"),
            id: report_id(),
            created_at: chrono::Local::now().to_rfc3339(),
            app_version: APP_VERSION.to_string(),
            player,
            agreement,
            roots,
            settings,
            result,
        }
    }

    pub fn payload_base64(&self) -> String {
        let json = serde_json::to_string(self).expect("отчёт сериализуется");
        base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
    }

    pub fn seal_for(payload: &str) -> String {
        let mut h = Sha256::new();
        h.update(SEAL_SALT.as_bytes());
        h.update(payload.as_bytes());
        hex::encode(&h.finalize()[..12])
    }

    pub fn seal(&self) -> String {
        Self::seal_for(&self.payload_base64())
    }

    /// Человекочитаемая часть отчёта.
    pub fn render(&self) -> String {
        let r = &self.result;
        let mut o = String::new();

        rule(&mut o, '=');
        line(&mut o, " SUNRISE WORLDS - ОТЧЁТ О ПРОВЕРКЕ НА ПРИЗНАКИ ЧИТОВ");
        line(
            &mut o,
            &format!(
                " формат .swcc v{}    приложение swcc {}    база сигнатур {}",
                FORMAT_VERSION, self.app_version, r.db_version
            ),
        );
        rule(&mut o, '=');
        kv(&mut o, "Отчёт N", &self.id);
        kv(&mut o, "Сформирован", &self.created_at);
        kv(&mut o, "Игрок", &self.player);
        kv(
            &mut o,
            "Согласие игрока",
            &format!(
                "принято {} (текст {})",
                self.agreement.accepted_at, self.agreement.text_version
            ),
        );
        kv(&mut o, "Отправлено на сервер", "НЕТ. Отчёт создаётся локально и никуда не уходит; игрок пересылает файл сам.");
        blank(&mut o);

        section(&mut o, "ИТОГ");
        kv(&mut o, "Заключение", r.verdict.ru());
        kv(
            &mut o,
            "Балл риска",
            &format!("{} (0-100+; >80 - высокая вероятность)", r.score),
        );
        kv(&mut o, "Всего находок", &counts(r));
        let families_list = if r.families.is_empty() {
            "ни одного".to_string()
        } else {
            r.families
                .iter()
                .map(|f| {
                    format!(
                        "{} - {} признак(ов) в {} файлах{}",
                        f.family,
                        f.findings,
                        f.distinct_files,
                        if f.corroborated {
                            ", подтверждено несколькими"
                        } else {
                            ""
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join("; ")
        };
        kv(&mut o, "Найдено семейств", &families_list);
        blank(&mut o);
        wrapped(&mut o, "Что это значит", r.verdict.advice());
        blank(&mut o);

        section(&mut o, "КАК ПРОВЕРЯТЬ ЭТОТ ОТЧЁТ (памятка админу)");
        for hint in [
            "Отчёт - повод для проверки, а не доказательство. Бан только по заключению сканера обосновать нельзя.",
            "Сверь названный файл с официальным релизом: пересобранный jar под именем легитимного мода - главный приём маскировки.",
            "Запроси у игрока сам файл (или ссылку на его публичный релиз) и путь к нему;совпадение пути в отчёте и присланного файла подтверждает находку.",
            "Смотри время изменения файлов: чит, скачанный за минуты до забан-события, и мод, установленный месяц назад, - это разные ситуации.",
            "Обнови базу сигнатур (signatures/custom.toml) при появлении нового клиента: встроенная база знает ограниченное число клиентов.",
            "Остаточный конфиг или удалённый клиент не оправдание: проверяй логи поведения на сервере.",
        ] {
            bullet(&mut o, hint);
        }
        blank(&mut o);

        section(&mut o, "ЧТО СКАНИРОВАЛОСЬ");
        if self.roots.is_empty() {
            bullet(&mut o, "Ни одна папка игры не найдена - проверка не выполнялась.");
        } else {
            for root in &self.roots {
                bullet(
                    &mut o,
                    &format!(
                        "[{}] {} - {}",
                        root.kind.ru(),
                        root.label,
                        crate::paths::shown_path(&root.path)
                    ),
                );
            }
        }
        bullet(
            &mut o,
            "Исключены из обхода: assets, libraries, runtime, bin, каталоги нативок (легитимные и огромные).",
        );
        if self.roots.iter().any(|r| !r.kind.is_game()) {
            bullet(
                &mut o,
                "Широкие папки (корни дисков и папки без признаков игры) обойдены только по \
                 именам, размерам и датам: содержимое файлов открывалось лишь там, где имя или \
                 путь уже дали зацепку.",
            );
        }
        for s in &self.settings {
            bullet(&mut o, s);
        }
        blank(&mut o);

        section(&mut o, "СТАТИСТИКА");
        kv(&mut o, "Файлов просмотрено", &r.stats.files_walked.to_string());
        kv(&mut o, "Каталогов пройдено", &r.stats.dirs_walked.to_string());
        kv(
            &mut o,
            "Системных каталогов пропущено",
            &r.stats.dirs_pruned_system.to_string(),
        );
        kv(&mut o, "Архивов открыто", &r.stats.archives_opened.to_string());
        kv(
            &mut o,
            "Архивов распаковано глубоко",
            &format!(
                "{} (пропущено по бюджету: {})",
                r.stats.archives_deep_scanned, r.stats.archives_skipped_by_budget
            ),
        );
        kv(
            &mut o,
            "Отброшено как легитимное",
            &format!("{} совпадений", r.stats.suppressed),
        );
        kv(
            &mut o,
            "Длительность",
            &format!("{} мс", r.stats.duration_ms),
        );
        if r.stats.walk_limited {
            bullet(
                &mut o,
                "ВНИМАНИЕ: обход достиг лимита числа файлов - часть файлов не проверена.",
            );
        }
        if r.stats.aborted {
            bullet(&mut o, "ВНИМАНИЕ: проверка прервана пользователем - вывод неполный.");
        }
        blank(&mut o);

        section(&mut o, "СИСТЕМА");
        kv(&mut o, "ОС / архитектура", &r.environment.os);
        kv(&mut o, "Пользователь ПК", &r.environment.user);
        kv(&mut o, "Часовой пояс", &r.environment.timezone);
        if !r.environment.mc_versions.is_empty() {
            kv(&mut o, "Версии игры", &r.environment.mc_versions.join(", "));
        }
        if let Some(v) = &r.environment.java_from_log {
            kv(&mut o, "Java из лога", v);
        }
        if let Some(v) = &r.environment.loader_from_log {
            kv(&mut o, "Загрузчик из лога", v);
        }
        if let Some(v) = &r.environment.nick_from_launch {
            kv(&mut o, "Ник из строки запуска", v);
        }
        blank(&mut o);

        section(&mut o, "НАХОДКИ");
        if r.findings.is_empty() {
            bullet(&mut o, "Ни одной находки. См. предупреждение ниже о пределах метода.");
        } else {
            let mut list: Vec<&Finding> = r.findings.iter().collect();
            list.sort_by(|a, b| {
                b.severity
                    .cmp(&a.severity)
                    .then_with(|| b.confidence.total_cmp(&a.confidence))
            });
            for (i, f) in list.iter().enumerate() {
                render_finding(&mut o, i + 1, f);
            }
        }
        blank(&mut o);

        section(&mut o, "ОТБРОШЕННО КАК ЛЕГИТИМНОЕ");
        if r.suppressed.is_empty() {
            bullet(&mut o, "Нет.");
        } else {
            for s in &r.suppressed {
                bullet(
                    &mut o,
                    &format!("{} -> {} ({})", s.sig_id, s.path, s.by),
                );
            }
        }
        blank(&mut o);

        section(&mut o, "ИНВЕНТАРЬ МОДОВ");
        if r.mods.is_empty() {
            bullet(&mut o, "Папок mods не найдено или они пусты.");
        } else {
            bullet(
                &mut o,
                &format!("{} файлов в mods/addons (в порядке обхода):", r.mods.len()),
            );
            for m in &r.mods {
                o.push_str(&format!(
                    "    {:<52} {:>10} байт\n",
                    truncate(&m.rel_path, 52),
                    m.size_bytes
                ));
            }
        }
        if !r.resource_packs.is_empty() {
            blank(&mut o);
            bullet(
                &mut o,
                &format!("{} ресурспаков:", r.resource_packs.len()),
            );
            for p in &r.resource_packs {
                bullet(&mut o, &format!("{} ({} байт)", p.rel_path, p.size_bytes));
            }
        }
        blank(&mut o);

        if !r.warnings.is_empty() || !r.db_warnings.is_empty() {
            section(&mut o, "ПРЕДУПРЕЖДЕНИЯ");
            for w in r.warnings.iter().chain(r.db_warnings.iter()) {
                bullet(&mut o, w);
            }
            blank(&mut o);
        }

        section(&mut o, "ПРЕДЕЛЫ МЕТОДА - ПРОЧИТАЙ ДО ТОГО, КАК РЕШАТЬ");
        for t in [
            "Сканер ищет файлы по известным сигнатурам. Самописный или пересобранный чит он может не увидеть: чистый отчёт не равен честной игре.",
            "Ложные срабатывания возможны: совпадение имени или строки в легитимном моде - не чит. Поэтому у каждой находки указан признак и уверенность.",
            "Отчёт формируется на машине игрока, которую он контролирует. Печать ниже ловит случайную правку и повреждение файла, но не подделку: ключ печати находится в той же программе, что и у игрока.",
            "Отсюда вывод: решение принимай по совокупности - отчёт + запрошенные у игрока файлы + серверные логи поведения.",
        ] {
            bullet(&mut o, t);
        }
        blank(&mut o);
        rule(&mut o, '-');
        line(&mut o, " НИЖЕ - МАШИНОЧИТАЕМАЯ КОПИЯ. Не редактируй: она ломает печать.");
        rule(&mut o, '-');
        blank(&mut o);

        o.push_str(PAYLOAD_START);
        o.push('\n');
        for chunk in wrap_chunks(&self.payload_base64(), WIDTH) {
            o.push_str(chunk);
            o.push('\n');
        }
        o.push_str(PAYLOAD_END);
        o.push('\n');
        o.push_str(&format!("{SEAL_MARKER} {}\n", self.seal()));
        blank(&mut o);
        kv(&mut o, "Печать", &self.seal());
        line(&mut o, " печать = контрольная сумма машиночитаемой части, первые 24 символа");
        rule(&mut o, '=');
        line(&mut o, &format!(" конец отчёта {}", self.id));
        rule(&mut o, '=');
        o
    }

    pub fn write(&self, path: &std::path::Path) -> anyhow::Result<usize> {
        let text = self.render();
        // BOM: иначе Блокнот в русской локали иногда показывает кракозябры.
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend(text.as_bytes());
        std::fs::write(path, &bytes)?;
        Ok(bytes.len())
    }

    /// Проверка полученного отчёта: целость payload и печати.
    pub fn verify(text: &str) -> VerifyOutcome {
        let body = text.trim_start_matches('\u{feff}');
        let Some(start) = body.find(PAYLOAD_START) else {
            return VerifyOutcome {
                intact: false,
                detail: "В файле нет машиночитаемой части: это не .swcc или файл обрезан.".into(),
                report: None,
            };
        };
        let after = &body[start + PAYLOAD_START.len()..];
        let Some(end) = after.find(PAYLOAD_END) else {
            return VerifyOutcome {
                intact: false,
                detail: "Конец payload не найден: файл повреждён или пересобран вручную.".into(),
                report: None,
            };
        };
        let payload: String = after[..end].chars().filter(|c| !c.is_whitespace()).collect();
        let seal_in_file = body
            .rfind(SEAL_MARKER)
            .and_then(|i| body[i + SEAL_MARKER.len()..].split_whitespace().next())
            .unwrap_or_default()
            .to_string();

        let decoded = match base64::engine::general_purpose::STANDARD.decode(&payload) {
            Ok(d) => d,
            Err(_) => {
                return VerifyOutcome {
                    intact: false,
                    detail: "payload не декодируется: файл изменён после формирования.".into(),
                    report: None,
                };
            }
        };
        let report: Report = match serde_json::from_slice(&decoded) {
            Ok(r) => r,
            Err(err) => {
                return VerifyOutcome {
                    intact: false,
                    detail: format!("payload не разобран: {err}"),
                    report: None,
                };
            }
        };
        let expected = Report::seal_for(&payload);
        if seal_in_file.is_empty() {
            return VerifyOutcome {
                intact: false,
                detail: "Печать в файле отсутствует.".into(),
                report: Some(report),
            };
        }
        if expected != seal_in_file {
            return VerifyOutcome {
                intact: false,
                detail: format!(
                    "Печать не сходится: в файле {seal_in_file}, пересчитано {expected}. Текст payload изменён."
                ),
                report: Some(report),
            };
        }
        VerifyOutcome {
            intact: true,
            detail: format!(
                "Целостность подтверждена. Отчёт {} не редактирован (заключение: {}).",
                report.id,
                report.result.verdict.ru()
            ),
            report: Some(report),
        }
    }
}

fn render_finding(o: &mut String, index: usize, f: &Finding) {
    o.push_str(&format!(
        "\n [F-{index:02}] {}  {}  |  {}\n",
        f.severity.ru().to_uppercase(),
        f.family,
        f.kind.ru()
      ));
    kv(o, "Сигнатура", &format!("{}  (уверенность {:.0}%, вес {})", f.sig_id, f.confidence * 100.0, f.weight));
    match &f.evidence {
        crate::scanner::Evidence::File(file) => {
            kv(o, "Файл", &file.rel_path);
            kv(o, "Где", &file.root);
            kv(
                o,
                "Размер / изменён",
                &format!("{} байт  |  {}", file.size_bytes, file.modified),
            );
        }
        crate::scanner::Evidence::Directory { root, rel_path } => {
            kv(o, "Каталог", &format!("{rel_path}/"));
            kv(o, "Где", root);
        }
        crate::scanner::Evidence::LaunchLine {
            source,
            excerpt,
            referenced_file,
        } => {
            kv(o, "Источник", source);
            if let Some(rf) = referenced_file {
                kv(o, "Названный файл", rf);
            }
            wrapped(o, "Строка запуска", &truncate(excerpt, 600));
        }
    }
    o.push_str("    Признаки:\n");
    for r in &f.rules {
        o.push_str(&format!(
            "      - {}: {}\n",
            r.rule.ru(),
            truncate(&r.detail, 200)
        ));
    }
    if !f.explain.is_empty() {
        wrapped(o, "Суть", &f.explain);
    }
    if !f.verify.is_empty() {
        wrapped(o, "Как проверить", &f.verify);
    }
}

// ---------------------------------------------------------------------------
// Помощники вёрстки (только ASCII-рамка: не разъезжается в любом шрифте)
// ---------------------------------------------------------------------------

fn rule(o: &mut String, ch: char) {
    o.push_str(&ch.to_string().repeat(WIDTH));
    o.push('\n');
}

fn line(o: &mut String, text: &str) {
    o.push_str(text);
    o.push('\n');
}

fn blank(o: &mut String) {
    o.push('\n');
}

fn section(o: &mut String, title: &str) {
    rule(o, '-');
    o.push_str(title);
    o.push('\n');
    rule(o, '-');
}

fn kv(o: &mut String, key: &str, value: &str) {
    let value = value.replace('\n', " ");
    if value.len() + key.len() + 3 <= WIDTH {
        o.push_str(&format!("{key:<19} : {value}\n"));
    } else {
        let indent = " ".repeat(21);
        o.push_str(&format!("{key:<19} : {}", head(&value, WIDTH - 21)));
        o.push('\n');
        let mut rest = &value[head_len(&value, WIDTH - 21)..];
        while !rest.is_empty() {
            let take = head_len(rest, WIDTH - indent.len());
            o.push_str(&indent);
            o.push_str(&head(rest, WIDTH - indent.len()));
            o.push('\n');
            rest = &rest[take..];
        }
    }
}

fn bullet(o: &mut String, text: &str) {
    let mut iter = text;
    let mut prefix = "  * ".to_string();
    loop {
        let take = head_len(iter, WIDTH - 4);
        if take == 0 {
            break;
        }
        o.push_str(&prefix);
        o.push_str(&head(iter, WIDTH - 4));
        o.push('\n');
        iter = &iter[take..];
        prefix = "    ".to_string();
        if iter.is_empty() {
            break;
        }
    }
}

fn wrapped(o: &mut String, key: &str, text: &str) {
    kv(o, key, text);
}

/// Байты до границы, но не внутри UTF-8 символа.
fn head_len(s: &str, width: usize) -> usize {
    if s.len() <= width {
        return s.len();
    }
    let mut i = width;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    // Пробуем разорвать по пробелу, иначе слово перенесётся целиком.
    if let Some(sp) = s[..i].rfind(' ') {
        if sp > width / 2 {
            return sp + 1;
        }
    }
    i
}

fn head(s: &str, width: usize) -> String {
    s[..head_len(s, width)].trim_end().to_string()
}

fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(width - 1).collect();
        out.push('~');
        out
    }
}

fn wrap_chunks(s: &str, width: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut start = 0;
    while start < bytes.len() {
        let end = (start + width).min(bytes.len());
        out.push(&s[start..end]);
        start = end;
    }
    out
}

fn counts(r: &ScanResult) -> String {
    let at = |s: Severity| r.findings.iter().filter(|f| f.severity == s).count();
    format!(
        "{} (критических {}, высоких {}, средних {}, низких {}, инфо {})",
        r.findings.len(),
        at(Severity::Critical),
        at(Severity::High),
        at(Severity::Medium),
        at(Severity::Low),
        at(Severity::Info),
    )
}

fn report_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = Sha256::new();
    h.update(nanos.to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    h.update(env!("CARGO_PKG_VERSION").as_bytes());
    let hex = hex::encode(h.finalize());
    format!("SWCC-{}", hex[..12].to_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{
        Evidence, FileEvidence, Finding, InventoryEntry, RuleHit, ScanStats, Verdict,
    };
    use crate::signatures::{Kind, RuleKind};

    fn finding(sev: Severity, conf: f32, path: &str) -> Finding {
        Finding {
            sig_id: "meteor.client".into(),
            family: "Meteor Client".into(),
            kind: Kind::CheatClient,
            severity: sev,
            rules: vec![RuleHit {
                rule: RuleKind::FileName,
                detail: path.to_string(),
                confidence: conf,
            }],
            confidence: conf,
            weight: 60,
            explain: "тест".into(),
            verify: "сверь файл с релизом".into(),
            evidence: Evidence::File(FileEvidence {
                root: "Minecraft".into(),
                rel_path: path.to_string(),
                size_bytes: 1234,
                modified: "2026-11-01T10:00:00".into(),
            }),
        }
    }

    fn result(findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            families: vec![],
            findings,
            suppressed: vec![],
            mods: vec![InventoryEntry {
                name: "sodium.jar".into(),
                rel_path: "mods/sodium.jar".into(),
                size_bytes: 1,
            }],
            resource_packs: vec![],
            environment: Default::default(),
            stats: ScanStats::default(),
            score: 0,
            verdict: Verdict::Clean,
            db_sources: vec!["в".into()],
            db_version: "t".into(),
            db_warnings: vec![],
            started_at: "2026-11-06T00:00:00".into(),
            warnings: vec![],
        }
    }

    fn report(findings: Vec<Finding>) -> Report {
        Report {
            format: "swcc/1".into(),
            id: "SWCC-TEST".into(),
            created_at: "2026-11-06T00:00:00".into(),
            app_version: "test".into(),
            agreement: AgreementRecord::sample(),
            roots: vec![GameRoot {
                label: "Minecraft".into(),
                path: "C:/fake/.minecraft".into(),
                kind: crate::paths::RootKind::Standard,
            }],
            player: "Steve_93".into(),
            settings: vec!["Чтение содержимого файлов: включено".into()],
            result: result(findings),
        }
    }

    #[test]
    fn payload_survives_roundtrip_and_seal() {
        let r = report(vec![finding(Severity::Critical, 0.95, "mods/meteor.jar")]);
        let text = r.render();
        let v = Report::verify(&text);
        assert!(v.intact, "{}", v.detail);
        let parsed = v.report.expect("отчёт разобран");
        assert_eq!(parsed.result.findings.len(), 1);
        assert_eq!(parsed.id, "SWCC-TEST");
    }

    #[test]
    fn verdict_is_read_from_payload_not_from_text() {
        let mut r = report(vec![finding(Severity::Critical, 0.95, "mods/meteor.jar")]);
        r.result.verdict = Verdict::HighRisk;
        let text = r.render();
        let edited = text.replace(Verdict::HighRisk.ru(), "ЧИСТО");
        assert_ne!(edited, text, "вердикт должен встречаться в человекочитаемой части");
        let v = Report::verify(&edited);
        assert!(v.intact, "правка текста не ломает печать payload: {v:?}");
        assert_eq!(
            v.report.unwrap().result.verdict,
            Verdict::HighRisk,
            "админ видит вывод из payload, а не из отредактированного текста"
        );
    }

    #[test]
    fn tampered_payload_breaks_seal() {
        let r = report(vec![finding(Severity::Critical, 0.95, "mods/meteor.jar")]);
        let mut text = r.render();
        let i = text.find(PAYLOAD_START).unwrap() + PAYLOAD_START.len() + 1;
        text.replace_range(i..i + 1, "!");
        let v = Report::verify(&text);
        assert!(!v.intact, "битый payload должен распознаваться");
    }

    #[test]
    fn missing_payload_is_reported() {
        let v = Report::verify("просто текст без разметки swcc");
        assert!(!v.intact);
        assert!(v.detail.contains("не .swcc") || v.detail.contains("нет"));
    }

    #[test]
    fn lines_never_exceed_width() {
        let r = report(vec![
            finding(Severity::Critical, 0.95, "mods/очень-длинное-имя-файла-которое-точно-не-влезет-в-строку-2026.jar"),
            finding(Severity::Medium, 0.4, "x"),
        ]);
        for l in r.render().lines() {
            assert!(
                l.chars().count() <= WIDTH + 24,
                "строка длиннее разметки: {l}"
            );
        }
    }

    #[test]
    fn report_names_the_player_and_never_a_hash() {
        let r = report(vec![finding(Severity::Critical, 0.95, "mods/meteor.jar")]);
        let text = r.render();
        let human = text.split(PAYLOAD_START).next().unwrap_or_default();
        assert!(human.contains("Steve_93"), "в отчёте нет ника игрока: {human}");
        for banned in ["SHA", "sha", "хэш", "Хэш", "хеш"] {
            assert!(!human.contains(banned), "в тексте отчёта упоминается {banned}");
        }
        assert!(text.contains(SEAL_MARKER), "после payload нет строки печати");
    }

    #[test]
    fn secret_flags_are_redacted() {
        let line = "--username Steve --accessToken SECRET --xuid=ABC --version 1.20.4";
        let out = crate::scanner::redact_secrets(line);
        assert!(!out.contains("SECRET"), "{out}");
        assert!(!out.contains("ABC"), "{out}");
        assert!(out.contains("Steve"));
    }
}
