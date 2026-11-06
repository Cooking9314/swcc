use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Instant;

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::paths::GameRoot;
use crate::signatures::{combine_confidence, Kind, RuleKind, Severity, SignatureDb};

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const FORMAT_VERSION: &str = "1";

const MAX_FINDINGS: usize = 400;
const MAX_SUPPRESSED: usize = 80;
const MAX_INVENTORY: usize = 900;
const MAGIC_HITS_PER_FILE: usize = 24;
const READ_CHUNK: usize = 64 * 1024;
const MAX_ENTRY_BYTES: u64 = 2 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Модель данных
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvidence {
    pub root: String,
    pub rel_path: String,
    pub size_bytes: u64,
    pub modified: String,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHit {
    pub rule: RuleKind,
    pub detail: String,
    pub confidence: f32,
}

/// Основание находки. Всегда проверяемое вручную: путь, каталог или строка
/// запуска. Содержимое чужих файлов в отчёт не попадает.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Evidence {
    File(FileEvidence),
    Directory { root: String, rel_path: String },
    LaunchLine {
        source: String,
        excerpt: String,
        #[serde(default)]
        referenced_file: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub sig_id: String,
    pub family: String,
    pub kind: Kind,
    pub severity: Severity,
    pub rules: Vec<RuleHit>,
    pub confidence: f32,
    pub weight: u32,
    pub explain: String,
    pub verify: String,
    pub evidence: Evidence,
}

impl Finding {
    pub fn location(&self) -> String {
        match &self.evidence {
            Evidence::File(f) => f.rel_path.clone(),
            Evidence::Directory { rel_path, .. } => format!("{rel_path}/"),
            Evidence::LaunchLine { source, .. } => source.clone(),
        }
    }

    pub fn effective_weight(&self) -> u32 {
        (self.weight as f32 * self.confidence).round() as u32
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryEntry {
    pub name: String,
    pub rel_path: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Environment {
    pub os: String,
    pub arch: String,
    pub user: String,
    pub timezone: String,
    pub mc_versions: Vec<String>,
    pub java_from_log: Option<String>,
    pub loader_from_log: Option<String>,
    pub nick_from_launch: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    pub dirs_walked: u64,
    pub files_walked: u64,
    pub bytes_read: u64,
    pub archives_opened: u64,
    pub archives_deep_scanned: u64,
    pub archives_skipped_by_budget: u64,
    pub files_hashed: u64,
    pub hash_bytes: u64,
    pub files_too_large: u64,
    pub files_unreadable: u64,
    pub symlinks_skipped: u64,
    pub dirs_pruned_system: u64,
    pub suppressed: u64,
    pub walk_limited: bool,
    pub aborted: bool,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    NoData,
    Clean,
    LowSignal,
    Suspicious,
    HighRisk,
}

impl Verdict {
    pub fn ru(self) -> &'static str {
        match self {
            Verdict::NoData => "Данных нет",
            Verdict::Clean => "Признаков не найдено",
            Verdict::LowSignal => "Косвенные признаки",
            Verdict::Suspicious => "Подозрение",
            Verdict::HighRisk => "Высокий риск",
        }
    }

    pub fn advice(self) -> &'static str {
        match self {
            Verdict::NoData => {
                "Сканирование не выполнено: не найдено ни одной папки игры, либо процесс прерван."
            }
            Verdict::Clean => {
                "Автоматических признаков не найдено. Это НЕ гарантия честной игры: база знает ограниченное число клиентов, а кастомный пересобранный чит она не увидит."
            }
            Verdict::LowSignal => {
                "Совпадения слабые или единичные. Бан по такому отчёту не обоснован."
            }
            Verdict::Suspicious => {
                "Нужна ручная проверка: запроси файлы по хэшам и сравни с официальными релизами."
            }
            Verdict::HighRisk => {
                "Несколько независимых признаков одного семейства либо критическое совпадение по хэшу. Вероятность чит-клиента высокая - проверяй хэши перед решением."
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilySummary {
    pub family: String,
    pub kind: Kind,
    pub severity: Severity,
    pub findings: usize,
    pub distinct_files: usize,
    pub corroborated: bool,
    pub score: u32,
    pub max_confidence: f32,
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub roots: Vec<GameRoot>,
    pub deep_archives: bool,
    pub deep_budget_bytes: u64,
    pub hash_budget_bytes: u64,
    /// Проверка всего компьютера: обход дисков по именам и атрибутам.
    /// Содержимое файлов читается только там, где уже есть зацепка.
    pub whole_pc: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            deep_archives: true,
            deep_budget_bytes: 384 * 1024 * 1024,
            hash_budget_bytes: 1024 * 1024 * 1024,
            whole_pc: false,
        }
    }
}

/// Каталоги, которые мы не обходим при проверке дисков целиком: системные,
/// мусор и хранилища легитимных библиотек. Иначе обход уйдет на сотни тысяч
/// файлов и ничего полезного не найдёт.
const SYSTEM_SKIP_DIRS: &[&str] = &[
    "windows",
    "$recycle.bin",
    "system volume information",
    "winsxs",
    "winstore",
    "driverstore",
    "servicing",
    "recovery",
    "perflogs",
    "boot",
    "efi",
    "$mfrt",
    "$extend",
    "assembly",
    "windowsold",
    "temp",
    "tmp",
];

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Progress {
        phase: &'static str,
        current: u64,
        note: String,
    },
    Finished(Box<ScanResult>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressedHit {
    pub sig_id: String,
    pub path: String,
    pub by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub families: Vec<FamilySummary>,
    pub suppressed: Vec<SuppressedHit>,
    pub mods: Vec<InventoryEntry>,
    pub resource_packs: Vec<InventoryEntry>,
    pub environment: Environment,
    pub stats: ScanStats,
    pub score: u32,
    pub verdict: Verdict,
    pub db_sources: Vec<String>,
    pub db_version: String,
    pub db_warnings: Vec<String>,
    pub started_at: String,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Индексы правил
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct RuleSet {
    sig: usize,
    re: Regex,
}

/// Одна альтернативная регулярка на все магические строки базы: поиск по файлу
/// идёт одним проходом вместо тысяч последовательных поисков.
struct MagicIndex {
    regex: Regex,
    owners: HashMap<String, Vec<(usize, f32)>>,
}

impl MagicIndex {
    fn build(db: &SignatureDb, raw: bool) -> Option<Self> {
        let mut owners: HashMap<String, Vec<(usize, f32)>> = HashMap::new();
        for (i, sig) in db.signatures.iter().enumerate() {
            let list = if raw {
                sig.raw_magics()
            } else {
                sig.jar_magics()
            };
            for m in list {
                owners.entry(m.clone()).or_default().push((i, sig.confidence));
            }
        }
        if owners.is_empty() {
            return None;
        }
        let mut keys: Vec<String> = owners.keys().cloned().collect();
        // Длинные раньше: иначе "xray" поглотит "xray esp" и потеряем владельцев.
        keys.sort_by(|a, b| b.len().cmp(&a.len()));
        let alt = keys
            .iter()
            .map(|k| regex::escape(k))
            .collect::<Vec<_>>()
            .join("|");
        let regex = regex_ci(&alt)?;
        Some(MagicIndex { regex, owners })
    }

    fn collect(&self, haystack: &str, kind: RuleKind, sink: &mut MatchSink) {
        for m in self.regex.find_iter(haystack).take(MAGIC_HITS_PER_FILE) {
            let key = m.as_str().to_ascii_lowercase();
            if let Some(ids) = self.owners.get(&key) {
                for (id, confidence) in ids {
                    sink.add(*id, kind, key.clone(), *confidence);
                }
            }
        }
    }
}

fn regex_ci(pattern: &str) -> Option<Regex> {
    regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .ok()
}

#[derive(Default)]
struct MatchSink(BTreeMap<usize, Vec<RuleHit>>);

impl MatchSink {
    fn add(&mut self, sig: usize, rule: RuleKind, detail: String, confidence: f32) {
        let hits = self.0.entry(sig).or_default();
        if !hits
            .iter()
            .any(|h| h.rule == rule && h.detail == detail)
        {
            hits.push(RuleHit {
                rule,
                detail,
                confidence,
            });
        }
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

struct Indexes {
    name: Vec<RuleSet>,
    path: Vec<RuleSet>,
    dir: Vec<RuleSet>,
    entry: Vec<RuleSet>,
    text: Vec<RuleSet>,
    log: Vec<RuleSet>,
    hash: HashMap<String, Vec<usize>>,
    raw_magic: Option<Arc<MagicIndex>>,
    jar_magic: Option<Arc<MagicIndex>>,
    skip_dir: HashSet<String>,
    skip_path: Vec<Regex>,
}

impl Indexes {
    fn build(db: &SignatureDb) -> Self {
        let mut idx = Indexes {
            name: vec![],
            path: vec![],
            dir: vec![],
            entry: vec![],
            text: vec![],
            log: vec![],
            hash: HashMap::new(),
            raw_magic: MagicIndex::build(db, true).map(Arc::new),
            jar_magic: MagicIndex::build(db, false).map(Arc::new),
            skip_dir: db
                .params
                .skip_dir_names
                .iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
            skip_path: db
                .params
                .skip_path_regex
                .iter()
                .filter_map(|p| regex_ci(p))
                .collect(),
        };
        for (i, sig) in db.signatures.iter().enumerate() {
            let push = |v: &mut Vec<RuleSet>, re: Option<&Regex>| {
                if let Some(re) = re {
                    v.push(RuleSet { sig: i, re: re.clone() });
                }
            };
            push(&mut idx.name, sig.name_re());
            push(&mut idx.path, sig.path_re());
            push(&mut idx.dir, sig.dir_re());
            push(&mut idx.entry, sig.entry_re());
            push(&mut idx.text, sig.text_re());
            push(&mut idx.log, sig.log_re());
            for h in sig.hashes() {
                idx.hash.entry(h.clone()).or_default().push(i);
            }
        }
        idx
    }

    fn skipped(&self, rel_lower: &str, name_lower: &str) -> bool {
        self.skip_dir.contains(name_lower)
            || rel_lower
                .split('/')
                .any(|part| self.skip_dir.contains(part))
            || self.skip_path.iter().any(|r| r.is_match(rel_lower))
    }
}

// ---------------------------------------------------------------------------
// Утилиты
// ---------------------------------------------------------------------------

fn mtime_iso(meta: &std::fs::Metadata) -> String {
    meta.modified().ok().map(|t| {
        let t: chrono::DateTime<chrono::Local> = t.into();
        t.to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
    }).unwrap_or_else(|| "неизвестно".into())
}

fn sha256_hex(path: &Path, budget: &mut u64) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    let size = meta.len();
    if size == 0 || size > *budget {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; READ_CHUNK];
    let mut done = 0u64;
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return None,
        };
        hasher.update(&buf[..n]);
        done += n as u64;
    }
    *budget -= done;
    Some(hex::encode(hasher.finalize()))
}

fn read_capped(path: &Path, cap: u64) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > cap {
        return None;
    }
    let mut buf = Vec::with_capacity(meta.len().min(1 << 20) as usize);
    std::fs::File::open(path).ok()?.read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn as_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn is_archive(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".jar") || n.ends_with(".zip") || n.ends_with(".litemod") || n.ends_with(".xl")
}

fn is_text(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        ".json", ".toml", ".cfg", ".conf", ".ini", ".txt", ".yml", ".yaml", ".properties",
        ".bat", ".cmd", ".sh", ".mcsettings", ".mcimport", ".html", ".xml", ".log",
    ]
    .iter()
    .any(|e| n.ends_with(e))
}

fn is_native(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".dll") || n.ends_with(".exe") || n.ends_with(".so") || n.ends_with(".dylib")
}

/// Внутри архивов смотрим байты только этих записей: классы (в константном
/// пуле имена пакетов), манифесты и конфиги.
fn entry_worth_reading(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        ".class", ".json", ".toml", ".cfg", ".txt", ".properties", ".mcmeta", ".xml", ".yml",
        ".html", ".bat", ".sh",
    ]
    .iter()
    .any(|e| n.ends_with(e))
}

/// Откуда читается файл: в `mods/` и `resourcepacks/` хэшируем всегда, остальные
/// только если на них уже есть находка.
fn in_inventory_dir(rel: &str) -> bool {
    rel.starts_with("mods/")
        || rel.contains("/mods/")
        || rel.starts_with("resourcepacks/")
        || rel.contains("/resourcepacks/")
        || rel.contains("/addons/")
}

fn log_source(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with("latest.log")
        || n.ends_with(".bat")
        || n.ends_with(".cmd")
        || n.ends_with(".sh")
        || n.ends_with("launcher_profiles.json")
}

/// Из строк запуска вычёрпываем токены: в логах некоторых лаунчеров они есть,
/// а в отчёте их быть не должно.
pub fn redact_secrets(line: &str) -> String {
    const SECRETS: &[&str] = &["--accessToken", "--xuid", "--clientId", "--userType", "--jwt"];
    let mut out = String::with_capacity(line.len());
    let mut drop_next = false;
    for token in line.split_whitespace() {
        if drop_next {
            out.push_str("<скрыто> ");
            drop_next = false;
            continue;
        }
        let (flag, has_inline_value) = match token.split_once('=') {
            Some((f, _)) => (f, true),
            None => (token, false),
        };
        if SECRETS.iter().any(|s| flag.eq_ignore_ascii_case(s)) {
            out.push_str(flag);
            out.push_str(if has_inline_value { "=<скрыто> " } else { " <скрыто> " });
            drop_next = !has_inline_value;
            continue;
        }
        out.push_str(token);
        out.push(' ');
    }
    out.trim().to_string()
}

/// Имя jar из `-javaagent:C:\...\something.jar` - по нему работают исключения.
fn referenced_agent(line: &str) -> Option<String> {
    let key = line.to_ascii_lowercase().find("-javaagent:")?;
    let rest = &line[key + "-javaagent:".len()..];
    let raw = rest
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(|c| c == '"' || c == '\'')
        .split(['=', ','])
        .next()
        .unwrap_or("");
    let name = raw.rsplit(['/', '\\']).next().unwrap_or(raw).trim_end_matches(',');
    (!name.is_empty()).then(|| name.to_string())
}

fn excerpt(body: &str, at: usize, len: usize) -> String {
    let start = at.saturating_sub(len / 3);
    let end = (at + len).min(body.len());
    let slice = &body[start..end];
    let flat = slice.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.len() > 400 {
        flat[..400].to_string()
    } else {
        flat
    }
}

// ---------------------------------------------------------------------------
// Сканер
// ---------------------------------------------------------------------------

pub struct Scanner<'a> {
    db: &'a SignatureDb,
    opts: &'a ScanOptions,
    idx: Indexes,
    stats: ScanStats,
    warnings: Vec<String>,
    findings: Vec<Finding>,
    suppressed: Vec<SuppressedHit>,
    mods: Vec<InventoryEntry>,
    packs: Vec<InventoryEntry>,
    env: Environment,
    mc_versions: HashSet<String>,
    deep_budget: u64,
    hash_budget: u64,
    budget_hash_skipped: u64,
    game_scoped: bool,
}

impl<'a> Scanner<'a> {
    pub fn new(db: &'a SignatureDb, opts: &'a ScanOptions) -> Self {
        Scanner {
            db,
            opts,
            idx: Indexes::build(db),
            stats: ScanStats::default(),
            warnings: db.warnings.clone(),
            findings: Vec::new(),
            suppressed: Vec::new(),
            mods: Vec::new(),
            packs: Vec::new(),
            env: Environment {
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
                user: std::env::var("USERNAME")
                    .or_else(|_| std::env::var("USER"))
                    .unwrap_or_else(|_| "неизвестно".into()),
                timezone: chrono::Local::now().offset().to_string(),
                ..Default::default()
            },
            mc_versions: HashSet::new(),
            deep_budget: opts.deep_budget_bytes,
            hash_budget: opts.hash_budget_bytes,
            budget_hash_skipped: 0,
            game_scoped: true,
        }
    }

    fn walk_limit(&self) -> u64 {
        if self.opts.whole_pc {
            self.db.params.max_walk_files * 8
        } else {
            self.db.params.max_walk_files
        }
    }

    pub fn run(&mut self, tx: &Sender<ScanEvent>, cancel: &AtomicBool) {
        let started = Instant::now();
        let started_at = chrono::Local::now().to_rfc3339();
        self.env.os = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);

        for root in &self.opts.roots {
            if cancel.load(Ordering::Relaxed) {
                self.stats.aborted = true;
                break;
            }
            let path = PathBuf::from(&root.path);
            self.game_scoped = root.kind.is_game();
            if !path.is_dir() {
                self.warnings
                    .push(format!("Папка недоступна, пропущена: {}", root.path));
                continue;
            }
            let _ = tx.send(ScanEvent::Progress {
                phase: "подготовка",
                current: 0,
                note: root.label.clone(),
            });
            self.walk_dir(&path, &path, "", 0, &root.label, tx, cancel);
            if self.stats.aborted || self.stats.walk_limited {
                break;
            }
        }

        let _ = tx.send(ScanEvent::Progress {
            phase: "анализ",
            current: self.stats.files_walked,
            note: String::new(),
        });

        let result = self.finalize(started, started_at);
        let _ = tx.send(ScanEvent::Finished(Box::new(result)));
    }

    fn walk_dir(
        &mut self,
        root: &Path,
        dir: &Path,
        prefix: &str,
        depth: usize,
        label: &str,
        tx: &Sender<ScanEvent>,
        cancel: &AtomicBool,
    ) {
        if depth > 14 {
            return;
        }
        let read = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => {
                self.stats.files_unreadable += 1;
                return;
            }
        };
        let mut entries: Vec<_> = read.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        self.stats.dirs_walked += 1;

        for entry in entries {
            if self.stats.files_walked >= self.walk_limit() {
                self.stats.walk_limited = true;
                self.warnings.push(format!(
                    "Обход остановлен на лимите {} файлов - остаток не проверен.",
                    self.walk_limit()
                ));
                return;
            }
            if self.stats.files_walked % 250 == 0 {
                if cancel.load(Ordering::Relaxed) {
                    self.stats.aborted = true;
                    return;
                }
                let _ = tx.send(ScanEvent::Progress {
                    phase: "обход",
                    current: self.stats.files_walked,
                    note: prefix.to_string(),
                });
            }

            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if file_type.is_symlink() {
                self.stats.symlinks_skipped += 1;
                continue;
            }
            let rel_lower = rel.to_ascii_lowercase();
            let name_lower = name.to_ascii_lowercase();
            if !self.game_scoped && SYSTEM_SKIP_DIRS.contains(&name_lower.as_str()) {
                self.stats.dirs_pruned_system += 1;
                continue;
            }
            if self.idx.skipped(&rel_lower, &name_lower) {
                continue;
            }
            let path = entry.path();

            if file_type.is_dir() {
                let matched: Vec<usize> = self
                    .idx
                    .dir
                    .iter()
                    .filter(|r| r.re.is_match(&rel_lower))
                    .map(|r| r.sig)
                    .collect();
                for sig in matched {
                    let mut sink = MatchSink::default();
                    sink.add(sig, RuleKind::Directory, rel.clone(), 1.0);
                    self.commit(
                        &sink,
                        &name,
                        &rel,
                        Evidence::Directory {
                            root: label.to_string(),
                            rel_path: rel.clone(),
                        },
                        None,
                    );
                }
                self.walk_dir(root, &path, &rel, depth + 1, label, tx, cancel);
                if self.stats.aborted || self.stats.walk_limited {
                    return;
                }
            } else {
                self.process_file(&path, &rel, &name, label);
                if let Some(meta) = entry.metadata().ok() {
                    self.note_inventory(&rel, &name, &meta);
                }
                self.note_version_json(&rel);
            }
        }
    }

    fn process_file(&mut self, path: &Path, rel: &str, name: &str, label: &str) {
        self.stats.files_walked += 1;
        let meta = match path.metadata() {
            Ok(m) => m,
            Err(_) => {
                self.stats.files_unreadable += 1;
                return;
            }
        };
        let size = meta.len();
        let archive = is_archive(name);
        let text = is_text(name);
        let native = is_native(name);
        let mut sink = MatchSink::default();

        for r in &self.idx.name {
            if r.re.is_match(name) {
                sink.add(
                    r.sig,
                    RuleKind::FileName,
                    name.to_string(),
                    self.db.signatures[r.sig].confidence,
                );
            }
        }
        for r in &self.idx.path {
            if r.re.is_match(rel) {
                sink.add(
                    r.sig,
                    RuleKind::FilePath,
                    rel.to_string(),
                    self.db.signatures[r.sig].confidence,
                );
            }
        }

        // Вне игровых папок содержимое файла читаем только если имя или путь
        // уже дали зацепку: иначе проверка диска превратилась бы в чтение всего.
        let probe = self.game_scoped || !sink.is_empty();

        let want_hash = probe
            && (archive || native)
            && size <= self.db.params.max_content_bytes
            && (in_inventory_dir(rel) || !sink.is_empty() || size <= 8 * 1024 * 1024);
        let hash = if want_hash {
            sha256_hex(path, &mut self.hash_budget)
        } else {
            if size <= self.db.params.max_content_bytes {
                self.budget_hash_skipped += 1;
            }
            None
        };
        if let Some(h) = &hash {
            if let Some(ids) = self.idx.hash.get(h) {
                for id in ids {
                    sink.add(
                        *id,
                        RuleKind::KnownHash,
                        h.clone(),
                        self.db.signatures[*id].confidence,
                    );
                }
            }
        }

        // 1) Сырые байты: имена записей архива и манифесты лежат открытым текстом.
        if probe && (archive || native) {
            if let Some(bytes) = read_capped(path, self.db.params.max_content_bytes) {
                let body = as_text(&bytes);
                let raw = self.idx.raw_magic.clone();
                if let Some(mi) = raw {
                    mi.collect(&body, RuleKind::RawBytes, &mut sink);
                }
                if archive {
                    self.scan_archive_names(path, &mut sink);
                }
            } else {
                self.stats.files_too_large += 1;
            }
        }

        // 2) Текстовые файлы и логи запуска.
        if probe && text {
            if let Some(bytes) = read_capped(path, self.db.params.max_text_bytes) {
                let body = as_text(&bytes);
                for r in &self.idx.text {
                    if let Some(m) = r.re.find(&body) {
                        sink.add(
                            r.sig,
                            RuleKind::TextContent,
                            excerpt(&body, m.start(), m.len()),
                            self.db.signatures[r.sig].confidence,
                        );
                    }
                }
                if log_source(name) {
                    for r in &self.idx.log {
                        if let Some(m) = r.re.find(&body) {
                            let raw = &body[m.start()..];
                            let line_end = raw.find(['\n', '\r']).unwrap_or(raw.len());
                            let mut end = line_end.min(1200);
                            while !raw.is_char_boundary(end) {
                                end -= 1;
                            }
                            let line = redact_secrets(&raw[..end]);
                            sink.add(
                                r.sig,
                                RuleKind::LaunchLog,
                                line.clone(),
                                self.db.signatures[r.sig].confidence,
                            );
                        }
                    }
                    self.note_env_from_log(&body);
                }
            }
        }

        // 3) Глубокая проверка архива: либо уже есть зацепка, либоmods/ при
        // включённой глубокой проверке и невостребованном бюджете.
        let candidate_needs_content = probe
            && archive
            && (!sink.is_empty()
                || (self.opts.deep_archives && in_inventory_dir(rel) && self.deep_budget > 0));
        if candidate_needs_content {
            if size > self.db.params.max_content_bytes {
                self.stats.files_too_large += 1;
            } else if self.deep_budget == 0 && !self.opts.deep_archives {
                self.stats.archives_skipped_by_budget += 1;
            } else if !self.deep_scan_archive(path, &mut sink) {
                self.stats.archives_skipped_by_budget += 1;
            } else {
                self.stats.archives_deep_scanned += 1;
            }
        }

        if !sink.is_empty() {
            let evidence = Evidence::File(FileEvidence {
                root: label.to_string(),
                rel_path: rel.to_string(),
                size_bytes: size,
                modified: mtime_iso(&meta),
                sha256: hash.clone(),
            });
            self.commit(&sink, name, rel, evidence, hash);
        }
    }

    /// Имена записей архива без распаковки (central directory).
    fn scan_archive_names(&mut self, path: &Path, sink: &mut MatchSink) {
        if self.idx.entry.is_empty() {
            return;
        }
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut zip = match zip::ZipArchive::new(std::io::BufReader::new(file)) {
            Ok(z) => z,
            Err(_) => return,
        };
        self.stats.archives_opened += 1;
        let limit = zip.len().min(self.db.params.max_archive_entries as usize);
        for i in 0..limit {
            if let Ok(f) = zip.by_index(i) {
                let entry = f.name().to_string();
                for r in &self.idx.entry {
                    if r.re.is_match(&entry) {
                        sink.add(
                            r.sig,
                            RuleKind::ArchiveEntry,
                            entry.clone(),
                            self.db.signatures[r.sig].confidence,
                        );
                    }
                }
            }
        }
    }

    /// Распаковка и поиск магических строк внутри записей. Возвращает false,
    /// если архив не начался из-за бюджета или повреждён.
    fn deep_scan_archive(&mut self, path: &Path, sink: &mut MatchSink) -> bool {
        if self.deep_budget == 0 {
            return false;
        }
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut zip = match zip::ZipArchive::new(std::io::BufReader::new(file)) {
            Ok(z) => z,
            Err(_) => return false,
        };
        let Some(jar_index) = self.idx.jar_magic.clone() else {
            return true;
        };
        let limit = zip.len().min(self.db.params.max_archive_entries as usize);
        let mut consumed_total = false;
        for i in 0..limit {
            if self.deep_budget == 0 {
                consumed_total = true;
                break;
            }
            let Ok(mut f) = zip.by_index(i) else { continue };
            if f.is_dir() || !entry_worth_reading(f.name()) {
                continue;
            }
            let cap = f.size().min(MAX_ENTRY_BYTES).min(self.deep_budget as u64) as usize;
            let mut buf = vec![0u8; cap];
            let n = f.read(&mut buf).unwrap_or(0);
            self.deep_budget -= n as u64;
            self.stats.bytes_read += n as u64;
            if n == 0 {
                continue;
            }
            buf.truncate(n);
            let body = as_text(&buf);
            jar_index.collect(&body, RuleKind::ArchiveContent, sink);
        }
        if consumed_total {
            self.warnings.push(format!(
                "Бюджет глубокой проверки архивов исчерпан ({} МБ) - последние архивы проверены только по именам.",
                self.opts.deep_budget_bytes / (1024 * 1024)
            ));
        }
        true
    }

    fn commit(
        &mut self,
        sink: &MatchSink,
        name: &str,
        rel: &str,
        evidence: Evidence,
        hash: Option<String>,
    ) {
        for (sig_id, rules) in &sink.0 {
            let sig = &self.db.signatures[*sig_id];
            let mut evidence = evidence.clone();
            // Совпадение только по строке запуска - это не "файл-чит", а
            // аргумент в логе/профиле: показываем саму строку, а не файл.
            if rules.iter().all(|r| r.rule == RuleKind::LaunchLog) {
                if let Some(r) = rules.iter().find(|r| r.rule == RuleKind::LaunchLog) {
                    if let Evidence::File(file) = &evidence {
                        evidence = Evidence::LaunchLine {
                            source: file.rel_path.clone(),
                            excerpt: r.detail.clone(),
                            referenced_file: referenced_agent(&r.detail),
                        };
                    }
                }
            }
            let check_name = match &evidence {
                Evidence::LaunchLine {
                    referenced_file: Some(f),
                    ..
                } => f.clone(),
                _ => name.to_string(),
            };
            if let Some(ex) = self.db.is_excluded(&sig.family, &check_name, rel) {
                if self.suppressed.len() < MAX_SUPPRESSED {
                    self.suppressed.push(SuppressedHit {
                        sig_id: sig.id.to_string(),
                        path: rel.to_string(),
                        by: ex.describe(),
                    });
                }
                self.stats.suppressed += 1;
                continue;
            }
            if self.findings.len() >= MAX_FINDINGS {
                self.warnings
                    .push(format!("Находок больше {MAX_FINDINGS} - остальные не включены."));
                return;
            }
            let mut confidence = 0.0f32;
            for r in rules {
                confidence = combine_confidence(confidence, r.confidence.max(sig.confidence));
            }
            // Подтверждение несколькими независимыми правилами не должен
            // превращать "medium" в "critical" автоматически.
            let severity = if rules.len() >= 3 && sig.severity == Severity::Medium {
                Severity::High
            } else {
                sig.severity
            };
            if let Evidence::File(f) = &mut evidence {
                f.sha256 = hash.clone();
            }
            self.findings.push(Finding {
                sig_id: sig.id.to_string(),
                family: sig.family.clone(),
                kind: sig.kind,
                severity,
                rules: rules.clone(),
                confidence,
                weight: sig.weight,
                explain: sig.explain.clone(),
                verify: sig.verify.clone(),
                evidence,
            });
        }
    }

    fn note_inventory(&mut self, rel: &str, name: &str, meta: &std::fs::Metadata) {
        if self.mods.len() >= MAX_INVENTORY {
            return;
        }
        let rel_lower = rel.to_ascii_lowercase();
        let entry = InventoryEntry {
            name: name.to_string(),
            rel_path: rel.to_string(),
            size_bytes: meta.len(),
            sha256: None,
        };
        if rel_lower.contains("/mods/") || rel_lower.starts_with("mods/") {
            if let Some(existing) = self
                .findings
                .iter()
                .find(|f| f.location().eq_ignore_ascii_case(rel))
                .and_then(|f| match &f.evidence {
                    Evidence::File(file) => file.sha256.clone(),
                    _ => None,
                })
            {
                let mut e = entry;
                e.sha256 = Some(existing);
                self.mods.push(e);
            } else {
                self.mods.push(entry);
            }
        } else if rel_lower.starts_with("resourcepacks/") || rel_lower.contains("/resourcepacks/")
        {
            self.packs.push(entry);
        }
    }

    fn note_version_json(&mut self, rel: &str) {
        if let Some(rest) = rel.strip_prefix("versions/") {
            if rest.matches('/').count() == 1 && rest.ends_with(".json") {
                if let Some(v) = rest.split('/').next() {
                    self.mc_versions.insert(v.to_string());
                }
            }
        }
    }

    fn note_env_from_log(&mut self, body: &str) {
        if self.env.java_from_log.is_none() {
            if let Some(m) = Regex::new(r"(?im)^.*\bJava:\s*([0-9][^\r\n]{0,40})").ok().and_then(|r| r.captures(body).and_then(|c| c.get(1).map(|x| x.as_str().trim().to_string()))) {
                self.env.java_from_log = Some(m);
            }
        }
        if self.env.loader_from_log.is_none() {
            for (marker, nice) in [
                ("fabricloader", "Fabric"),
                ("quiltmc", "Quilt"),
                ("neoforge", "NeoForge"),
                ("minecraftforge", "Forge"),
                ("optifine", "OptiFine"),
                ("lunar client", "Lunar Client"),
                ("badlion", "Badlion"),
                ("meteorclient", "Fabric"),
                ("wurstclient", "Wurst"),
            ] {
                if body.to_ascii_lowercase().contains(marker) {
                    self.env.loader_from_log = Some(nice.to_string());
                    break;
                }
            }
        }
        if self.env.nick_from_launch.is_none() {
            if let Some(v) = body
                .split("--username=")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_'))
            {
                self.env.nick_from_launch = Some(v.chars().take(16).collect());
            }
        }
    }

    fn finalize(&mut self, started: Instant, started_at: String) -> ScanResult {
        self.env.mc_versions = {
            let mut v: Vec<String> = self.mc_versions.iter().cloned().collect();
            v.sort();
            v
        };
        if self.budget_hash_skipped > 0 {
            self.warnings.push(format!(
                "Хэш не вычислен для {} файлов: исчерпан бюджет хэширования {} МБ.",
                self.budget_hash_skipped,
                self.opts.hash_budget_bytes / (1024 * 1024)
            ));
        }

        let families = summarize_families(&self.findings);
        let score = scored_total(&self.findings);
        let max_conf = self
            .findings
            .iter()
            .map(|f| f.confidence)
            .fold(0.0f32, f32::max);
        let critical = self
            .findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.confidence >= 0.85);

        let verdict = if self.opts.roots.is_empty() || self.stats.aborted && self.findings.is_empty()
        {
            Verdict::NoData
        } else if (score >= 80 && (self.findings.len() >= 2 || max_conf >= 0.9)) || critical {
            Verdict::HighRisk
        } else if score >= 30 {
            Verdict::Suspicious
        } else if score >= 6 {
            Verdict::LowSignal
        } else {
            Verdict::Clean
        };

        self.stats.duration_ms = started.elapsed().as_millis() as u64;
        ScanResult {
            findings: std::mem::take(&mut self.findings),
            families,
            suppressed: std::mem::take(&mut self.suppressed),
            mods: std::mem::take(&mut self.mods),
            resource_packs: std::mem::take(&mut self.packs),
            environment: self.env.clone(),
            stats: self.stats.clone(),
            score,
            verdict,
            db_sources: self.db.sources.clone(),
            db_version: self.db.version.clone(),
            db_warnings: self.db.warnings.clone(),
            started_at,
            warnings: std::mem::take(&mut self.warnings),
        }
    }
}

/// Итоговый балл: по каждому семейству считаем три самых тяжёлых признака
/// полностью, остальные - четвертью. Иначе 40 совпадений в одном мусорном
/// каталоге не должны выглядеть как гарантированный бан.
fn scored_total(findings: &[Finding]) -> u32 {
    let mut by_family: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for f in findings {
        by_family
            .entry(f.family.to_ascii_lowercase())
            .or_default()
            .push(f.effective_weight());
    }
    by_family
        .values_mut()
        .map(|list| {
            list.sort_unstable_by(|a, b| b.cmp(a));
            let top: u32 = list.iter().take(3).sum();
            let rest: u32 = list.iter().skip(3).map(|w| w / 4).sum();
            top + rest
        })
        .sum()
}

fn summarize_families(findings: &[Finding]) -> Vec<FamilySummary> {
    let mut by_family: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_family.entry(f.family.clone()).or_default().push(f);
    }
    let mut out: Vec<FamilySummary> = by_family
        .into_iter()
        .map(|(family, list)| {
            let distinct = list
                .iter()
                .map(|f| f.location().to_ascii_lowercase())
                .collect::<HashSet<_>>()
                .len();
            let owned: Vec<Finding> = list.iter().map(|f| (*f).clone()).collect();
            FamilySummary {
                kind: list[0].kind,
                family: family.clone(),
                severity: list.iter().map(|f| f.severity).max().unwrap_or(Severity::Info),
                findings: list.len(),
                distinct_files: distinct,
                corroborated: distinct >= 2,
                score: scored_total(&owned),
                max_confidence: list.iter().map(|f| f.confidence).fold(0.0f32, f32::max),
            }
        })
        .collect();
    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.family.cmp(&b.family)));
    out
}

/// Поиск по находкам: одна строка фильтра плюс фильтр по уровню и типу.
pub fn query<'f>(findings: &'f [Finding], text: &str, min: Severity) -> Vec<&'f Finding> {
    let needle = text.trim().to_ascii_lowercase();
    findings
        .iter()
        .filter(|f| f.severity >= min)
        .filter(|f| {
            needle.is_empty()
                || [
                    &f.family,
                    &f.sig_id,
                    &f.location(),
                    &f.explain,
                    &f.verify,
                    f.kind.ru(),
                    f.severity.ru(),
                ]
                .iter()
                .any(|s| s.to_ascii_lowercase().contains(&needle))
                || f.rules
                    .iter()
                    .any(|r| r.detail.to_ascii_lowercase().contains(&needle))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::referenced_agent;

    #[test]
    fn agent_name_strips_options_and_dirs() {
        assert_eq!(
            referenced_agent("-javaagent:C:/mc/mods/meteor-client-0.5.9.jar=bootstrap").as_deref(),
            Some("meteor-client-0.5.9.jar")
        );
        assert_eq!(
            referenced_agent("-javaagent:libs/fabric-loader-0.16.9.jar").as_deref(),
            Some("fabric-loader-0.16.9.jar")
        );
        assert_eq!(referenced_agent("-Xmx2G"), None);
    }
}
