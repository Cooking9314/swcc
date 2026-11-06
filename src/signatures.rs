use std::borrow::Cow;
use std::path::Path;

use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

pub const DEFAULT_DB_TOML: &str = include_str!("../signatures/default.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn ru(self) -> &'static str {
        match self {
            Severity::Info => "информация",
            Severity::Low => "низкая",
            Severity::Medium => "средняя",
            Severity::High => "высокая",
            Severity::Critical => "критическая",
        }
    }

    pub fn weight(self) -> u32 {
        match self {
            Severity::Info => 1,
            Severity::Low => 4,
            Severity::Medium => 12,
            Severity::High => 30,
            Severity::Critical => 55,
        }
    }

    fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" | "crit" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "med" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    CheatClient,
    Autoclicker,
    Xray,
    Macro,
    Injection,
    CrackedLauncher,
    GreyHelper,
    ConfigLeftover,
    Other,
}

impl Kind {
    pub fn ru(self) -> &'static str {
        match self {
            Kind::CheatClient => "чит-клиент",
            Kind::Autoclicker => "автокликер",
            Kind::Xray => "x-ray",
            Kind::Macro => "макрос",
            Kind::Injection => "инъекция/агент",
            Kind::CrackedLauncher => "обход лицензии",
            Kind::GreyHelper => "серый помощник",
            Kind::ConfigLeftover => "остаточный конфиг",
            Kind::Other => "прочее",
        }
    }

    fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "cheat_client" => Kind::CheatClient,
            "autoclicker" => Kind::Autoclicker,
            "xray" => Kind::Xray,
            "macro" => Kind::Macro,
            "injection" => Kind::Injection,
            "cracked_launcher" => Kind::CrackedLauncher,
            "grey_helper" => Kind::GreyHelper,
            "config_leftover" => Kind::ConfigLeftover,
            _ => Kind::Other,
        }
    }
}

/// Настройки обхода, читаются из `[scan]` базы сигнатур.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanParams {
    pub skip_dir_names: Vec<String>,
    pub skip_path_regex: Vec<String>,
    pub max_walk_files: u64,
    pub max_content_bytes: u64,
    pub max_archive_scan_bytes: u64,
    pub max_archive_entries: u64,
    pub max_text_bytes: u64,
}

impl Default for ScanParams {
    fn default() -> Self {
        Self {
            skip_dir_names: vec![
                "assets".into(),
                "libraries".into(),
                "runtime".into(),
                "bin".into(),
                "web".into(),
            ],
            skip_path_regex: vec![],
            max_walk_files: 250_000,
            max_content_bytes: 33_554_432,
            max_archive_scan_bytes: 25_165_824,
            max_archive_entries: 4_000,
            max_text_bytes: 2_097_152,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct RawSignature {
    id: String,
    #[serde(default)]
    family: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    severity: String,
    #[serde(default = "one")]
    confidence: f32,
    #[serde(default)]
    weight: u32,
    #[serde(default)]
    explain: String,
    #[serde(default)]
    verify: String,
    #[serde(default)]
    name_regex: Option<String>,
    #[serde(default)]
    path_regex: Option<String>,
    #[serde(default)]
    dir_regex: Option<String>,
    #[serde(default)]
    content_magic: Vec<String>,
    #[serde(default)]
    jar_entry_regex: Option<String>,
    #[serde(default)]
    jar_content_magic: Vec<String>,
    #[serde(default)]
    text_regex: Option<String>,
    #[serde(default)]
    log_regex: Option<String>,
    #[serde(default)]
    sha256: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawExclude {
    id: String,
    #[serde(default)]
    family: Option<String>,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    name_regex: Option<String>,
    #[serde(default)]
    path_regex: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawDb {
    #[serde(default)]
    meta: RawMeta,
    #[serde(default)]
    scan: ScanParams,
    #[serde(default)]
    signature: Vec<RawSignature>,
    #[serde(default)]
    exclude: Vec<RawExclude>,
}

#[derive(Debug, Deserialize, Default)]
struct RawMeta {
    #[serde(default)]
    version: String,
}

fn one() -> f32 {
    1.0
}

/// Как именно сработало правило - попадает в отчёт, чтобы админ видел причину.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleKind {
    FileName,
    FilePath,
    Directory,
    RawBytes,
    ArchiveEntry,
    ArchiveContent,
    TextContent,
    LaunchLog,
    KnownHash,
}

impl RuleKind {
    pub fn ru(self) -> &'static str {
        match self {
            RuleKind::FileName => "имя файла",
            RuleKind::FilePath => "путь файла",
            RuleKind::Directory => "каталог",
            RuleKind::RawBytes => "строка в байтах файла",
            RuleKind::ArchiveEntry => "запись внутри архива",
            RuleKind::ArchiveContent => "содержимое архива",
            RuleKind::TextContent => "содержимое текста",
            RuleKind::LaunchLog => "лог запуска",
            RuleKind::KnownHash => "совпал известный хэш",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub id: Cow<'static, str>,
    pub family: String,
    pub kind: Kind,
    pub severity: Severity,
    pub confidence: f32,
    pub weight: u32,
    pub explain: String,
    pub verify: String,
    name: Option<Regex>,
    path: Option<Regex>,
    dir: Option<Regex>,
    content: Vec<String>,
    entry: Option<Regex>,
    jar_content: Vec<String>,
    text: Option<Regex>,
    log: Option<Regex>,
    hashes: Vec<String>,
}

impl Signature {
    fn compile(raw: RawSignature) -> Result<Self> {
        let sid = raw.id.clone();
        let build = |p: &str| -> Result<Regex> {
            RegexBuilder::new(p)
                .case_insensitive(true)
                .build()
                .with_context(|| format!("некомпилируемый regex в сигнатуре {sid}: {p}"))
        };
        let family = if raw.family.is_empty() { sid.clone() } else { raw.family.clone() };
        Ok(Signature {
            id: raw.id.into(),
            family,
            kind: Kind::parse(&raw.kind),
            severity: Severity::parse(&raw.severity),
            confidence: raw.confidence.clamp(0.0, 1.0),
            weight: if raw.weight == 0 {
                Severity::parse(&raw.severity).weight()
            } else {
                raw.weight
            },
            explain: raw.explain.clone(),
            verify: raw.verify.clone(),
            name: raw.name_regex.as_deref().map(&build).transpose()?,
            path: raw.path_regex.as_deref().map(&build).transpose()?,
            dir: raw.dir_regex.as_deref().map(&build).transpose()?,
            content: raw.content_magic.iter().map(|m| m.to_lowercase()).collect(),
            entry: raw.jar_entry_regex.as_deref().map(&build).transpose()?,
            jar_content: raw.jar_content_magic.iter().map(|m| m.to_lowercase()).collect(),
            text: raw.text_regex.as_deref().map(&build).transpose()?,
            log: raw.log_regex.as_deref().map(&build).transpose()?,
            hashes: raw.sha256.iter().map(|h| h.to_lowercase()).collect(),
        })
    }

    pub fn name_re(&self) -> Option<&Regex> {
        self.name.as_ref()
    }
    pub fn path_re(&self) -> Option<&Regex> {
        self.path.as_ref()
    }
    pub fn dir_re(&self) -> Option<&Regex> {
        self.dir.as_ref()
    }
    pub fn entry_re(&self) -> Option<&Regex> {
        self.entry.as_ref()
    }
    pub fn text_re(&self) -> Option<&Regex> {
        self.text.as_ref()
    }
    pub fn log_re(&self) -> Option<&Regex> {
        self.log.as_ref()
    }
    pub fn hashes(&self) -> &[String] {
        &self.hashes
    }
    pub fn raw_magics(&self) -> &[String] {
        &self.content
    }
    pub fn jar_magics(&self) -> &[String] {
        &self.jar_content
    }

    /// Используется, чтобы понять, стоит ли вообще читать файл.
    pub fn needs_any_rules(&self) -> bool {
        self.name.is_some()
            || self.path.is_some()
            || self.dir.is_some()
            || self.entry.is_some()
            || self.text.is_some()
            || self.log.is_some()
            || !self.content.is_empty()
            || !self.jar_content.is_empty()
            || !self.hashes.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct Exclude {
    pub id: String,
    pub family: Option<String>,
    pub reason: String,
    name: Option<Regex>,
    path: Option<Regex>,
}

impl Exclude {
    fn compile(raw: RawExclude) -> Result<Self> {
        let sid = raw.id.clone();
        let build = |p: &str| -> Result<Regex> {
            RegexBuilder::new(p)
                .case_insensitive(true)
                .build()
                .with_context(|| format!("некомпилируемый regex в exclude {sid}: {p}"))
        };
        let family = raw.family.filter(|f| !f.is_empty());
        Ok(Exclude {
            id: raw.id,
            family,
            reason: raw.reason,
            name: raw.name_regex.as_deref().map(&build).transpose()?,
            path: raw.path_regex.as_deref().map(&build).transpose()?,
        })
    }

    pub fn suppresses(&self, family: &str, name: &str, rel: &str) -> bool {
        if let Some(f) = &self.family {
            if !f.eq_ignore_ascii_case(family) {
                return false;
            }
        }
        let hit_name = self.name.as_ref().is_some_and(|r| r.is_match(name));
        let hit_path = self.path.as_ref().is_some_and(|r| r.is_match(rel));
        hit_name || hit_path
    }

    pub fn describe(&self) -> String {
        format!("{}: {}", self.id, self.reason)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SignatureDb {
    pub version: String,
    pub signatures: Vec<Signature>,
    pub excludes: Vec<Exclude>,
    pub params: ScanParams,
    pub sources: Vec<String>,
    pub warnings: Vec<String>,
}

impl SignatureDb {
    /// Загружает встроенную базу и, если есть, `signatures/custom.toml` рядом с exe.
    /// Пользовательская база дополняет встроенную: сигнатура с тем же `id` её заменяет.
    pub fn load(extra_dir: Option<&Path>) -> Self {
        let mut db = match Self::from_toml(DEFAULT_DB_TOML, "встроенная база") {
            Ok(db) => db,
            Err(err) => {
                // Встроенная база компилируется вместе с кодом, так что сюда
                // попадёт только ошибка, найденная при разработке.
                panic!("встроенная база сигнатур повреждена: {err:?}");
            }
        };
        if db.version.is_empty() {
            db.version = "builtin".to_string();
        }
        if let Some(dir) = extra_dir {
            let path = dir.join("custom.toml");
            if path.is_file() {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                match Self::from_toml(&text, "custom.toml") {
                    Ok(custom) => db.merge(custom),
                    Err(err) => db.warnings.push(format!("custom.toml не загружен: {err:?}")),
                }
            }
        }
        db
    }

    fn from_toml(text: &str, source: &str) -> Result<Self> {
        let where_from = format!("база сигнатур «{source}»");
        let raw: RawDb = toml::from_str(text).with_context(|| where_from)?;
        let mut signatures = Vec::with_capacity(raw.signature.len());
        let mut warnings = Vec::new();
        for s in raw.signature {
            match Signature::compile(s) {
                Ok(sig) if sig.needs_any_rules() => signatures.push(sig),
                Ok(sig) => warnings.push(format!("сигнатура {} не имеет правил", sig.id)),
                Err(err) => warnings.push(format!("{err:#}")),
            }
        }
        let mut excludes = Vec::with_capacity(raw.exclude.len());
        for e in raw.exclude {
            match Exclude::compile(e) {
                Ok(ex) => excludes.push(ex),
                Err(err) => warnings.push(format!("{err:#}")),
            }
        }
        Ok(SignatureDb {
            version: raw.meta.version,
            signatures,
            excludes,
            params: raw.scan,
            sources: vec![source.to_string()],
            warnings,
        })
    }

    fn merge(&mut self, custom: SignatureDb) {
        for sig in custom.signatures {
            match self.signatures.iter_mut().position(|s| s.id == sig.id) {
                Some(i) => self.signatures[i] = sig,
                None => self.signatures.push(sig),
            }
        }
        for ex in custom.excludes {
            match self.excludes.iter_mut().position(|e| e.id == ex.id) {
                Some(i) => self.excludes[i] = ex,
                None => self.excludes.push(ex),
            }
        }
        if !custom.version.is_empty() {
            self.version = format!("{} + {}", self.version, custom.version);
        }
        self.sources.extend(custom.sources);
        self.warnings.extend(custom.warnings);
    }

    pub fn is_excluded(&self, family: &str, name: &str, rel: &str) -> Option<&Exclude> {
        self.excludes.iter().find(|e| e.suppresses(family, name, rel))
    }

    pub fn rule_count(&self) -> usize {
        self.signatures.len()
    }
}

/// Сложение независимых подтверждений: 1 - произведение (1 - c).
/// Два независимых признака по 0.7 дают 0.91, а не 1.4.
pub fn combine_confidence(a: f32, b: f32) -> f32 {
    1.0 - (1.0 - a.clamp(0.0, 1.0)) * (1.0 - b.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> SignatureDb {
        SignatureDb::from_toml(DEFAULT_DB_TOML, "test").unwrap()
    }

    #[test]
    fn default_db_compiles_without_warnings() {
        let db = db();
        assert!(
            db.warnings.is_empty(),
            "предупреждения в базе: {:?}",
            db.warnings
        );
        assert!(db.signatures.len() > 20);
    }

    #[test]
    fn meteor_jar_matches() {
        let db = db();
        let sig = db.signatures.iter().find(|s| s.id == "meteor.client").unwrap();
        let re = sig.name_re().expect("у meteor.client должно быть правило по имени");
        assert!(re.is_match("meteor-client-0.5.12.jar"));
        assert!(!re.is_match("sodium-0.5.8.jar"));
    }

    #[test]
    fn excludes_kill_false_positives() {
        let db = db();
        assert!(db.is_excluded("Java Agent", "fabric-loader-0.16.9.jar", "libs/a.jar").is_some());
        assert!(
            db.is_excluded("Autoclicker", "fabric-loader-0.16.9.jar", "mods/x.jar")
                .is_none(),
            "exclude с family не должен гасить другие семейства"
        );
    }

    #[test]
    fn confidence_combination_saturates() {
        let c = combine_confidence(0.7, 0.7);
        assert!((c - 0.91).abs() < 0.001);
        assert!(combine_confidence(1.0, 1.0) <= 1.0);
    }
}
