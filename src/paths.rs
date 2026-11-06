use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Найденная корневая папка игры. Всё, что сканирует swcc, ограничено такими
/// корнями: наружу (домашний каталог, диск целиком) обход не выходит.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameRoot {
    pub label: String,
    pub path: String,
    pub kind: RootKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    /// %APPDATA%\.minecraft и аналоги
    Standard,
    /// Instance отдельного лаунчера (Prism, MultiMC, HMCL, TLauncher, PCL)
    LauncherInstance,
    /// Папку выбрал сам игрок
    Manual,
    /// Корень диска в режиме проверки всего компьютера
    Drive,
}

impl RootKind {
    pub fn ru(self) -> &'static str {
        match self {
            RootKind::Standard => "стандартная",
            RootKind::LauncherInstance => "инстанс лаунчера",
            RootKind::Manual => "папка игры выбрана вручную",
            RootKind::Drive => "обход по метаданным",
        }
    }

    /// true - это игровая папка: в ней можно читать содержимое файлов.
    pub fn is_game(self) -> bool {
        !matches!(self, RootKind::Drive)
    }
}

/// Признак игровой папки: у ванильного и почти всех сторонних лаунчеров есть
/// каталог versions с сборками.
pub fn looks_like_game_root(path: &Path) -> bool {
    if !path.is_dir() {
        return false;
    }
    path.join("versions").is_dir()
        || path.join("launcher_profiles.json").is_file()
        || (path.join("logs").is_dir() && path.join("assetIndex").is_dir())
}

fn env_dir(key: &str) -> Option<PathBuf> {
    std::env::var_os(key).map(PathBuf::from).filter(|p| p.is_dir())
}

/// Путь для показа человеку. `canonicalize` на Windows добавляет префикс
/// `\\?\`, который нужен для длинных путей при обходе, но в отчёте и в окне
/// только шумит: обход идёт по исходному `GameRoot.path`, а тут мы его снимаем.
pub fn shown_path(path: &str) -> String {
    path.strip_prefix(r"\\?\").unwrap_or(path).to_string()
}

/// Кандидаты, где лаунчеры держат игровые папки. Перечисляем только по одному
/// уровню вглубь: полный обход домашнего каталога не делаем никогда.
fn candidate_bases() -> Vec<(PathBuf, &'static str)> {
    let mut out: Vec<(PathBuf, &'static str)> = Vec::new();
    let mut push = |p: Option<PathBuf>, tag: &'static str| {
        if let Some(p) = p {
            out.push((p, tag));
        }
    };

    let roaming = env_dir("APPDATA");
    let local = env_dir("LOCALAPPDATA");
    let home = env_dir("USERPROFILE");

    push(roaming.as_ref().map(|p| p.join(".minecraft")), "Minecraft");
    push(local.as_ref().map(|p| p.join("minecraft")), "Minecraft (Store)");
    push(home.as_ref().map(|p| p.join(".minecraft")), "Minecraft");

    for launcher in [
        "PrismLauncher/instances",
        "MultiMC/instances",
        "ATLauncher/instances",
        "TLauncher/.minecraft",
        "TLauncher/instances",
        "curseforge/minecraft",
        "modrinth-app/instances",
        "PCL",
        "PCL/.minecraft",
        "Hello Minecraft! Launcher",
        ".hmcl",
        "vaeo/instances",
        "Adrenalin",
    ] {
        if let Some(p) = roaming.as_ref().map(|r| r.join(launcher)) {
            out.push((p, "instance root"));
        }
    }
    out.retain(|(p, _)| p.is_dir());
    out
}

fn label_for(base: &Path, tag: &str) -> String {
    let name = base
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match tag {
        "Minecraft" | "Minecraft (Store)" => tag.to_string(),
        _ => {
            let owner = base
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name.eq_ignore_ascii_case(".minecraft") {
                format!("{tag}: .minecraft ({owner})")
            } else {
                format!("{tag}: {name}")
            }
        }
    }
}

/// Один уровень вглубь от кандидата: там лежат инстансы лаунчеров.
fn shallow_children(base: &Path, limit: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(read) = std::fs::read_dir(base) {
        for entry in read.flatten().take(limit) {
            let path = entry.path();
            if path.is_dir() {
                out.push(path);
            }
        }
    }
    out
}

/// Корни для обхода дисков: локальные диски. Обход идёт только по
/// именам и атрибутам - содержимое вне игровых папок мы не читаем (см. scanner).
pub fn computer_roots() -> Vec<GameRoot> {
    let mut out = Vec::new();
    for (i, path) in drive_paths().into_iter().enumerate() {
        let letter = path.chars().next().unwrap_or('?').to_ascii_uppercase();
        out.push(GameRoot {
            label: format!(
                "Диск {letter} ({})",
                if i == 0 { "системный" } else { "локальный" }
            ),
            path,
            kind: RootKind::Drive,
        });
    }
    out
}

/// Буквы доступных дисков. Сначала дешёвый трюк с корнем объектного пространства
/// Windows, потом - проверка букв A..Z (сетевые диски могут не появиться в первом).
fn drive_paths() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/") {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            let b = n.as_bytes();
            if b.len() == 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
                out.push(format!("{n}/"));
            }
        }
    }
    if out.is_empty() {
        for c in 'A'..='Z' {
            let p = format!("{c}:/");
            if Path::new(&p).is_dir() {
                out.push(p);
            }
        }
    }
    if out.is_empty() {
        out.push("/".into());
    }
    out
}

pub fn discover_roots() -> Vec<GameRoot> {
    let mut seen = BTreeSet::new();
    let mut roots = Vec::new();

    for (base, tag) in candidate_bases() {
        let canonical = base.canonicalize().unwrap_or_else(|_| base.clone());
        if looks_like_game_root(&canonical) {
            let key = canonical.to_string_lossy().to_lowercase();
            if seen.insert(key) {
                roots.push(GameRoot {
                    label: label_for(&canonical, tag),
                    path: canonical.to_string_lossy().into_owned(),
                    kind: if tag == "instance root" {
                        RootKind::LauncherInstance
                    } else {
                        RootKind::Standard
                    },
                });
            }
        }
        // Инстансы: <base>/<имя>/.minecraft или <base>/<имя>
        for child in shallow_children(&canonical, 60) {
            for candidate in [child.clone(), child.join(".minecraft")] {
                if looks_like_game_root(&candidate) {
                    let canonical_child =
                        candidate.canonicalize().unwrap_or_else(|_| candidate.clone());
                    let key = canonical_child.to_string_lossy().to_lowercase();
                    if seen.insert(key) {
                        roots.push(GameRoot {
                            label: label_for(&canonical_child, tag),
                            path: canonical_child.to_string_lossy().into_owned(),
                            kind: RootKind::LauncherInstance,
                        });
                    }
                }
            }
        }
    }
    roots
}

/// Игровая папка - та, где есть признаки Minecraft: её обходят с чтением
/// содержимого. Всё остальное (выбранная вручную папка без признаков игры,
/// корень диска, домашний каталог) - только имена, размеры и даты.
pub fn is_wide_root(path: &Path) -> bool {
    path.parent().is_none() || !looks_like_game_root(path)
}

/// Домашний каталог игрока: как и корень диска, обходится только по метаданным.
fn home_dir() -> Option<PathBuf> {
    env_dir("USERPROFILE").map(|h| h.canonicalize().unwrap_or(h))
}

pub fn accept_manual_root(path: &Path) -> Result<GameRoot, String> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !canonical.is_dir() {
        return Err("Это не каталог: нужно выбрать папку, а не файл.".into());
    }
    let wide = is_wide_root(&canonical)
        || home_dir().is_some_and(|h| h == canonical);
    let name = canonical
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| canonical.to_string_lossy().into_owned());
    Ok(GameRoot {
        label: if wide {
            format!("Папка целиком: {name}")
        } else {
            format!("Папка игры: {name}")
        },
        path: canonical.to_string_lossy().into_owned(),
        kind: if wide { RootKind::Drive } else { RootKind::Manual },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn game_root_marker_recognises_versions() {
        let dir = std::env::temp_dir().join(format!("swcc-root-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("versions")).unwrap();
        assert!(looks_like_game_root(&dir));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn random_folder_is_accepted_as_metadata_only() {
        let dir = std::env::temp_dir().join(format!("swcc-plain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = accept_manual_root(&dir).expect("любую папку можно добавить");
        assert!(!root.kind.is_game(), "папка без признаков игры читается только по метаданным");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn game_folder_is_accepted_for_full_read() {
        let dir = std::env::temp_dir().join(format!("swcc-game-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("versions")).unwrap();
        let root = accept_manual_root(&dir).expect("папку игры можно добавить");
        assert!(root.kind.is_game());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn discovery_never_returns_drive_root() {
        for root in discover_roots() {
            let p = Path::new(&root.path);
            assert!(p.parent().is_some(), "слишком широкий корень: {}", root.path);
            assert!(looks_like_game_root(p));
        }
    }
}
