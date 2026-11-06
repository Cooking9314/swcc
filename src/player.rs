/// Ник игрока. Его вводит человек перед проверкой: он попадает в отчёт и в
/// команду бана, которую админ составляет по отчёту, поэтому требования такие же,
/// как у самого Minecraft.
pub fn check_nick(raw: &str) -> Result<String, &'static str> {
    let nick = raw.trim();
    if nick.is_empty() {
        return Err("Введи ник, под которым ты заходишь на Sunrise Worlds.");
    }
    let count = nick.chars().count();
    if count < 3 {
        return Err("Ник короче 3 символов — такого аккаунта Minecraft не существует.");
    }
    if count > 16 {
        return Err("Ник длиннее 16 символов: Minecraft столько не позволяет.");
    }
    if !nick.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("В нике только латинские буквы, цифры и подчёркивание.");
    }
    Ok(nick.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_nick_passes_and_is_trimmed() {
        assert_eq!(check_nick("  Steve_93  ").unwrap(), "Steve_93");
    }

    #[test]
    fn wrong_nicks_are_rejected_with_a_reason() {
        for raw in ["", "   ", "St", "12345678901234567", "Стив", "steve x", "-steve"] {
            assert!(check_nick(raw).is_err(), "ник {raw:?} не должен проходить");
        }
    }
}
