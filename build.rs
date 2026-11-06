fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/icon.ico");
    res.set("ProductName", "Sunrise Worlds Cheats Checker");
    res.set("FileDescription", "Локальная проверка папок игры на признаки читов");
    res.set("LegalCopyright", "© Sunrise Worlds");
    if let Err(err) = res.compile() {
        println!("cargo:warning=иконку в .exe встроить не вышло: {err}");
    }
}
