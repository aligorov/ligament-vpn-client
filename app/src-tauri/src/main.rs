// Точка входа десктоп-приложения (не используется на mobile).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    corpvpn_app::run()
}
