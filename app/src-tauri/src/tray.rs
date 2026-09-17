// Трей: серый/жёлтый/зелёный статусы, меню подключения, клик — показать окно.
// Иконки вшиты в бинарник (include_bytes!) — не зависят от ресурс-директорий.
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager,
};

const ICON_GRAY: &[u8] = include_bytes!("../icons/tray-gray.png");
const ICON_YELLOW: &[u8] = include_bytes!("../icons/tray-yellow.png");
const ICON_GREEN: &[u8] = include_bytes!("../icons/tray-green.png");

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrayStatus {
    Disconnected,
    Connecting,
    Connected,
}

impl TrayStatus {
    fn icon(self) -> &'static [u8] {
        match self {
            TrayStatus::Disconnected => ICON_GRAY,
            TrayStatus::Connecting => ICON_YELLOW,
            TrayStatus::Connected => ICON_GREEN,
        }
    }

    fn tooltip(self) -> &'static str {
        match self {
            TrayStatus::Disconnected => "CorpVPN: Отключено",
            TrayStatus::Connecting => "CorpVPN: Подключение…",
            TrayStatus::Connected => "CorpVPN: Подключено",
        }
    }
}

/// PNG-байты → RGBA-иконка Tauri (декод через крейт `image`).
fn icon_from_png(bytes: &'static [u8]) -> tauri::Result<tauri::image::Image<'static>> {
    let img = image::load_from_memory(bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("PNG: {e}")))
        .map_err(tauri::Error::InvalidIcon)?;
    let (w, h) = (img.width(), img.height());
    Ok(tauri::image::Image::new_owned(img.into_rgba8().into_raw(), w, h))
}

pub fn build_tray(app: &AppHandle) -> tauri::Result<TrayIcon> {
    let connect = MenuItem::with_id(app, "connect", "Подключить", true, None::<&str>)?;
    let disconnect = MenuItem::with_id(app, "disconnect", "Отключить", true, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Открыть Ligament VPN", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&connect, &disconnect, &show, &quit])?;

    let icon = icon_from_png(ICON_GRAY)?;
    let tray = TrayIconBuilder::with_id("main")
        .icon(icon)
        .tooltip(TrayStatus::Disconnected.tooltip())
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "connect" => {
                tauri::async_runtime::spawn(async move {
                    // Подключаем активный/первый профиль
                    if let Ok(v) =
                        crate::transport::rpc_envelope("corpvpn.profiles.list", None).await
                    {
                        if let Ok(listing) = serde_json::from_str::<serde_json::Value>(&v) {
                            let pid = listing
                                .get("result")
                                .and_then(|r| r.get("profiles"))
                                .and_then(|p| p.as_array())
                                .and_then(|a| a.first())
                                .and_then(|p| p.get("id"))
                                .and_then(|i| i.as_str())
                                .map(str::to_owned);
                            let pid = match pid {
                                Some(p) => p,
                                None => return,
                            };
                            let _ = crate::transport::rpc_envelope(
                                "corpvpn.connect",
                                Some(serde_json::json!({ "profileId": pid })),
                            )
                            .await;
                        }
                    }
                });
            }
            "disconnect" => {
                tauri::async_runtime::spawn(async move {
                    let _ = crate::transport::rpc_envelope("corpvpn.disconnect", None).await;
                });
            }
            "show" => show_main(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(tray)
}

fn show_main(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

/// Обновление иконки/тултипа трея при смене статуса.
pub fn set_tray_status(app: &AppHandle, status: &str) {
    let Some(tray) = app.tray_by_id("main") else {
        return;
    };
    let st = match status {
        "connected" => TrayStatus::Connected,
        "connecting" | "disconnecting" => TrayStatus::Connecting,
        _ => TrayStatus::Disconnected,
    };
    if let Ok(img) = icon_from_png(st.icon()) {
        let _ = tray.set_icon(Some(img));
    }
    let _ = tray.set_tooltip(Some(st.tooltip()));
}
