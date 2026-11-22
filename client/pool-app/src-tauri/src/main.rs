// Prevents an extra console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Vouch Compute: Tauri 2 shell. Holds no keys and runs no jobs: everything goes through pool-core's local
//! control channel (`core_client`). Wallet is display-only: linking happens in the server's web flow,
//! opened in the browser. Earnings views show server snapshots only.

mod core_client;
mod i18n;
#[cfg(test)]
mod ipc_review;
mod links;
mod update_policy;
mod updater;

use serde_json::Value;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::Wry;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WindowEvent};
use tauri_plugin_opener::OpenerExt;

/// Proxy an allow-listed request to the agent.
#[tauri::command]
async fn core(method: String, params: Option<Value>) -> Result<Value, String> {
    if !core_client::ALLOWED.contains(&method.as_str()) {
        return Err(i18n::tv("error.methodNotAllowed", &[("method", &method)]));
    }
    core_client::call(&method, params.unwrap_or(Value::Null)).await
}

#[tauri::command]
async fn ensure_core() -> Result<(), String> {
    core_client::ensure_running().await
}

/// Open one of a fixed set of links in the browser. URLs come from the agent's config (account-server/web base
/// URLs), never from the page, so the page cannot open arbitrary URLs.
#[tauri::command]
async fn open_link(app: AppHandle, kind: String) -> Result<(), String> {
    let url = match kind.as_str() {
        "signin" => {
            let s = core_client::call("signin.status", Value::Null).await?;
            s.get("verification_uri_complete").and_then(Value::as_str).map(String::from).ok_or_else(|| i18n::t("error.noSignin"))?
        }
        "wallet" | "dashboard" | "earn" | "trust" | "devices" | "recover" | "verify" => {
            let s = core_client::call("status", Value::Null).await?;
            s.pointer(&format!("/links/{kind}")).and_then(Value::as_str).map(String::from).ok_or_else(|| i18n::t("error.linkUnavailable"))?
        }
        _ => return Err(i18n::t("error.unknownLink")),
    };
    // Parsed check (the old prefix check accepted http://127.0.0.1.evil.example/); plain http only in dev builds
    let url = links::check(&url, updater::CHANNEL == updater::Channel::Dev)?;
    app.opener().open_url(url, None::<&str>).map_err(|e| e.to_string())
}

/// The app's build channel: dev builds show a permanent "DEV BUILD" marker.
#[tauri::command]
fn build_info() -> Value {
    updater::info()
}

#[tauri::command]
async fn check_update(app: AppHandle) -> Result<Value, String> {
    updater::check(&app).await
}

#[tauri::command]
async fn install_update(app: AppHandle) -> Result<(), String> {
    updater::install(&app).await
}

/// Whether the app starts when the user signs in to the computer (per-user login item: the HKCU `Run` key on
/// Windows, a LaunchAgent on macOS). It starts in the tray (`--background`), visible there, never hidden.
#[tauri::command]
fn autostart_get(app: AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

#[tauri::command]
fn autostart_set(app: AppHandle, enabled: bool) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    let a = app.autolaunch();
    if enabled { a.enable() } else { a.disable() }.map_err(|e| e.to_string())?;
    a.is_enabled().map_err(|e| e.to_string())
}

/// The page's language for native strings (tray menu, window title, errors). Anything outside the registry is English;
/// returns the registry code in use.
#[tauri::command]
fn set_locale(app: AppHandle, locale: String) -> String {
    let code = i18n::set(&locale);
    relabel(&app);
    code.to_string()
}

/// The UI's messages for a language, as JSON text (English for anything outside the registry). Embedded in the app,
/// so the page needs no fetch permission in its CSP.
#[tauri::command]
fn i18n_messages(locale: String) -> String {
    i18n::ui_messages(&locale).to_string()
}

/// The tray menu items, kept so they can be relabelled when the language changes.
struct TrayItems {
    open: MenuItem<Wry>,
    pause: MenuItem<Wry>,
    resume: MenuItem<Wry>,
    quit: MenuItem<Wry>,
}

fn dev_build() -> bool {
    updater::CHANNEL == updater::Channel::Dev
}

fn relabel(app: &AppHandle) {
    if let Some(items) = app.try_state::<TrayItems>() {
        let _ = items.open.set_text(i18n::t("tray.open"));
        let _ = items.pause.set_text(i18n::t("tray.pause"));
        let _ = items.resume.set_text(i18n::t("tray.resume"));
        let _ = items.quit.set_text(i18n::t("tray.quit"));
    }
    if let Some(tray) = app.tray_by_id("vouchcompute") {
        let _ = tray.set_tooltip(Some(i18n::t(if dev_build() { "tray.tooltipDev" } else { "tray.tooltip" })));
    }
    if dev_build() {
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.set_title(&i18n::t("window.titleDev"));
        }
    }
}

/// Started by the login item: stay in the tray instead of opening the window.
const BACKGROUND_ARG: &str = "--background";

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, Some(vec![BACKGROUND_ARG])))
        .invoke_handler(tauri::generate_handler![
            core,
            ensure_core,
            open_link,
            build_info,
            check_update,
            install_update,
            autostart_get,
            autostart_set,
            set_locale,
            i18n_messages
        ])
        .setup(|app| {
            // the window starts hidden (tauri.conf.json); show it unless the login item started the app
            if !std::env::args().any(|a| a == BACKGROUND_ARG) {
                show_main(app.handle());
            }
            // English until the page reports its language (set_locale, called as soon as the page has loaded)
            let open = MenuItem::with_id(app, "open", i18n::t("tray.open"), true, None::<&str>)?;
            let pause = MenuItem::with_id(app, "pause", i18n::t("tray.pause"), true, None::<&str>)?;
            let resume = MenuItem::with_id(app, "resume", i18n::t("tray.resume"), true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", i18n::t("tray.quit"), true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let menu = Menu::with_items(app, &[&open, &pause, &resume, &sep, &quit])?;
            let dev = dev_build();
            if dev {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.set_title(&i18n::t("window.titleDev"));
                }
            }
            app.manage(TrayItems { open, pause, resume, quit });
            TrayIconBuilder::with_id("vouchcompute")
                .icon(app.default_window_icon().cloned().ok_or("no icon")?)
                .tooltip(i18n::t(if dev { "tray.tooltipDev" } else { "tray.tooltip" }))
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, ev| match ev.id().as_ref() {
                    "open" => show_main(app),
                    "pause" => {
                        tauri::async_runtime::spawn(core_client::call("pause", serde_json::json!({ "minutes": 60 })));
                    }
                    "resume" => {
                        tauri::async_runtime::spawn(core_client::call("resume", Value::Null));
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, ev| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;
            tauri::async_runtime::spawn(async {
                if let Err(e) = core_client::ensure_running().await {
                    eprintln!("agent: {e}");
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps the agent running and the tray icon visible (never hidden work).
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running Vouch Compute");
}
