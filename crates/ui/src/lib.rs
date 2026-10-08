pub mod commands;

use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(commands::PairState::default())
        .invoke_handler(tauri::generate_handler![
            commands::get_devices,
            commands::get_pulls,
            commands::get_sends,
            commands::accept_pull,
            commands::deny_pull,
            commands::send_files,
            commands::send_text,
            commands::remove_device,
            commands::set_name,
            commands::get_name,
            commands::import_pairing,
            commands::pair_near_start,
            commands::pair_near_confirm,
            commands::pair_near_cancel,
            commands::daemon_running,
            commands::read_pairing_file,
        ])
        .setup(|app| {
            // 托盘：显示主窗口 / 退出
            let show = MenuItem::with_id(app, "show", "显示 DeviceFabric", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            let icon = tauri::image::Image::from_bytes(include_bytes!("../icons/32x32.png"))?;
            TrayIconBuilder::with_id("dfabric-tray")
                .icon(icon)
                .tooltip("DeviceFabric")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // 关闭窗口 = 隐藏到托盘（Agent 常驻语义）
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
