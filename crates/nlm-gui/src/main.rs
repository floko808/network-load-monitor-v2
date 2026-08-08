//! Desktop front end.
//!
//! The window is deliberately a thin shell over `nlm-core`: it owns widget
//! state and nothing else. Classification, statistics and table layout all
//! come from the shared engine, so the desktop and terminal views cannot
//! disagree about what a capture contains.
//!
//! The interface is rasterised on the CPU, so the program depends on no
//! graphics driver and runs unchanged in a virtual machine.

// No console window on Windows; this is a GUI binary.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod filter_popup;

use egui_software_backend::SoftwareBackendAppConfiguration;
use nlm_core::consts::{SOFTWARE_NAME, VERSION};

fn main() -> std::process::ExitCode {
    install_panic_dialog();

    let settings = SoftwareBackendAppConfiguration::new()
        .inner_size(Some(egui::vec2(1480.0, 620.0)))
        .title(Some(format!("{SOFTWARE_NAME} {VERSION}")));

    match egui_software_backend::run_app_with_software_backend(settings, app::MonitorApp::new) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // Returning the error from `main` would print it to stderr, which
            // a GUI-subsystem binary does not have — the window would simply
            // never appear, with nothing to explain why.
            eprintln!("{SOFTWARE_NAME}: {e}");
            show_error(&format!(
                "{SOFTWARE_NAME} could not open its window.\n\n{e}\n\n\
                 The window is drawn entirely on the CPU, so this is not a \
                 graphics-driver problem. The command-line build \
                 (network-monitor) offers the same capture and analysis."
            ));
            std::process::ExitCode::FAILURE
        }
    }
}

/// Show panics in a dialog rather than losing them.
///
/// The Windows build is linked as a GUI subsystem binary, so it has no
/// console and no stderr for the default panic handler to write to. Without
/// this, a crash would simply make the window vanish with no explanation.
fn install_panic_dialog() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default(info);
        show_error(&format!(
            "{SOFTWARE_NAME} hit an unexpected error and must close.\n\n{info}"
        ));
    }));
}

fn show_error(message: &str) {
    rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Error)
        .set_title("Could not start")
        .set_description(message)
        .show();
}
