mod cli;
mod ui;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(
        args.first().map(String::as_str),
        Some("--sync-session" | "session-sync" | "__session-sync")
    ) {
        if let Ok(paths) = cli::detect_paths() {
            cli::sync_session_quiet(&paths);
        }
        std::process::exit(0);
    }

    if args.is_empty() {
        if agy_tui::is_tty(0) && agy_tui::is_tty(1) {
            match cli::detect_paths() {
                Ok(paths) => {
                    std::process::exit(ui::run_interactive(paths));
                }
                Err(err) => {
                    eprintln!("agy-swap-rs: {err}");
                    std::process::exit(1);
                }
            }
        }
        eprintln!(
            "agy-swap-rs: error: --use-account=<slot|alias|email> is required in non-interactive CLI mode (no default account is used)."
        );
        std::process::exit(2);
    }

    if let Some(code) = cli::try_run_isolated_wrapper(&args) {
        std::process::exit(code);
    }

    std::process::exit(cli::run(&args));
}
