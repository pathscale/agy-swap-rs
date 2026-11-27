use clap::{Arg, ArgAction, Command};

fn flag(id: &'static str, long: &'static str, help: &'static str) -> Arg {
    Arg::new(id)
        .long(long)
        .action(ArgAction::SetTrue)
        .help(help)
}

fn opt(id: &'static str, long: &'static str, val: &'static str, help: &'static str) -> Arg {
    Arg::new(id)
        .long(long)
        .value_name(val)
        .num_args(1)
        .help(help)
}

fn pos(id: &'static str, val: &'static str, required: bool, help: &'static str) -> Arg {
    Arg::new(id)
        .value_name(val)
        .required(required)
        .num_args(1)
        .help(help)
}

pub fn build_cli() -> Command {
    Command::new("agy-swap-rs")
        .version(agy_core::VERSION)
        .about("Multi-account OAuth switcher and quota router for Google Antigravity CLI (agy)")
        .after_help("Isolated sessions (no default account in CLI mode):\n  agy-swap-rs --use-account=<slot|alias|email> [agy args...]")
        .arg(flag("json", "json", "Emit structured JSON output").global(true))
        .arg(flag("verbose", "verbose", "Enable verbose diagnostic output").global(true))
        .arg(flag("refresh", "refresh", "Force live quota refresh before acting").global(true))
        .arg(flag("force", "force", "Force operation without confirmation or in manual mode").global(true))
        .arg(opt("family", "family", "FAMILY", "Filter or target model family (gemini, claude, gpt, argon)").global(true))
        .arg(opt("use_account", "use-account", "ACCOUNT", "Explicit account (<slot|alias|email>); required when running agy or targeting one account").global(true))
        .arg(flag("legacy_add", "add", "Log in and add a Google account"))
        .arg(opt("token", "token", "SOURCE", "Import OAuth token JSON or '-' for stdin"))
        .arg(flag("legacy_list", "list", "List saved accounts"))
        .arg(flag("legacy_next", "next", "Rotate to next account with available quota"))
        .arg(flag("auto_rotate", "auto-rotate", "Alias for --next"))
        .arg(opt("switch_to", "switch-to", "ACCOUNT", "Switch active session to ACCOUNT"))
        .arg(flag("legacy_switch", "switch", "Switch active session"))
        .arg(opt("legacy_remove", "remove", "ACCOUNT", "Remove a saved account"))
        .arg(flag("legacy_status", "status", "Show active account status"))
        .arg(flag("legacy_logout", "logout", "Clear active Antigravity session"))
        .subcommand(
            Command::new("add")
                .about("Log in or import a Google account into the vault")
                .arg(opt("token", "token", "SOURCE", "Import OAuth token JSON or '-' for stdin"))
                .arg(opt("email", "email", "EMAIL", "Explicit account email when importing offline"))
                .arg(opt("name", "name", "NAME", "Display name for imported account"))
                .arg(opt("source_dir", "source-dir", "DIR", "Import OAuth session from directory"))
                .arg(opt("alias", "alias", "ALIAS", "Optional short alias for the saved account"))
                .arg(flag("import_current", "import-current", "Import active ~/.gemini or Keychain session into the vault"))
                .arg(flag("via_agy", "via-agy", "Authenticate via isolated interactive agy TTY instead of PKCE browser chooser"))
                .arg(flag("no_browser", "no-browser", "Print authorization URL without launching system browser")),
        )
        .subcommand(
            Command::new("login")
                .about("Sign in to one or more Google accounts via PKCE account chooser or isolated agy")
                .arg(pos("alias", "ALIAS", false, "Optional alias for the logged-in account"))
                .arg(opt("count", "count", "N", "Number of accounts to log in sequentially (e.g. 3)"))
                .arg(flag("via_agy", "via-agy", "Authenticate via isolated interactive agy TTY instead of PKCE browser chooser"))
                .arg(flag("no_browser", "no-browser", "Print authorization URL without launching system browser")),
        )
        .subcommand(
            Command::new("import-current")
                .about("Import current ~/.gemini or Keychain OAuth session into the vault")
                .arg(opt("alias", "alias", "ALIAS", "Optional short alias for the imported account"))
                .arg(opt("email", "email", "EMAIL", "Explicit account email when importing offline"))
                .arg(opt("name", "name", "NAME", "Display name for imported account")),
        )
        .subcommand(
            Command::new("list")
                .about("List saved accounts with status badges and quota gauges")
                .arg(opt("tag", "tag", "TAG", "Filter accounts by tag")),
        )
        .subcommand(
            Command::new("limits")
                .about("Refresh and display 5-hour and weekly quota pools")
                .arg(pos("account", "ACCOUNT", false, "Optional account selector"))
                .arg(flag("no_refresh", "no-refresh", "Display cached quota snapshot without live HTTP fetch")),
        )
        .subcommand(
            Command::new("image")
                .about("Generate one image with agy in print mode inside an isolated overlay HOME")
                .arg(opt("prompt", "prompt", "TEXT", "Image generation prompt").required(true))
                .arg(opt("out", "out", "PATH", "Destination image path").required(true))
                .arg(opt("width", "width", "W", "Target width in pixels (default: 1024)"))
                .arg(opt("height", "height", "H", "Target height in pixels (default: 1024)"))
                .arg(
                    Arg::new("ref")
                        .long("ref")
                        .value_name("IMG")
                        .action(ArgAction::Append)
                        .num_args(1)
                        .help("Reference image path (repeatable)"),
                )
                .arg(opt("wait_seconds", "wait-seconds", "SECS", "Seconds to poll brain folder for output image (default: 300)"))
                .arg(opt("print_timeout", "print-timeout", "DURATION", "Timeout passed to agy --print-timeout (default: 12m)"))
                .arg(opt("model", "model", "MODEL", "agy model for the run, e.g. gemini-4-neon-low (default: agy's own)"))
                .arg(opt("account", "account", "ACCOUNT", "Account override (or pass --use-account)")),
        )
        .subcommand(
            Command::new("limit")
                .about("Set or clear a manual model-family cooldown")
                .subcommand_required(true)
                .subcommand(
                    Command::new("set")
                        .about("Apply a manual cooldown duration (e.g. 45m, 2h, 1d)")
                        .arg(pos("first", "ACCOUNT_OR_DURATION", true, "Account selector (or duration when --use-account is set)"))
                        .arg(pos("second", "DURATION", false, "Cooldown duration")),
                )
                .subcommand(
                    Command::new("clear")
                        .about("Clear manual or log cooldowns for an account")
                        .arg(pos("account", "ACCOUNT", false, "Account selector (or pass --use-account)")),
                ),
        )
        .subcommand(
            Command::new("switch")
                .visible_alias("activate")
                .about("Switch active Antigravity session to ACCOUNT")
                .arg(pos("account", "ACCOUNT", false, "Email, alias, or 1-based slot")),
        )
        .subcommand(
            Command::new("next")
                .visible_aliases(["switch-next", "rotate"])
                .about("Rotate to the best available standby account"),
        )
        .subcommand(
            Command::new("remove")
                .visible_alias("rm")
                .about("Remove a saved account and its vault secret")
                .arg(pos("account", "ACCOUNT", false, "Email, alias, or 1-based slot")),
        )
        .subcommand(
            Command::new("status")
                .visible_alias("current")
                .about("Show active account, quota pools, and failover coordinator state"),
        )
        .subcommand(Command::new("logout").about("Clear active Antigravity OAuth session"))
        .subcommand(
            Command::new("verify")
                .visible_alias("verify-accounts")
                .about("Inspect account verification requirements and auth readiness")
                .arg(pos("account", "ACCOUNT", false, "Optional account selector"))
                .arg(flag("open", "open", "Open verification URL in system browser"))
                .arg(flag("all", "all", "Inspect verification state across all saved accounts")),
        )
        .subcommand(
            Command::new("account")
                .about("Inspect, toggle, or migrate saved account records")
                .subcommand(Command::new("list").about("List account summaries"))
                .subcommand(Command::new("show").about("Show one account").arg(pos("account", "ACCOUNT", false, "Account selector (or pass --use-account)")))
                .subcommand(Command::new("migrate").about("Migrate legacy inline tokens into vault"))
                .subcommand(Command::new("enable").about("Enable account for routing").arg(pos("account", "ACCOUNT", false, "Account selector (or pass --use-account)")))
                .subcommand(Command::new("disable").about("Disable account from automatic routing").arg(pos("account", "ACCOUNT", false, "Account selector (or pass --use-account)"))),
        )
        .subcommand(
            Command::new("alias")
                .about("Manage short account aliases")
                .subcommand(Command::new("set").about("Bind ALIAS to ACCOUNT").arg(pos("alias", "ALIAS", true, "Alias name")).arg(pos("account", "ACCOUNT", true, "Account selector")))
                .subcommand(Command::new("rm").visible_alias("remove").about("Delete an alias").arg(pos("alias", "ALIAS", true, "Alias name")))
                .subcommand(Command::new("list").about("List configured aliases")),
        )
        .subcommand(
            Command::new("tag")
                .about("Manage searchable account tags")
                .subcommand(Command::new("add").about("Add TAG to ACCOUNT").arg(pos("account", "ACCOUNT", true, "Account selector")).arg(pos("tag", "TAG", true, "Tag label")))
                .subcommand(Command::new("rm").visible_alias("remove").about("Remove TAG from ACCOUNT").arg(pos("account", "ACCOUNT", true, "Account selector")).arg(pos("tag", "TAG", true, "Tag label")))
                .subcommand(Command::new("list").about("List tags across accounts").arg(opt("tag", "tag", "TAG", "Filter by tag"))),
        )
        .subcommand(
            Command::new("profile")
                .about("Manage project routing profiles")
                .subcommand(
                    Command::new("set")
                        .about("Create or update a routing profile")
                        .arg(pos("name", "NAME", true, "Profile name"))
                        .arg(pos("account", "ACCOUNT", true, "Primary account selector"))
                        .arg(opt("policy", "policy", "POLICY", "Ranking policy (sticky, balanced, round-robin)"))
                        .arg(opt("reserve", "reserve", "ACCOUNTS", "Comma-separated reserve account selectors"))
                        .arg(opt("threshold", "threshold", "PCT", "Minimum remaining quota threshold (0-100)")),
                )
                .subcommand(Command::new("rm").visible_alias("remove").about("Delete a profile").arg(pos("name", "NAME", true, "Profile name")))
                .subcommand(Command::new("list").about("List configured profiles")),
        )
        .subcommand(
            Command::new("bind")
                .about("Manage directory-to-profile bindings")
                .subcommand(
                    Command::new("set")
                        .about("Bind DIR to PROFILE")
                        .arg(pos("dir", "DIR", true, "Directory path"))
                        .arg(pos("profile", "PROFILE", true, "Profile name"))
                        .arg(opt("mode", "mode", "MODE", "Bind mode (recommend, prompt, auto)")),
                )
                .subcommand(Command::new("rm").visible_alias("remove").about("Remove binding for DIR").arg(pos("dir", "DIR", true, "Directory path")))
                .subcommand(Command::new("list").about("List directory bindings")),
        )
        .subcommand(
            Command::new("recommend")
                .about("Explain the best account candidate; pass --apply to switch")
                .arg(opt("dir", "dir", "DIR", "Working directory for binding lookup"))
                .arg(opt("profile", "profile", "PROFILE", "Explicit profile name"))
                .arg(opt("policy", "policy", "POLICY", "Override ranking policy"))
                .arg(flag("apply", "apply", "Switch active session to the recommended account")),
        )
        .subcommand(
            Command::new("ensure-active")
                .about("Evaluate failover policy and ensure a healthy active account"),
        )
        .subcommand(
            Command::new("resolve-route")
                .about("Resolve account and model-family fallback route")
                .arg(opt("fallback_strategy", "fallback-strategy", "STRATEGY", "same-family-first, same-account-first, or strict-family"))
                .arg(flag("force_switch", "force-switch", "Apply switch even when switch-mode is manual")),
        )
        .subcommand(
            Command::new("rotate-after-failure")
                .about("Record quota failure, apply cooldown, and fail over to standby")
                .arg(opt("reason", "reason", "REASON", "Failure reason label"))
                .arg(opt("trigger", "trigger", "TRIGGER", "Trigger source (cli, logwatch)"))
                .arg(opt("request_id", "request-id", "ID", "Idempotency request identifier"))
                .arg(opt("cooldown_minutes", "cooldown-minutes", "MINS", "Cooldown window in minutes"))
                .arg(flag("force_switch", "force-switch", "Switch even when switch-mode is manual")),
        )
        .subcommand(
            Command::new("quota-policy")
                .about("Show or update dynamic pool failover policy")
                .arg(opt("enabled", "enabled", "STATE", "Enable or disable pool failover (on or off)"))
                .arg(Arg::new("pool").long("pool").value_name("POOL").action(ArgAction::Append).num_args(1).help("Checked pool name (repeatable)"))
                .arg(opt("match_mode", "match", "MODE", "Pool match mode (any or all)"))
                .arg(opt("threshold", "threshold", "PCT", "Minimum remaining pool percentage (0-100)"))
                .arg(opt("max_age_seconds", "max-age-seconds", "SECS", "Maximum snapshot cache age in seconds")),
        )
        .subcommand(
            Command::new("switch-mode")
                .about("Show or set automatic failover mode (auto or manual)")
                .arg(pos("mode", "MODE", false, "auto or manual")),
        )
        .subcommand(
            Command::new("run")
                .about("Launch agy in an isolated overlay HOME (requires --use-account=<slot|alias|email>)")
                .arg(opt("dir", "dir", "DIR", "Working directory for binding resolution"))
                .arg(opt("profile", "profile", "PROFILE", "Profile override"))
                .arg(opt("account", "account", "ACCOUNT", "Account override"))
                .arg(opt("target", "target", "CMD", "Target CLI executable (default: agy)"))
                .arg(Arg::new("run_args").value_name("ARGS").num_args(0..).trailing_var_arg(true).allow_hyphen_values(true).help("Arguments passed to target CLI")),
        )
        .subcommand(Command::new("doctor").about("Audit config permissions, vault integrity, and active session"))
        .subcommand(
            Command::new("config")
                .about("Inspect or update settings.json")
                .subcommand(Command::new("show").about("Print current settings"))
                .subcommand(Command::new("set").about("Set configuration key").arg(pos("key", "KEY", true, "Setting key")).arg(pos("value", "VALUE", true, "Setting value")))
                .subcommand(Command::new("reset").about("Reset settings to defaults")),
        )
        .subcommand(
            Command::new("watch")
                .about("Tail Antigravity CLI logs for 429 quota exhaustion and poll usage")
                .arg(flag("once", "once", "Poll newly appended logs once and exit"))
                .arg(flag("from_start", "from-start", "Scan existing log files from byte 0"))
                .arg(flag("no_rotate", "no-rotate", "Detect quota errors without rotating active session"))
                .arg(flag("force_switch", "force-switch", "Switch even when switch-mode is manual"))
                .arg(opt("poll_seconds", "poll-seconds", "SECS", "Log poll interval in seconds"))
                .arg(opt("interval", "interval", "DUR", "Poll interval duration"))
                .arg(opt("cooldown_minutes", "cooldown-minutes", "MINS", "Cooldown minutes applied on 429")),
        )
        .subcommand(Command::new("ack-restart").about("Acknowledge agy restart after automatic failover"))
        .subcommand(
            Command::new("history")
                .about("Inspect or export bounded audit history")
                .arg(pos("action", "ACTION", false, "list, clear, or export"))
                .arg(opt("limit", "limit", "N", "Maximum history entries to read"))
                .arg(opt("output", "output", "FILE", "Export destination path or '-'")),
        )
        .subcommand(Command::new("stats").about("Summarize switch and quota history statistics"))
        .subcommand(
            Command::new("forecast")
                .about("Compute pool exhaustion and reset forecasts")
                .arg(pos("account", "ACCOUNT", false, "Optional account selector")),
        )
        .subcommand(
            Command::new("backup")
                .about("Export or import metadata or AES-256-GCM encrypted vault backups")
                .subcommand(
                    Command::new("export")
                        .about("Export accounts and settings backup")
                        .arg(pos("file", "FILE", false, "Output file path"))
                        .arg(opt("output", "output", "FILE", "Output file path"))
                        .arg(flag("include_secrets", "include-secrets", "Encrypt vault secrets with AES-256-GCM + PBKDF2-HMAC-SHA256"))
                        .arg(opt("passphrase", "passphrase", "PASS", "Encryption passphrase"))
                        .arg(flag("passphrase_stdin", "passphrase-stdin", "Read encryption passphrase from stdin")),
                )
                .subcommand(
                    Command::new("import")
                        .about("Import backup archive into store and vault")
                        .arg(pos("file", "FILE", true, "Backup file path"))
                        .arg(flag("merge", "merge", "Merge into existing accounts instead of replacing"))
                        .arg(opt("passphrase", "passphrase", "PASS", "Decryption passphrase"))
                        .arg(flag("passphrase_stdin", "passphrase-stdin", "Read decryption passphrase from stdin")),
                )
                .subcommand(
                    Command::new("verify")
                        .about("Verify backup archive integrity and passphrase")
                        .arg(pos("file", "FILE", true, "Backup file path"))
                        .arg(opt("passphrase", "passphrase", "PASS", "Decryption passphrase"))
                        .arg(flag("passphrase_stdin", "passphrase-stdin", "Read decryption passphrase from stdin")),
                ),
        )
        .subcommand(
            Command::new("statusline")
                .about("Render or install compact shell/tmux/Starship statusline")
                .subcommand(Command::new("render").about("Render statusline segment"))
                .subcommand(Command::new("install").about("Install statusline snippet").arg(pos("tool", "TOOL", false, "starship, tmux, or zsh"))),
        )
        .subcommand(
            Command::new("metrics")
                .about("Render local Prometheus quota metrics")
                .arg(pos("format", "FORMAT", false, "prometheus, render, or json")),
        )
        .subcommand(
            Command::new("install-agy")
                .about("Download, SHA-512 verify, and install the Antigravity CLI (agy)")
                .arg(opt("dir", "dir", "DIR", "Target installation directory")),
        )
        .subcommand(
            Command::new("update")
                .about("Check for or install agy-swap-rs updates")
                .arg(pos("mode", "MODE", false, "Optional 'check' mode"))
                .arg(flag("check", "check", "Only check whether a newer release is available")),
        )
        .subcommand(Command::new("version").about("Print agy-swap-rs version"))
        .subcommand(
            Command::new("completion")
                .about("Print shell completion script")
                .arg(pos("shell", "SHELL", false, "bash, zsh, fish, or powershell")),
        )
        .subcommand(
            Command::new("__dump-frame")
                .hide(true)
                .about("Render headless TUI frame for E2E verification")
                .arg(pos("size", "WxH", true, "Viewport dimensions such as 140x40"))
                .arg(flag("ascii", "ascii", "Render ASCII borders and gauges"))
                .arg(flag("ansi", "ansi", "Emit synchronized diff_ansi output instead of plain text")),
        )
}
