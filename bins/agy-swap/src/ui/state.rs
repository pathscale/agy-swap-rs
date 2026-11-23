use super::alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use agy_core::{
    logwatch::{SwitchRuntime, SwitchRuntimeState},
    ops::DoctorCheck,
    policy::{PoolFailoverPolicy, PoolMatchMode, SwitchMode},
    Account, Accounts, Badge, Paths, SessionManager, Store, Vault,
};
use agy_tui::{HitId, PointerShape};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveView {
    Dashboard,
    Profiles,
    History,
    Settings,
    Doctor,
    Backup,
    QuotaPools,
    FailoverPolicy,
}

impl ActiveView {
    pub const ALL: [ActiveView; 8] = [
        ActiveView::Dashboard,
        ActiveView::QuotaPools,
        ActiveView::FailoverPolicy,
        ActiveView::Profiles,
        ActiveView::History,
        ActiveView::Settings,
        ActiveView::Doctor,
        ActiveView::Backup,
    ];

    pub const fn tab_label(self) -> &'static str {
        match self {
            ActiveView::Dashboard => "Dash",
            ActiveView::Profiles => "Profiles",
            ActiveView::History => "History",
            ActiveView::Settings => "Settings",
            ActiveView::Doctor => "Doctor",
            ActiveView::Backup => "Backup",
            ActiveView::QuotaPools => "Pools",
            ActiveView::FailoverPolicy => "Failover",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            ActiveView::Dashboard => "OPERATOR DECK",
            ActiveView::Profiles => "PROFILES",
            ActiveView::History => "SWITCH & QUOTA HISTORY",
            ActiveView::Settings => "SETTINGS & BINDINGS",
            ActiveView::Doctor => "INSTALLATION DOCTOR",
            ActiveView::Backup => "BACKUP & RESTORE",
            ActiveView::QuotaPools => "DISCOVERED QUOTA POOLS",
            ActiveView::FailoverPolicy => "POOL FAILOVER POLICY",
        }
    }

    pub const fn subtitle(self) -> &'static str {
        match self {
            ActiveView::Dashboard => "Live multi-account routing, quota telemetry, and instant session switch.",
            ActiveView::Profiles => "Named routing profiles with family preference and reserve accounts.",
            ActiveView::History => "Local audit trail of session switches, rotations, and refreshes.",
            ActiveView::Settings => "Switch mode, ranking policy, directory bindings, and aliases.",
            ActiveView::Doctor => "Read-only diagnostics across storage, vault, session, and CLI paths.",
            ActiveView::Backup => "Metadata-only export or AES-256-GCM + PBKDF2 encrypted vault bundles.",
            ActiveView::QuotaPools => "All cached model pools and reset windows on the selected account.",
            ActiveView::FailoverPolicy => "Select ANY or ALL checked pools that trigger automatic rotation.",
        }
    }

    pub const fn to_code(self) -> u32 {
        match self {
            ActiveView::Dashboard => 0,
            ActiveView::Profiles => 1,
            ActiveView::History => 2,
            ActiveView::Settings => 3,
            ActiveView::Doctor => 4,
            ActiveView::Backup => 5,
            ActiveView::QuotaPools => 6,
            ActiveView::FailoverPolicy => 7,
        }
    }

    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(ActiveView::Dashboard),
            1 => Some(ActiveView::Profiles),
            2 => Some(ActiveView::History),
            3 => Some(ActiveView::Settings),
            4 => Some(ActiveView::Doctor),
            5 => Some(ActiveView::Backup),
            6 => Some(ActiveView::QuotaPools),
            7 => Some(ActiveView::FailoverPolicy),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    None,
    ConfirmSwitch { email: String },
    ConfirmDelete { email: String },
    FilterInput,
    CommandPalette { query: String, selected: usize },
    ShortcutGuide,
    AddAccountHint,
}

impl Modal {
    pub const fn is_overlay(&self) -> bool {
        !matches!(self, Modal::None | Modal::FilterInput)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastLevel {
    Info,
    Success,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub message: String,
    pub level: ToastLevel,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DividerDrag {
    Vertical,
    Horizontal,
}

#[derive(Debug, Clone, Copy)]
pub struct LastClick {
    pub hit: HitId,
    pub at_ms: u64,
    pub x: u16,
    pub y: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeycapAction {
    MoveUp,
    MoveDown,
    Confirm,
    Palette,
    Help,
    Quit,
    Filter,
    Refresh,
    Next,
    Add,
    Delete,
    Verify,
    AckRestart,
    SplitNarrow,
    SplitWiden,
    SplitReset,
    BackDashboard,
    PolicyToggle,
    PolicySave,
    PolicyMode,
    BackupExport,
    ImportCurrent,
    LaunchIsolated,
}

impl KeycapAction {
    pub const fn to_code(self) -> u32 {
        match self {
            KeycapAction::MoveUp => 1,
            KeycapAction::MoveDown => 2,
            KeycapAction::Confirm => 3,
            KeycapAction::Palette => 4,
            KeycapAction::Help => 5,
            KeycapAction::Quit => 6,
            KeycapAction::Filter => 7,
            KeycapAction::Refresh => 8,
            KeycapAction::Next => 9,
            KeycapAction::Add => 10,
            KeycapAction::Delete => 11,
            KeycapAction::Verify => 12,
            KeycapAction::AckRestart => 13,
            KeycapAction::SplitNarrow => 14,
            KeycapAction::SplitWiden => 15,
            KeycapAction::SplitReset => 16,
            KeycapAction::BackDashboard => 17,
            KeycapAction::PolicyToggle => 18,
            KeycapAction::PolicySave => 19,
            KeycapAction::PolicyMode => 20,
            KeycapAction::BackupExport => 21,
            KeycapAction::ImportCurrent => 22,
            KeycapAction::LaunchIsolated => 23,
        }
    }

    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            1 => Some(KeycapAction::MoveUp),
            2 => Some(KeycapAction::MoveDown),
            3 => Some(KeycapAction::Confirm),
            4 => Some(KeycapAction::Palette),
            5 => Some(KeycapAction::Help),
            6 => Some(KeycapAction::Quit),
            7 => Some(KeycapAction::Filter),
            8 => Some(KeycapAction::Refresh),
            9 => Some(KeycapAction::Next),
            10 => Some(KeycapAction::Add),
            11 => Some(KeycapAction::Delete),
            12 => Some(KeycapAction::Verify),
            13 => Some(KeycapAction::AckRestart),
            14 => Some(KeycapAction::SplitNarrow),
            15 => Some(KeycapAction::SplitWiden),
            16 => Some(KeycapAction::SplitReset),
            17 => Some(KeycapAction::BackDashboard),
            18 => Some(KeycapAction::PolicyToggle),
            19 => Some(KeycapAction::PolicySave),
            20 => Some(KeycapAction::PolicyMode),
            21 => Some(KeycapAction::BackupExport),
            22 => Some(KeycapAction::ImportCurrent),
            23 => Some(KeycapAction::LaunchIsolated),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitTarget {
    AccountRow(usize),
    FooterKeycap(KeycapAction),
    ModalConfirm,
    ModalCancel,
    ModalSecondary,
    ModalBox,
    PaletteRow(usize),
    SplitDivider,
    StackDivider,
    SubviewTab(ActiveView),
    PolicyPoolRow(usize),
    ListScrollArea,
    DetailScrollArea,
}

impl HitTarget {
    const TAG_ACCOUNT_ROW: u32 = 1;
    const TAG_FOOTER_KEYCAP: u32 = 2;
    const TAG_MODAL_CONFIRM: u32 = 3;
    const TAG_MODAL_CANCEL: u32 = 4;
    const TAG_MODAL_BOX: u32 = 5;
    const TAG_PALETTE_ROW: u32 = 6;
    const TAG_SPLIT_DIVIDER: u32 = 7;
    const TAG_STACK_DIVIDER: u32 = 8;
    const TAG_SUBVIEW_TAB: u32 = 9;
    const TAG_POLICY_POOL_ROW: u32 = 10;
    const TAG_LIST_SCROLL: u32 = 11;
    const TAG_DETAIL_SCROLL: u32 = 12;
    const TAG_MODAL_SECONDARY: u32 = 13;

    pub const fn encode(self) -> HitId {
        let (tag, payload) = match self {
            HitTarget::AccountRow(idx) => (Self::TAG_ACCOUNT_ROW, (idx as u32) & 0x00ff_ffff),
            HitTarget::FooterKeycap(act) => (Self::TAG_FOOTER_KEYCAP, act.to_code()),
            HitTarget::ModalConfirm => (Self::TAG_MODAL_CONFIRM, 0),
            HitTarget::ModalCancel => (Self::TAG_MODAL_CANCEL, 0),
            HitTarget::ModalSecondary => (Self::TAG_MODAL_SECONDARY, 0),
            HitTarget::ModalBox => (Self::TAG_MODAL_BOX, 0),
            HitTarget::PaletteRow(idx) => (Self::TAG_PALETTE_ROW, (idx as u32) & 0x00ff_ffff),
            HitTarget::SplitDivider => (Self::TAG_SPLIT_DIVIDER, 0),
            HitTarget::StackDivider => (Self::TAG_STACK_DIVIDER, 0),
            HitTarget::SubviewTab(view) => (Self::TAG_SUBVIEW_TAB, view.to_code()),
            HitTarget::PolicyPoolRow(idx) => {
                (Self::TAG_POLICY_POOL_ROW, (idx as u32) & 0x00ff_ffff)
            }
            HitTarget::ListScrollArea => (Self::TAG_LIST_SCROLL, 0),
            HitTarget::DetailScrollArea => (Self::TAG_DETAIL_SCROLL, 0),
        };
        HitId((tag << 24) | payload)
    }

    pub const fn decode(id: HitId) -> Option<Self> {
        let tag = id.0 >> 24;
        let payload = id.0 & 0x00ff_ffff;
        match tag {
            Self::TAG_ACCOUNT_ROW => Some(HitTarget::AccountRow(payload as usize)),
            Self::TAG_FOOTER_KEYCAP => match KeycapAction::from_code(payload) {
                Some(act) => Some(HitTarget::FooterKeycap(act)),
                None => None,
            },
            Self::TAG_MODAL_CONFIRM => Some(HitTarget::ModalConfirm),
            Self::TAG_MODAL_CANCEL => Some(HitTarget::ModalCancel),
            Self::TAG_MODAL_SECONDARY => Some(HitTarget::ModalSecondary),
            Self::TAG_MODAL_BOX => Some(HitTarget::ModalBox),
            Self::TAG_PALETTE_ROW => Some(HitTarget::PaletteRow(payload as usize)),
            Self::TAG_SPLIT_DIVIDER => Some(HitTarget::SplitDivider),
            Self::TAG_STACK_DIVIDER => Some(HitTarget::StackDivider),
            Self::TAG_SUBVIEW_TAB => match ActiveView::from_code(payload) {
                Some(v) => Some(HitTarget::SubviewTab(v)),
                None => None,
            },
            Self::TAG_POLICY_POOL_ROW => Some(HitTarget::PolicyPoolRow(payload as usize)),
            Self::TAG_LIST_SCROLL => Some(HitTarget::ListScrollArea),
            Self::TAG_DETAIL_SCROLL => Some(HitTarget::DetailScrollArea),
            _ => None,
        }
    }

    pub const fn pointer_shape(self) -> PointerShape {
        match self {
            HitTarget::SplitDivider => PointerShape::ColResize,
            HitTarget::StackDivider => PointerShape::RowResize,
            HitTarget::ModalBox | HitTarget::ListScrollArea | HitTarget::DetailScrollArea => {
                PointerShape::Default
            }
            _ => PointerShape::Pointer,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyDraft {
    pub policy: PoolFailoverPolicy,
    pub known_pools: Vec<String>,
    pub cursor: usize,
    pub dirty: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteCommand {
    GoView(ActiveView),
    LaunchIsolated,
    SwitchSelected,
    NextAccount,
    RefreshQuota,
    RefreshSelected,
    AddAccount,
    ImportCurrent,
    DeleteSelected,
    OpenVerify,
    MigrateVault,
    ToggleSwitchMode,
    AckRestart,
    RunDoctor,
    BackupExportMeta,
    SplitNarrow,
    SplitWiden,
    SplitReset,
    ShortcutGuide,
    Quit,
}

#[derive(Debug, Clone, Copy)]
pub struct PaletteEntry {
    pub cmd: PaletteCommand,
    pub label: &'static str,
    pub description: &'static str,
    pub shortcut: &'static str,
    pub section: &'static str,
}

pub const PALETTE_CATALOG: &[PaletteEntry] = &[
    PaletteEntry {
        cmd: PaletteCommand::GoView(ActiveView::Dashboard),
        label: "Dashboard",
        description: "Return to the multi-account operator deck",
        shortcut: "g",
        section: "Navigate",
    },
    PaletteEntry {
        cmd: PaletteCommand::GoView(ActiveView::QuotaPools),
        label: "Quota Pools",
        description: "Inspect all discovered model pools on selected account",
        shortcut: "v",
        section: "Navigate",
    },
    PaletteEntry {
        cmd: PaletteCommand::GoView(ActiveView::FailoverPolicy),
        label: "Failover Policy",
        description: "Configure ANY/ALL checked pool failover thresholds",
        shortcut: "f",
        section: "Navigate",
    },
    PaletteEntry {
        cmd: PaletteCommand::GoView(ActiveView::Profiles),
        label: "Profiles",
        description: "View named account routing profiles and reserves",
        shortcut: "p",
        section: "Navigate",
    },
    PaletteEntry {
        cmd: PaletteCommand::GoView(ActiveView::History),
        label: "History",
        description: "Review recent switches, rotations, and refreshes",
        shortcut: "h",
        section: "Navigate",
    },
    PaletteEntry {
        cmd: PaletteCommand::GoView(ActiveView::Settings),
        label: "Settings",
        description: "Inspect policy, bindings, aliases, and switch mode",
        shortcut: "s",
        section: "Navigate",
    },
    PaletteEntry {
        cmd: PaletteCommand::GoView(ActiveView::Doctor),
        label: "Doctor Health Check",
        description: "Run diagnostics across store, vault, and session",
        shortcut: "o",
        section: "Navigate",
    },
    PaletteEntry {
        cmd: PaletteCommand::GoView(ActiveView::Backup),
        label: "Backup & Restore",
        description: "Export redacted metadata or encrypted backup bundles",
        shortcut: "b",
        section: "Navigate",
    },
    PaletteEntry {
        cmd: PaletteCommand::LaunchIsolated,
        label: "Launch agy (--use-account)",
        description: "Run isolated agy session on selected account without touching ~/.gemini",
        shortcut: "Enter / o",
        section: "Accounts",
    },
    PaletteEntry {
        cmd: PaletteCommand::SwitchSelected,
        label: "Switch Global ~/.gemini IDE Session",
        description: "Swap ~/.gemini + Keychain to selected account (restart IDE)",
        shortcut: "Enter",
        section: "Accounts",
    },
    PaletteEntry {
        cmd: PaletteCommand::NextAccount,
        label: "Rotate to Next Healthy Account",
        description: "Select and switch to the next available standby account",
        shortcut: "n",
        section: "Accounts",
    },
    PaletteEntry {
        cmd: PaletteCommand::RefreshQuota,
        label: "Refresh All Quotas",
        description: "Force live quota refresh across saved accounts",
        shortcut: "r",
        section: "Accounts",
    },
    PaletteEntry {
        cmd: PaletteCommand::RefreshSelected,
        label: "Refresh Selected Account",
        description: "Fetch fresh usage snapshot for the highlighted account",
        shortcut: "u",
        section: "Accounts",
    },
    PaletteEntry {
        cmd: PaletteCommand::AddAccount,
        label: "Add / Login Account",
        description: "Open non-disruptive Google Account Chooser login",
        shortcut: "a",
        section: "Accounts",
    },
    PaletteEntry {
        cmd: PaletteCommand::ImportCurrent,
        label: "Import current ~/.gemini session",
        description: "Save active ~/.gemini or Keychain OAuth session into vault",
        shortcut: "i",
        section: "Accounts",
    },
    PaletteEntry {
        cmd: PaletteCommand::DeleteSelected,
        label: "Remove Selected Account",
        description: "Delete selected account and its vault token",
        shortcut: "d",
        section: "Accounts",
    },
    PaletteEntry {
        cmd: PaletteCommand::OpenVerify,
        label: "Show Google Verification URL",
        description: "Display verification link for accounts flagged VERIFY",
        shortcut: "w",
        section: "Accounts",
    },
    PaletteEntry {
        cmd: PaletteCommand::MigrateVault,
        label: "Migrate Legacy Tokens to Vault",
        description: "Move inline legacy tokens out of accounts.json",
        shortcut: "m",
        section: "Security",
    },
    PaletteEntry {
        cmd: PaletteCommand::ToggleSwitchMode,
        label: "Toggle Auto / Manual Switch Mode",
        description: "Control whether logwatch rotates active session automatically",
        shortcut: "w",
        section: "Routing",
    },
    PaletteEntry {
        cmd: PaletteCommand::AckRestart,
        label: "Acknowledge AGY Restart",
        description: "Clear LogWatch restart banner and re-arm rotation",
        shortcut: "y",
        section: "Routing",
    },
    PaletteEntry {
        cmd: PaletteCommand::RunDoctor,
        label: "Re-run Doctor Checks",
        description: "Refresh local installation health checks",
        shortcut: "o",
        section: "System",
    },
    PaletteEntry {
        cmd: PaletteCommand::BackupExportMeta,
        label: "Export Metadata Backup",
        description: "Write redacted backup JSON to config directory",
        shortcut: "x",
        section: "System",
    },
    PaletteEntry {
        cmd: PaletteCommand::SplitNarrow,
        label: "Narrow Left Pane",
        description: "Decrease split width of the accounts pane",
        shortcut: "[",
        section: "Layout",
    },
    PaletteEntry {
        cmd: PaletteCommand::SplitWiden,
        label: "Widen Left Pane",
        description: "Increase split width of the accounts pane",
        shortcut: "]",
        section: "Layout",
    },
    PaletteEntry {
        cmd: PaletteCommand::SplitReset,
        label: "Reset Pane Split",
        description: "Restore default split ratio",
        shortcut: "=",
        section: "Layout",
    },
    PaletteEntry {
        cmd: PaletteCommand::ShortcutGuide,
        label: "Keyboard & Mouse Guide",
        description: "Show full shortcut overlay",
        shortcut: "?",
        section: "System",
    },
    PaletteEntry {
        cmd: PaletteCommand::Quit,
        label: "Quit Console",
        description: "Exit interactive operator deck",
        shortcut: "q",
        section: "System",
    },
];

pub struct DeckState {
    pub accounts: Accounts,
    pub active_email: Option<String>,
    pub token_present: BTreeMap<String, bool>,
    pub isolated_running: BTreeMap<String, usize>,
    pub selected: usize,
    pub filter: String,
    pub filter_backup: String,
    pub selected_before_filter: usize,
    pub split_offset: i16,
    pub stack_offset: i16,
    pub view: ActiveView,
    pub modal: Modal,
    pub modal_button_idx: usize,
    pub toast: Option<Toast>,
    pub status_line: Option<(String, ToastLevel)>,
    pub runtime: SwitchRuntime,
    pub policy_draft: PolicyDraft,
    pub settings_json: serde_json::Value,
    pub history_json: Vec<serde_json::Value>,
    pub doctor_checks: Vec<DoctorCheck>,
    pub backup_path: String,
    pub subview_cursor: usize,
    pub list_scroll: usize,
    pub detail_scroll: usize,
    pub hover_hit: Option<HitId>,
    pub dragging: Option<DividerDrag>,
    pub last_click: Option<LastClick>,
    pub armed_row_click: Option<usize>,
    pub now_unix: i64,
    pub refreshing: bool,
    pub switch_mode: SwitchMode,
}

pub(crate) fn open_vault(paths: &Paths) -> Vault {
    Vault::new(paths.clone())
}

pub(crate) fn vault_key_for(account: &Account) -> String {
    account
        .vault_ref
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("account:{}", account.email))
}

pub(crate) fn lookup_account_token(account: &Account, vault: &Vault) -> Option<String> {
    let primary = vault_key_for(account);
    if let Ok(Some(tok)) = vault.get(&primary) {
        if !tok.trim().is_empty() {
            return Some(tok);
        }
    }
    let fallback = format!("account:{}", account.email);
    if fallback != primary {
        if let Ok(Some(tok)) = vault.get(&fallback) {
            if !tok.trim().is_empty() {
                return Some(tok);
            }
        }
    }
    if let Ok(Some(tok)) = vault.get(&account.email) {
        if !tok.trim().is_empty() {
            return Some(tok);
        }
    }
    account
        .legacy_token_data
        .clone()
        .filter(|s| !s.trim().is_empty())
}

pub(crate) fn default_runtime() -> SwitchRuntime {
    SwitchRuntime {
        state: SwitchRuntimeState::Idle,
        active_email: None,
        last_switch_unix: 0,
        last_trigger: None,
        restart_agy_needed: false,
    }
}

pub(crate) fn load_runtime_file(paths: &Paths) -> SwitchRuntime {
    match eko::file::read(&paths.runtime_file) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|_| default_runtime()),
        Err(_) => default_runtime(),
    }
}

pub(crate) fn default_pool_policy() -> PoolFailoverPolicy {
    PoolFailoverPolicy {
        enabled: true,
        match_mode: PoolMatchMode::Any,
        checked_pools: vec!["Gemini".to_string(), "Claude/GPT".to_string()],
        threshold_pct: 10,
        max_age_secs: 900,
    }
}

fn extract_pool_policy(val: &serde_json::Value) -> PoolFailoverPolicy {
    for key in ["pool_failover", "pool_failover_policy", "failover_policy", "quota_policy"] {
        if let Some(sub) = val.get(key) {
            if let Ok(parsed) = serde_json::from_value::<PoolFailoverPolicy>(sub.clone()) {
                return parsed;
            }
        }
    }
    default_pool_policy()
}

fn extract_switch_mode(val: &serde_json::Value) -> SwitchMode {
    for key in ["switch_mode", "mode"] {
        if let Some(s) = val.get(key).and_then(|v| v.as_str()) {
            if s.eq_ignore_ascii_case("auto") {
                return SwitchMode::Auto;
            }
            if s.eq_ignore_ascii_case("manual") {
                return SwitchMode::Manual;
            }
        }
    }
    if let Some(allow) =
        val.get("policy").and_then(|p| p.get("allow_apply")).and_then(|v| v.as_bool())
    {
        if allow {
            return SwitchMode::Auto;
        }
    }
    SwitchMode::Manual
}

fn extract_split_offsets(val: &serde_json::Value) -> (i16, i16) {
    let split = val
        .get("ui")
        .and_then(|u| u.get("split_offset"))
        .or_else(|| val.get("split_offset"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        .clamp(-40, 40) as i16;
    let stack = val
        .get("ui")
        .and_then(|u| u.get("stack_offset"))
        .or_else(|| val.get("stack_offset"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        .clamp(-20, 20) as i16;
    (split, stack)
}

fn contains_fold(haystack: &str, needle_lower: &str) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    haystack.to_lowercase().contains(needle_lower)
}

pub(crate) fn warm_token_map(accounts: &Accounts, vault: &Vault) -> BTreeMap<String, bool> {
    let mut map = BTreeMap::new();
    for email in &accounts.order {
        if let Some(acc) = accounts.get(email) {
            map.insert(email.clone(), lookup_account_token(acc, vault).is_some());
        }
    }
    map
}

pub(crate) fn warm_isolated_map(paths: &Paths, accounts: &Accounts) -> BTreeMap<String, usize> {
    let mut map = BTreeMap::new();
    for email in &accounts.order {
        let count = agy_core::isolate::active_isolated_sessions(paths, email);
        if count > 0 {
            map.insert(email.clone(), count);
        }
    }
    map
}

fn detect_active_email(
    accounts: &Accounts,
    session: &SessionManager,
    runtime: &SwitchRuntime,
) -> Option<String> {
    if let Some(email) = session.current_email() {
        if let Some(resolved) = accounts.resolve(&email) {
            return Some(resolved.to_string());
        }
        if !email.trim().is_empty() {
            return Some(email);
        }
    }
    if let Some(raw_token) = session.current_token() {
        if let Ok(bundle) = agy_core::oauth::TokenBundle::parse(&raw_token) {
            if let Some(hint) = bundle.email_hint {
                if let Some(resolved) = accounts.resolve(&hint) {
                    return Some(resolved.to_string());
                }
                return Some(hint);
            }
        }
    }
    runtime.active_email.clone()
}

impl DeckState {
    pub fn load(paths: &Paths) -> Self {
        let now_unix = agy_core::wall_unix_secs();
        let store = Store::new(paths.clone());
        let vault = open_vault(paths);
        let session = SessionManager::new(paths.clone());
        let accounts = store.load().unwrap_or_else(|_| Accounts::new());
        let token_present = warm_token_map(&accounts, &vault);
        let isolated_running = warm_isolated_map(paths, &accounts);
        let runtime = load_runtime_file(paths);
        let active_email = detect_active_email(&accounts, &session, &runtime);
        let settings_json = store
            .load_settings()
            .ok()
            .and_then(|s| serde_json::to_value(&s).ok())
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
        let history_json = store
            .read_history(80)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| serde_json::to_value(&e).ok())
            .collect();
        let doctor_checks = agy_core::ops::run_doctor(paths, &store, &vault, &session);
        let (split_offset, stack_offset) = extract_split_offsets(&settings_json);
        let policy = extract_pool_policy(&settings_json);
        let switch_mode = extract_switch_mode(&settings_json);
        let backup_path = format!("{}/agy-swap-rs-backup.json", paths.config_dir);
        let mut state = Self {
            accounts,
            active_email,
            token_present,
            isolated_running,
            selected: 0,
            filter: String::new(),
            filter_backup: String::new(),
            selected_before_filter: 0,
            split_offset,
            stack_offset,
            view: ActiveView::Dashboard,
            modal: Modal::None,
            modal_button_idx: 0,
            toast: None,
            status_line: None,
            runtime,
            policy_draft: PolicyDraft {
                policy,
                known_pools: Vec::new(),
                cursor: 0,
                dirty: false,
            },
            settings_json,
            history_json,
            doctor_checks,
            backup_path,
            subview_cursor: 0,
            list_scroll: 0,
            detail_scroll: 0,
            hover_hit: None,
            dragging: None,
            last_click: None,
            armed_row_click: None,
            now_unix,
            refreshing: false,
            switch_mode,
        };
        state.sync_policy_pools();
        state.clamp_selection();
        state
    }

    pub fn reload_from_disk(&mut self, paths: &Paths) {
        self.now_unix = agy_core::wall_unix_secs();
        let store = Store::new(paths.clone());
        let vault = open_vault(paths);
        let session = SessionManager::new(paths.clone());
        let prev_email = self.selected_email();
        if let Ok(accounts) = store.load() {
            self.token_present = warm_token_map(&accounts, &vault);
            self.accounts = accounts;
        }
        self.isolated_running = warm_isolated_map(paths, &self.accounts);
        self.runtime = load_runtime_file(paths);
        self.active_email = detect_active_email(&self.accounts, &session, &self.runtime);
        if let Ok(s) = store.load_settings() {
            if let Ok(val) = serde_json::to_value(&s) {
                if !self.policy_draft.dirty {
                    self.policy_draft.policy = extract_pool_policy(&val);
                }
                self.switch_mode = extract_switch_mode(&val);
                self.settings_json = val;
            }
        }
        if let Ok(hist) = store.read_history(80) {
            self.history_json = hist
                .into_iter()
                .filter_map(|e| serde_json::to_value(&e).ok())
                .collect();
        }
        self.sync_policy_pools();
        if let Some(target) = prev_email {
            let vis = self.visible_emails();
            if let Some(pos) = vis.iter().position(|e| e.eq_ignore_ascii_case(&target)) {
                self.selected = pos;
            }
        }
        self.clamp_selection();
    }

    pub fn has_token(&self, account: &Account) -> bool {
        if account.legacy_token_data.as_deref().map(|s| !s.is_empty()).unwrap_or(false) {
            return true;
        }
        self.token_present.get(&account.email).copied().unwrap_or(false)
    }

    pub fn isolated_count(&self, email: &str) -> usize {
        if let Some(&n) = self.isolated_running.get(email) {
            return n;
        }
        self.isolated_running
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(email))
            .map(|(_, &n)| n)
            .unwrap_or(0)
    }

    pub fn account_badge(&self, account: &Account) -> Badge {
        account.badge(self.has_token(account), self.now_unix)
    }

    pub fn visible_emails(&self) -> Vec<String> {
        let q = self.filter.trim().to_lowercase();
        let mut ready = Vec::new();
        let mut attention = Vec::new();
        for email in &self.accounts.order {
            let Some(acc) = self.accounts.get(email) else {
                continue;
            };
            if !q.is_empty() {
                let matched = contains_fold(&acc.email, &q)
                    || contains_fold(&acc.name, &q)
                    || acc.aliases.iter().any(|a| contains_fold(a, &q))
                    || acc.tags.iter().any(|t| contains_fold(t, &q));
                if !matched {
                    continue;
                }
            }
            let badge = self.account_badge(acc);
            if acc.disabled || matches!(badge, Badge::NoToken | Badge::Verify) {
                attention.push(email.clone());
            } else {
                ready.push(email.clone());
            }
        }
        ready.extend(attention);
        ready
    }

    pub fn selected_email(&self) -> Option<String> {
        let vis = self.visible_emails();
        vis.get(self.selected).cloned()
    }

    pub fn selected_account(&self) -> Option<&Account> {
        let email = self.selected_email()?;
        self.accounts.get(&email)
    }

    pub fn clamp_selection(&mut self) {
        let len = self.visible_emails().len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    pub fn move_selection(&mut self, delta: isize) {
        let len = self.visible_emails().len();
        if len == 0 {
            self.selected = 0;
            return;
        }
        let cur = self.selected as isize;
        let next = (cur + delta).rem_euclid(len as isize) as usize;
        self.selected = next;
        self.armed_row_click = None;
    }

    pub fn select_slot(&mut self, slot_one_based: usize) {
        if slot_one_based == 0 {
            return;
        }
        let len = self.visible_emails().len();
        let idx = slot_one_based - 1;
        if idx < len {
            self.selected = idx;
            self.armed_row_click = None;
        }
    }

    pub fn select_boundary(&mut self, last: bool) {
        let len = self.visible_emails().len();
        if len == 0 {
            self.selected = 0;
        } else if last {
            self.selected = len - 1;
        } else {
            self.selected = 0;
        }
        self.armed_row_click = None;
    }

    pub fn adjust_split(&mut self, delta: i16, stacked: bool) {
        if stacked {
            self.stack_offset = (self.stack_offset + delta / 2).clamp(-16, 16);
        } else {
            self.split_offset = (self.split_offset + delta).clamp(-36, 36);
        }
    }

    pub fn reset_split(&mut self, stacked: bool) {
        if stacked {
            self.stack_offset = 0;
        } else {
            self.split_offset = 0;
        }
    }

    pub fn set_stack_from_row(&mut self, row: u16, body_y: u16, body_h: u16) {
        let base = (body_y as i32) + ((body_h as i32) * 45 / 100).max(3);
        let desired = (row as i32) - base;
        self.stack_offset = desired.clamp(-16, 16) as i16;
    }

    pub fn sync_policy_pools(&mut self) {
        let mut names = vec!["Gemini".to_string(), "Claude/GPT".to_string()];
        let mut push_unique = |name: &str| {
            let trimmed = name.trim();
            if !trimmed.is_empty() && !names.iter().any(|n| n.eq_ignore_ascii_case(trimmed)) {
                names.push(trimmed.to_string());
            }
        };
        for email in &self.accounts.order {
            if let Some(acc) = self.accounts.get(email) {
                if let Some(ref snap) = acc.quota {
                    push_unique(&snap.gemini.name);
                    push_unique(&snap.claude_gpt.name);
                    if let Some(ref argon) = snap.argon {
                        if argon.name.trim().is_empty() {
                            push_unique("Gemini 4 Argon");
                        } else {
                            push_unique(&argon.name);
                        }
                    }
                    for extra in &snap.extra_pools {
                        push_unique(&extra.name);
                    }
                }
            }
        }
        for checked in &self.policy_draft.policy.checked_pools {
            push_unique(checked);
        }
        self.policy_draft.known_pools = names;
        if self.policy_draft.cursor >= self.policy_draft.known_pools.len() {
            self.policy_draft.cursor = self.policy_draft.known_pools.len().saturating_sub(1);
        }
    }

    pub fn is_pool_checked(&self, name: &str) -> bool {
        self.policy_draft
            .policy
            .checked_pools
            .iter()
            .any(|p| p.eq_ignore_ascii_case(name))
    }

    pub fn policy_toggle_at(&mut self, idx: usize) {
        let Some(name) = self.policy_draft.known_pools.get(idx).cloned() else {
            return;
        };
        if let Some(pos) = self
            .policy_draft
            .policy
            .checked_pools
            .iter()
            .position(|p| p.eq_ignore_ascii_case(&name))
        {
            self.policy_draft.policy.checked_pools.remove(pos);
        } else {
            self.policy_draft.policy.checked_pools.push(name);
        }
        self.policy_draft.dirty = true;
    }

    pub fn policy_toggle_current(&mut self) {
        let idx = self.policy_draft.cursor;
        self.policy_toggle_at(idx);
    }

    pub fn policy_select_all(&mut self) {
        self.policy_draft.policy.checked_pools = self.policy_draft.known_pools.clone();
        self.policy_draft.dirty = true;
    }

    pub fn policy_clear_all(&mut self) {
        self.policy_draft.policy.checked_pools.clear();
        self.policy_draft.dirty = true;
    }

    pub fn policy_toggle_match(&mut self) {
        self.policy_draft.policy.match_mode = match self.policy_draft.policy.match_mode {
            PoolMatchMode::Any => PoolMatchMode::All,
            PoolMatchMode::All => PoolMatchMode::Any,
        };
        self.policy_draft.dirty = true;
    }

    pub fn policy_toggle_enabled(&mut self) {
        self.policy_draft.policy.enabled = !self.policy_draft.policy.enabled;
        self.policy_draft.dirty = true;
    }

    pub fn policy_adjust_threshold(&mut self, delta: i16) {
        let next = ((self.policy_draft.policy.threshold_pct as i16) + delta).clamp(0, 100) as u8;
        self.policy_draft.policy.threshold_pct = next;
        self.policy_draft.dirty = true;
    }

    pub fn policy_adjust_max_age(&mut self, delta_secs: i64) {
        let cur = self.policy_draft.policy.max_age_secs as i64;
        self.policy_draft.policy.max_age_secs = (cur + delta_secs).clamp(60, 86_400) as u64;
        self.policy_draft.dirty = true;
    }

    pub fn persist_settings(&mut self, store: &Store) -> Result<(), String> {
        let mut base = store
            .load_settings()
            .ok()
            .and_then(|s| serde_json::to_value(&s).ok())
            .unwrap_or_else(|| self.settings_json.clone());
        if let Some(obj) = base.as_object_mut() {
            if let Ok(pol_val) = serde_json::to_value(&self.policy_draft.policy) {
                let mut wrote = false;
                for key in [
                    "pool_failover",
                    "pool_failover_policy",
                    "failover_policy",
                    "quota_policy",
                ] {
                    if obj.contains_key(key) {
                        obj.insert(key.to_string(), pol_val.clone());
                        wrote = true;
                    }
                }
                if !wrote {
                    obj.insert("pool_failover".to_string(), pol_val);
                }
            }
            let mode_str = match self.switch_mode {
                SwitchMode::Auto => "auto",
                SwitchMode::Manual => "manual",
            };
            obj.insert("switch_mode".to_string(), serde_json::Value::String(mode_str.to_string()));
            if let Some(ui) = obj.get_mut("ui").and_then(|v| v.as_object_mut()) {
                ui.insert("split_offset".to_string(), serde_json::Value::from(self.split_offset));
                ui.insert("stack_offset".to_string(), serde_json::Value::from(self.stack_offset));
            } else {
                obj.insert("split_offset".to_string(), serde_json::Value::from(self.split_offset));
                obj.insert("stack_offset".to_string(), serde_json::Value::from(self.stack_offset));
            }
        }
        let parsed: agy_core::Settings =
            serde_json::from_value(base.clone()).map_err(|e| e.to_string())?;
        store.save_settings(&parsed).map_err(|e| e.to_string())?;
        self.settings_json = base;
        self.policy_draft.dirty = false;
        Ok(())
    }

    pub fn show_toast(&mut self, msg: impl Into<String>, level: ToastLevel, now_ms: u64) {
        let message = msg.into();
        self.status_line = Some((message.clone(), level));
        self.toast = Some(Toast { message, level, expires_at_ms: now_ms.saturating_add(3_200) });
    }

    pub fn expire_toast(&mut self, now_ms: u64) -> bool {
        if let Some(ref t) = self.toast {
            if now_ms >= t.expires_at_ms {
                self.toast = None;
                return true;
            }
        }
        false
    }

    pub fn filtered_palette(&self, query: &str) -> Vec<PaletteEntry> {
        let q = query.trim().to_lowercase();
        let mut out = Vec::new();
        for item in PALETTE_CATALOG {
            if q.is_empty()
                || contains_fold(item.label, &q)
                || contains_fold(item.description, &q)
                || contains_fold(item.section, &q)
                || contains_fold(item.shortcut, &q)
            {
                out.push(*item);
            }
        }
        out
    }
}
