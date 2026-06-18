#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::{anyhow, Result};
use futures_util::StreamExt;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::{
    env, fs,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Window};
use tokio::sync::watch;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
mod common_store_windows {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../store-module/tauri-shell/src-tauri/src/common_store_windows.rs"
    ));
}

static PROMPT_TEMPLATE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../app/prompt.md"));

static STREAM_CANCEL: OnceLock<Mutex<HashMap<String, watch::Sender<bool>>>> = OnceLock::new();

static APP_HANDLE: OnceLock<AppHandle> = OnceLock::new();

static LOG_FILE: OnceLock<Mutex<std::fs::File>> = OnceLock::new();
static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();
static LOG_SEQ: AtomicU64 = AtomicU64::new(1);

static TRIAL_USAGE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static TRIAL_TOKEN_SEQ: AtomicU64 = AtomicU64::new(1);
static CHAT_USAGE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static CHAT_TOKEN_SEQ: AtomicU64 = AtomicU64::new(1);
static USAGE_ACCESS_CACHE: OnceLock<Mutex<Option<UsageAccess>>> = OnceLock::new();

const FREE_ANALYSIS_LIMIT: u32 = 3;
const FREE_CHAT_LIMIT: u32 = 10;
const LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;
const LOG_BACKUPS: usize = 3;
const FEATURE_FILE_NAME: &str = "llmshark_feature.json";

fn init_log_file() -> Option<PathBuf> {
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(d) = exe_dir {
        candidates.push(d.join("llmshark.log"));
    }
    candidates.push(env::temp_dir().join("llmshark").join("llmshark.log"));

    for p in candidates {
        if let Some(dir) = p.parent() {
            let _ = fs::create_dir_all(dir);
        }
        if let Ok(f) = OpenOptions::new().create(true).append(true).open(&p) {
            let _ = LOG_PATH.set(p.clone());
            let _ = LOG_FILE.set(Mutex::new(f));
            return Some(p);
        }
    }

    None
}

fn log_backup_path(p: &Path, idx: usize) -> Option<PathBuf> {
    let name = p.file_name()?.to_string_lossy().to_string();
    Some(p.with_file_name(format!("{name}.{idx}")))
}

fn rotate_log_if_needed(f: &mut std::fs::File) {
    let Some(path) = LOG_PATH.get() else {
        return;
    };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    if size < LOG_MAX_BYTES {
        return;
    }

    for i in (1..=LOG_BACKUPS).rev() {
        let Some(dst) = log_backup_path(path, i) else {
            continue;
        };
        if i == LOG_BACKUPS {
            let _ = fs::remove_file(&dst);
        }
        let src = if i == 1 {
            path.clone()
        } else {
            match log_backup_path(path, i - 1) {
                Some(p) => p,
                None => continue,
            }
        };
        if src.exists() {
            let _ = fs::copy(&src, &dst);
        }
    }

    let _ = f.set_len(0);
    let _ = f.seek(SeekFrom::Start(0));
}

fn log_line(level: &str, msg: &str) {
    let Some(m) = LOG_FILE.get() else {
        return;
    };
    let Ok(mut f) = m.lock() else {
        return;
    };
    rotate_log_if_needed(&mut f);
    let ts = chrono::Local::now().to_rfc3339();
    let _ = writeln!(f, "{ts} [{level}] {msg}");
    let _ = f.flush();
}

fn sanitize_log_value(s: &str) -> String {
    let mut out = s.replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t");
    if out.len() > 800 {
        out.truncate(800);
        out.push_str("...");
    }
    out
}

fn log_event(level: &str, event: &str, fields: Vec<(&str, String)>) {
    let mut line = format!("event={event}");
    for (k, v) in fields {
        line.push(' ');
        line.push_str(k);
        line.push('=');
        line.push_str(&sanitize_log_value(&v));
    }
    log_line(level, &line);
}

fn init_logging() {
    let p = init_log_file();

    let exe = env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    let cwd = env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    log_line(
        "INFO",
        &format!(
            "startup exe={:?} cwd={:?} log={:?}",
            exe,
            cwd,
            p.map(|p| p.to_string_lossy().to_string())
        ),
    );
    log_event(
        "INFO",
        "startup_env",
        vec![
            ("pid", std::process::id().to_string()),
            ("version", env!("CARGO_PKG_VERSION").to_string()),
            ("os", env::consts::OS.to_string()),
            ("arch", env::consts::ARCH.to_string()),
            ("debug", cfg!(debug_assertions).to_string()),
        ],
    );

    std::panic::set_hook(Box::new(|info| {
        log_line("PANIC", &format!("{info}"));
    }));
}

fn stream_cancel_map() -> &'static Mutex<HashMap<String, watch::Sender<bool>>> {
    STREAM_CANCEL.get_or_init(|| Mutex::new(HashMap::new()))
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlmConfig {
    endpoint: String,
    api_key: String,
    model: String,
    temperature: f64,
    #[serde(default = "default_true")]
    use_kb: bool,
    #[serde(default)]
    ui_lang: Option<String>,
    #[serde(default = "default_true")]
    prompt_auto: bool,
    #[serde(default)]
    prompt_path: Option<String>,
}

const TRIAL_API_KEY_PLACEHOLDER: &str = "__LLMSHARK_TRIAL_KEY__";
/// 编译时从环境变量 LLMSHARK_SF_TRIAL_KEY 注入试用密钥；未设置时回退 "sk-"（仅开发/调试用）。
const BUILTIN_SF_TRIAL_API_KEY: &str = match option_env!("LLMSHARK_SF_TRIAL_KEY") {
    Some(v) => v,
    None => "sk-",
};

fn materialize_trial_cfg(mut cfg: LlmConfig) -> LlmConfig {
    if cfg.api_key.trim() == TRIAL_API_KEY_PLACEHOLDER {
        cfg.api_key = BUILTIN_SF_TRIAL_API_KEY.to_string();
        if cfg.endpoint.trim().is_empty() {
            cfg.endpoint = "https://api.siliconflow.cn".to_string();
        }
        if cfg.model.trim().is_empty() {
            cfg.model = "Deepseek-ai/DeepSeek-V4-Flash".to_string();
        }
    }
    cfg
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct BridgeMessage {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "productId")]
    product_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LicenseStatusDto {
    ok: bool,
    reason: Option<String>,
    name: Option<String>,
    expire: Option<String>,
    kind: Option<String>,
}

fn license_candidate_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();

    if let Ok(p) = env::var("LLMSHARK_LICENSE") {
        let p = p.trim().to_string();
        if !p.is_empty() {
            out.push(PathBuf::from(p));
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = env::var_os("APPDATA") {
            out.push(
                PathBuf::from(appdata)
                    .join("LLM-Shark")
                    .join("license.json"),
            );
        }
    }

    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join("license.json"));
            out.push(dir.join("resources").join("license.json"));
        }
    }

    if let Ok(cwd) = env::current_dir() {
        out.push(cwd.join("license.json"));
    }

    out
}

fn license_existing_files() -> Vec<PathBuf> {
    license_candidate_paths()
        .into_iter()
        .filter(|p| p.is_file())
        .collect()
}

fn preferred_license_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = env::var_os("APPDATA") {
            let p = PathBuf::from(appdata)
                .join("LLM-Shark")
                .join("license.json");
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            return p;
        }
    }

    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join("license.json");
        }
    }

    PathBuf::from("license.json")
}

fn preferred_feature_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = env::var_os("APPDATA") {
            let p = PathBuf::from(appdata)
                .join("LLM-Shark")
                .join(FEATURE_FILE_NAME);
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            return p;
        }
    }

    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join(FEATURE_FILE_NAME);
        }
    }

    if let Ok(cwd) = env::current_dir() {
        return cwd.join(FEATURE_FILE_NAME);
    }

    PathBuf::from(FEATURE_FILE_NAME)
}

fn ensure_feature_file() -> Result<(), String> {
    let p = preferred_feature_path();
    if p.is_file() {
        let len = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        if len > 0 {
            log_event(
                "INFO",
                "feature_file_exists",
                vec![
                    ("path", p.to_string_lossy().to_string()),
                    ("len", len.to_string()),
                ],
            );
            return Ok(());
        }
    }

    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }

    llm_license::export_feature_signature(Path::new(&p)).map_err(|e| e.to_string())?;
    let len = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
    log_event(
        "INFO",
        "feature_file_created",
        vec![
            ("path", p.to_string_lossy().to_string()),
            ("len", len.to_string()),
        ],
    );
    Ok(())
}

fn compute_license_status() -> LicenseStatusDto {
    let mut first_reason: Option<String> = None;

    for path in license_existing_files() {
        let vr = match llm_license::verify_license(Path::new(&path)) {
            Ok(v) => v,
            Err(e) => {
                if first_reason.is_none() {
                    first_reason = Some(e.to_string());
                }
                continue;
            }
        };

        if vr.ok {
            let (name, expire, kind) = vr
                .payload
                .as_ref()
                .map(|p| {
                    let k = match p.license.kind {
                        Some(llm_license::LicenseKind::Trial) => Some("trial".to_string()),
                        Some(llm_license::LicenseKind::Full) => Some("full".to_string()),
                        None => None,
                    };
                    (
                        Some(p.license.name.clone()),
                        Some(p.license.expire.clone()),
                        k,
                    )
                })
                .unwrap_or((None, None, None));

            return LicenseStatusDto {
                ok: true,
                reason: None,
                name,
                expire,
                kind,
            };
        }

        if first_reason.is_none() {
            first_reason = vr
                .reason
                .clone()
                .or(Some("license verify failed".to_string()));
        }
    }

    if let Some(reason) = first_reason {
        return LicenseStatusDto {
            ok: false,
            reason: Some(reason),
            name: None,
            expire: None,
            kind: None,
        };
    }

    LicenseStatusDto {
        ok: false,
        reason: Some("未找到授权文件".to_string()),
        name: None,
        expire: None,
        kind: None,
    }
}

#[derive(Clone)]
struct VerifiedLicense {
    path: PathBuf,
    license_id: String,
    kind: Option<llm_license::LicenseKind>,
    trial_limit: u32,
    name: Option<String>,
    expire: Option<String>,
}

#[derive(Clone)]
struct UsageLimits {
    license_id: String,
    analysis_limit: u32,
    chat_limit: u32,
}

#[derive(Clone)]
struct UsageAccess {
    limits: Option<UsageLimits>,
    license_path: Option<PathBuf>,
    subscription_type: Option<String>,
    auth_state: String,
    license_name: Option<String>,
    license_expire: Option<String>,
    license_kind: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct UsageAuthStateDto {
    state: String,
    subscription_type: Option<String>,
    license_name: Option<String>,
    license_expire: Option<String>,
    license_kind: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct MobileAuthQrDto {
    payload: String,
    qr_svg: String,
    qr_expires_at: i64,
    public_key_pem: String,
}

fn verify_local_license() -> Result<Option<VerifiedLicense>, String> {
    for path in license_existing_files() {
        let vr = match llm_license::verify_license(Path::new(&path)) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !vr.ok {
            continue;
        }

        let Some(license_id) = vr.license_id.clone() else {
            continue;
        };
        let trial_limit = vr.trial_daily_pcap_limit.unwrap_or(3);
        let (name, expire) = vr
            .payload
            .as_ref()
            .map(|p| (Some(p.license.name.clone()), Some(p.license.expire.clone())))
            .unwrap_or((None, None));

        return Ok(Some(VerifiedLicense {
            path,
            license_id,
            kind: vr.kind,
            trial_limit,
            name,
            expire,
        }));
    }

    Ok(None)
}

#[cfg(target_os = "windows")]
async fn get_store_subscription_type() -> Option<String> {
    let Some(app) = APP_HANDLE.get() else {
        return None;
    };
    let cfg = common_store_windows::StoreConfig::from_conf();
    let out = common_store_windows::entitlement_status(app, &cfg).await;
    let Ok(v) = out else {
        return None;
    };
    let ok = v.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    if !ok {
        return None;
    }
    let t = v
        .get("entitlement")
        .and_then(|e| e.get("type"))
        .and_then(|v| v.as_str())?;
    
    if matches!(t, "pro_month" | "pro_year") {
        Some(t.to_string())
    } else {
        None
    }
}

#[cfg(not(target_os = "windows"))]
async fn get_store_subscription_type() -> Option<String> {
    None
}

fn usage_access_cache() -> &'static Mutex<Option<UsageAccess>> {
    USAGE_ACCESS_CACHE.get_or_init(|| Mutex::new(None))
}

fn cached_usage_access() -> Option<UsageAccess> {
    usage_access_cache()
        .lock()
        .ok()
        .and_then(|g| g.as_ref().cloned())
}

fn set_cached_usage_access(access: UsageAccess) {
    if let Ok(mut g) = usage_access_cache().lock() {
        *g = Some(access);
    }
}

async fn compute_usage_access_once() -> Result<UsageAccess, String> {
    if let Some(sub_type) = get_store_subscription_type().await {
        return Ok(UsageAccess {
            limits: None,
            license_path: None,
            subscription_type: Some(sub_type),
            auth_state: "online_active".to_string(),
            license_name: None,
            license_expire: None,
            license_kind: None,
        });
    }

    if let Some(info) = verify_local_license()? {
        if matches!(info.kind, Some(llm_license::LicenseKind::Trial)) {
            return Ok(UsageAccess {
                limits: Some(UsageLimits {
                    license_id: info.license_id,
                    analysis_limit: info.trial_limit,
                    chat_limit: FREE_CHAT_LIMIT,
                }),
                license_path: Some(info.path),
                subscription_type: None,
                auth_state: "offline_trial".to_string(),
                license_name: info.name,
                license_expire: info.expire,
                license_kind: Some("trial".to_string()),
            });
        }

        return Ok(UsageAccess {
            limits: None,
            license_path: Some(info.path),
            subscription_type: None,
            auth_state: "offline_full".to_string(),
            license_name: info.name,
            license_expire: info.expire,
            license_kind: Some("full".to_string()),
        });
    }

    Ok(UsageAccess {
        limits: Some(UsageLimits {
            license_id: "free".to_string(),
            analysis_limit: FREE_ANALYSIS_LIMIT,
            chat_limit: FREE_CHAT_LIMIT,
        }),
        license_path: None,
        subscription_type: None,
        auth_state: "free".to_string(),
        license_name: None,
        license_expire: None,
        license_kind: None,
    })
}

async fn init_usage_access_cache() -> Result<(), String> {
    let access = compute_usage_access_once().await?;
    set_cached_usage_access(access.clone());
    log_event(
        "INFO",
        "usage_access_cached",
        vec![
            ("state", access.auth_state),
            (
                "subscription_type",
                access.subscription_type.unwrap_or_default(),
            ),
            (
                "has_license",
                access.license_path.is_some().to_string(),
            ),
        ],
    );
    Ok(())
}

async fn resolve_usage_access() -> Result<UsageAccess, String> {
    if let Some(access) = cached_usage_access() {
        return Ok(access);
    }
    let access = compute_usage_access_once().await?;
    set_cached_usage_access(access.clone());
    Ok(access)
}

fn get_max_pcap_size_kb(access: &UsageAccess) -> u64 {
    // Free/Trial: 1MB = 1024KB
    // Pro Month: 5MB = 5120KB
    // Pro Year: 10MB = 10240KB
    if let Some(sub_type) = &access.subscription_type {
        match sub_type.as_str() {
            "pro_year" => 10240,
            "pro_month" => 5120,
            _ => 1024,
        }
    } else if access.license_path.is_some() {
        // Full license (non-trial)
        10240
    } else {
        // Free or Trial
        1024
    }
}

fn require_report_token(report: &Value) -> Result<String, String> {
    report
        .get("trial_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "需要重新执行诊断".to_string())
}

fn require_report_license_id(report: &Value) -> Result<String, String> {
    let token = require_report_token(report)?;
    let Some((license_id, day)) = parse_trial_token(&token) else {
        return Err("token 无效，请重新执行诊断".to_string());
    };
    let today = trial_today();
    if day != today {
        return Err("token 已过期，请重新执行诊断".to_string());
    }
    Ok(license_id)
}

async fn resolve_llm_analysis_trial(report: &Value) -> Result<Option<LlmCommit>, String> {
    let access = resolve_usage_access().await?;
    let Some(lim) = access.limits.as_ref() else {
        return Ok(None);
    };
    let token = require_report_token(report)?;
    trial_can_start_llm(&token, lim.analysis_limit)?;
    Ok(Some(LlmCommit::Analysis {
        token,
        limit: lim.analysis_limit,
    }))
}

async fn resolve_llm_chat_trial(report: &Value) -> Result<Option<LlmCommit>, String> {
    let access = resolve_usage_access().await?;
    let Some(lim) = access.limits.as_ref() else {
        return Ok(None);
    };
    let license_id = require_report_license_id(report)?;
    let token = chat_reserve_for_llm(&license_id, lim.chat_limit)?;
    Ok(Some(LlmCommit::Chat {
        token,
        limit: lim.chat_limit,
    }))
}

fn trial_usage_lock() -> &'static Mutex<()> {
    TRIAL_USAGE_LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrialUsageReservation {
    created_ts: i64,
    committed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrialUsageFile {
    day: String,
    committed: u32,
    reservations: HashMap<String, TrialUsageReservation>,
}

fn trial_today() -> String {
    chrono::Utc::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string()
}

fn dpapi_protect(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    #[cfg(target_os = "windows")]
    {
        use windows::core::{Array, HSTRING};
        use windows::Security::Cryptography::CryptographicBuffer;
        use windows::Security::Cryptography::DataProtection::DataProtectionProvider;
        let provider = DataProtectionProvider::CreateOverloadExplicit(&HSTRING::from("LOCAL=user")).ok()?;
        let input = CryptographicBuffer::CreateFromByteArray(data).ok()?;
        let out_buffer = provider.ProtectAsync(&input).ok()?.get().ok()?;
        let mut out = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&out_buffer, &mut out).ok()?;
        return Some(out.as_slice().to_vec());
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(data.to_vec())
    }
}

fn dpapi_unprotect(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    #[cfg(target_os = "windows")]
    {
        use windows::core::{Array, HSTRING};
        use windows::Security::Cryptography::CryptographicBuffer;
        use windows::Security::Cryptography::DataProtection::DataProtectionProvider;
        let provider = DataProtectionProvider::CreateOverloadExplicit(&HSTRING::from("LOCAL=user")).ok()?;
        let input = CryptographicBuffer::CreateFromByteArray(data).ok()?;
        let out_buffer = provider.UnprotectAsync(&input).ok()?.get().ok()?;
        let mut out = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&out_buffer, &mut out).ok()?;
        return Some(out.as_slice().to_vec());
    }
    #[cfg(not(target_os = "windows"))]
    {
        Some(data.to_vec())
    }
}

fn usage_meta_path(prefix: &str, license_id: &str) -> PathBuf {
    trial_usage_dir().join(format!("{prefix}{license_id}.meta"))
}

fn usage_meta_exists(prefix: &str, license_id: &str) -> bool {
    fs::metadata(usage_meta_path(prefix, license_id)).is_ok()
}

fn write_usage_meta(prefix: &str, license_id: &str) -> Result<(), String> {
    let dir = trial_usage_dir();
    let _ = fs::create_dir_all(&dir);
    let p = usage_meta_path(prefix, license_id);
    let raw = serde_json::to_vec(&serde_json::json!({"v": 1})).map_err(|e| e.to_string())?;
    let enc = dpapi_protect(&raw).ok_or_else(|| "usage meta protect failed".to_string())?;
    fs::write(&p, enc).map_err(|e| e.to_string())
}

fn trial_usage_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = env::var_os("APPDATA") {
            return PathBuf::from(appdata).join("LLM-Shark").join("trial_usage");
        }
    }

    env::temp_dir().join("llmshark").join("trial_usage")
}

fn trial_usage_path(license_id: &str) -> PathBuf {
    trial_usage_dir().join(format!("{license_id}.json"))
}

fn load_trial_usage(license_id: &str) -> Result<TrialUsageFile, String> {
    let today = trial_today();
    let p = trial_usage_path(license_id);
    let mut u = if let Ok(raw) = fs::read(&p) {
        let parsed = if let Some(dec) = dpapi_unprotect(&raw) {
            serde_json::from_slice::<TrialUsageFile>(&dec).ok()
        } else if !usage_meta_exists("", license_id) {
            serde_json::from_slice::<TrialUsageFile>(&raw).ok()
        } else {
            None
        };
        parsed.ok_or_else(|| "usage file invalid".to_string())?
    } else {
        if usage_meta_exists("", license_id) {
            return Err("usage file missing".to_string());
        }
        TrialUsageFile {
            day: today.clone(),
            committed: 0,
            reservations: HashMap::new(),
        }
    };

    if u.day != today {
        u.day = today;
        u.committed = 0;
        u.reservations.clear();
    }

    let now = chrono::Utc::now().timestamp();
    let ttl = 12 * 3600;
    u.reservations
        .retain(|_, r| r.committed || now.saturating_sub(r.created_ts) <= ttl);

    if u.reservations.len() > 200 {
        let mut items: Vec<(String, TrialUsageReservation)> = u.reservations.drain().collect();
        items.sort_by_key(|(_, r)| r.created_ts);
        for (k, v) in items.into_iter().rev().take(200) {
            u.reservations.insert(k, v);
        }
    }

    Ok(u)
}

fn save_trial_usage(license_id: &str, u: &TrialUsageFile) -> Result<(), String> {
    let dir = trial_usage_dir();
    let _ = fs::create_dir_all(&dir);
    let p = trial_usage_path(license_id);
    let raw = serde_json::to_vec(u).map_err(|e| e.to_string())?;
    let enc = dpapi_protect(&raw).ok_or_else(|| "usage protect failed".to_string())?;
    fs::write(&p, enc).map_err(|e| e.to_string())?;
    write_usage_meta("", license_id)
}

fn parse_trial_token(token: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    Some((parts[0].to_string(), parts[1].to_string()))
}

fn trial_reserve_for_pcap(license_id: &str, limit: u32) -> Result<String, String> {
    let _g = trial_usage_lock()
        .lock()
        .map_err(|_| "lock failed".to_string())?;
    let mut u = load_trial_usage(license_id)?;

    if u.committed >= limit {
        return Err(format!("今日PCAP处理已达上限({limit}次)"));
    }

    let day = u.day.clone();
    let seq = TRIAL_TOKEN_SEQ.fetch_add(1, Ordering::Relaxed);
    let token = format!("{license_id}:{day}:{seq}");
    u.reservations
        .entry(token.clone())
        .or_insert(TrialUsageReservation {
            created_ts: chrono::Utc::now().timestamp(),
            committed: false,
        });

    save_trial_usage(license_id, &u)?;
    Ok(token)
}

fn trial_cleanup_reservation(token: &str) {
    let Some((license_id, day)) = parse_trial_token(token) else {
        return;
    };
    let today = trial_today();
    if day != today {
        return;
    }

    let Ok(_g) = trial_usage_lock().lock() else {
        return;
    };
    let mut u = match load_trial_usage(&license_id) {
        Ok(v) => v,
        Err(_) => return,
    };
    if let Some(r) = u.reservations.get(token) {
        if r.committed {
            return;
        }
    } else {
        return;
    }

    u.reservations.remove(token);
    let _ = save_trial_usage(&license_id, &u);
}

fn trial_can_start_llm(token: &str, limit: u32) -> Result<(), String> {
    let Some((license_id, day)) = parse_trial_token(token) else {
        return Err("token 无效，请重新执行诊断".to_string());
    };
    let today = trial_today();
    if day != today {
        return Err("token 已过期，请重新执行诊断".to_string());
    }

    let _g = trial_usage_lock()
        .lock()
        .map_err(|_| "lock failed".to_string())?;
    let u = load_trial_usage(&license_id)?;

    let Some(r) = u.reservations.get(token) else {
        return Err("token 不存在，请重新执行诊断".to_string());
    };

    if r.committed {
        return Ok(());
    }

    if u.committed >= limit {
        return Err(format!("今日PCAP处理已达上限({limit}次)"));
    }

    Ok(())
}

fn trial_commit(token: &str, limit: u32) -> Result<(), String> {
    let Some((license_id, day)) = parse_trial_token(token) else {
        return Err("token 无效".to_string());
    };
    let today = trial_today();
    if day != today {
        return Err("token 已过期".to_string());
    }

    let _g = trial_usage_lock()
        .lock()
        .map_err(|_| "lock failed".to_string())?;
    let mut u = load_trial_usage(&license_id)?;

    let Some(r) = u.reservations.get_mut(token) else {
        return Err("token 不存在".to_string());
    };

    if r.committed {
        return Ok(());
    }

    if u.committed >= limit {
        return Err(format!("今日PCAP处理已达上限({limit}次)"));
    }

    r.committed = true;
    u.committed = u.committed.saturating_add(1);
    save_trial_usage(&license_id, &u)
}

fn chat_usage_lock() -> &'static Mutex<()> {
    CHAT_USAGE_LOCK.get_or_init(|| Mutex::new(()))
}

fn chat_usage_path(license_id: &str) -> PathBuf {
    trial_usage_dir().join(format!("chat_{license_id}.json"))
}

fn load_chat_usage(license_id: &str) -> Result<TrialUsageFile, String> {
    let today = trial_today();
    let p = chat_usage_path(license_id);
    let mut u = if let Ok(raw) = fs::read(&p) {
        let parsed = if let Some(dec) = dpapi_unprotect(&raw) {
            serde_json::from_slice::<TrialUsageFile>(&dec).ok()
        } else if !usage_meta_exists("chat_", license_id) {
            serde_json::from_slice::<TrialUsageFile>(&raw).ok()
        } else {
            None
        };
        parsed.ok_or_else(|| "usage file invalid".to_string())?
    } else {
        if usage_meta_exists("chat_", license_id) {
            return Err("usage file missing".to_string());
        }
        TrialUsageFile {
            day: today.clone(),
            committed: 0,
            reservations: HashMap::new(),
        }
    };

    if u.day != today {
        u.day = today;
        u.committed = 0;
        u.reservations.clear();
    }

    let now = chrono::Utc::now().timestamp();
    let ttl = 12 * 3600;
    u.reservations
        .retain(|_, r| r.committed || now.saturating_sub(r.created_ts) <= ttl);

    if u.reservations.len() > 200 {
        let mut items: Vec<(String, TrialUsageReservation)> = u.reservations.drain().collect();
        items.sort_by_key(|(_, r)| r.created_ts);
        for (k, v) in items.into_iter().rev().take(200) {
            u.reservations.insert(k, v);
        }
    }

    Ok(u)
}

fn save_chat_usage(license_id: &str, u: &TrialUsageFile) -> Result<(), String> {
    let dir = trial_usage_dir();
    let _ = fs::create_dir_all(&dir);
    let p = chat_usage_path(license_id);
    let raw = serde_json::to_vec(u).map_err(|e| e.to_string())?;
    let enc = dpapi_protect(&raw).ok_or_else(|| "usage protect failed".to_string())?;
    fs::write(&p, enc).map_err(|e| e.to_string())?;
    write_usage_meta("chat_", license_id)
}

fn chat_reserve_for_llm(license_id: &str, limit: u32) -> Result<String, String> {
    let _g = chat_usage_lock()
        .lock()
        .map_err(|_| "lock failed".to_string())?;
    let mut u = load_chat_usage(license_id)?;

    if u.committed >= limit {
        return Err(format!("今日追问已达上限({limit}次)"));
    }

    let day = u.day.clone();
    let seq = CHAT_TOKEN_SEQ.fetch_add(1, Ordering::Relaxed);
    let token = format!("{license_id}:{day}:{seq}");
    u.reservations
        .entry(token.clone())
        .or_insert(TrialUsageReservation {
            created_ts: chrono::Utc::now().timestamp(),
            committed: false,
        });

    save_chat_usage(license_id, &u)?;
    Ok(token)
}

fn chat_cleanup_reservation(token: &str) {
    let Some((license_id, day)) = parse_trial_token(token) else {
        return;
    };
    let today = trial_today();
    if day != today {
        return;
    }

    let Ok(_g) = chat_usage_lock().lock() else {
        return;
    };
    let mut u = match load_chat_usage(&license_id) {
        Ok(v) => v,
        Err(_) => return,
    };
    if let Some(r) = u.reservations.get(token) {
        if r.committed {
            return;
        }
    } else {
        return;
    }

    u.reservations.remove(token);
    let _ = save_chat_usage(&license_id, &u);
}

fn chat_commit(token: &str, limit: u32) -> Result<(), String> {
    let Some((license_id, day)) = parse_trial_token(token) else {
        return Err("token 无效".to_string());
    };
    let today = trial_today();
    if day != today {
        return Err("token 已过期".to_string());
    }

    let _g = chat_usage_lock()
        .lock()
        .map_err(|_| "lock failed".to_string())?;
    let mut u = load_chat_usage(&license_id)?;

    let Some(r) = u.reservations.get_mut(token) else {
        return Err("token 不存在".to_string());
    };

    if r.committed {
        return Ok(());
    }

    if u.committed >= limit {
        return Err(format!("今日追问已达上限({limit}次)"));
    }

    r.committed = true;
    u.committed = u.committed.saturating_add(1);
    save_chat_usage(&license_id, &u)
}

fn normalize_chat_completions_url(endpoint: &str) -> String {
    let e = endpoint.trim().trim_end_matches('/');
    if e.ends_with("/chat/completions") {
        e.to_string()
    } else if e.ends_with("/v1") {
        format!("{e}/chat/completions")
    } else {
        format!("{e}/v1/chat/completions")
    }
}

fn read_prompt_template(prompt_auto: bool, prompt_path: Option<&str>) -> Result<String> {
    if prompt_auto {
        if let Some(p) = prompt_path.map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let pb = PathBuf::from(p);
            if pb.is_file() {
                if let Ok(s) = fs::read_to_string(&pb) {
                    return Ok(s);
                }
            }
        } else if let Ok(exe) = env::current_exe() {
            if let Some(dir) = exe.parent() {
                let p = dir.join("prompt.md");
                if p.is_file() {
                    if let Ok(s) = fs::read_to_string(&p) {
                        return Ok(s);
                    }
                }
            }
        }
    }

    Ok(PROMPT_TEMPLATE.to_string())
}

fn ui_lang_hint(ui_lang: Option<&str>) -> String {
    let s = ui_lang.unwrap_or("").trim().to_ascii_lowercase();
    if s.is_empty() {
        "（中文）".to_string()
    } else if s.starts_with("zh") {
        "（中文）".to_string()
    } else if s.starts_with("en") {
        "（English）".to_string()
    } else if s.starts_with("fr") {
        "（Français）".to_string()
    } else if s.starts_with("de") {
        "（Deutsch）".to_string()
    } else if s.starts_with("it") {
        "（Italiano）".to_string()
    } else if s.starts_with("ru") {
        "（Русский）".to_string()
    } else if s.starts_with("fa") {
        "（فارسی）".to_string()
    } else if s.starts_with("ar") {
        "（العربية）".to_string()
    } else if s.starts_with("ja") || s.starts_with("jp") {
        "（日本語）".to_string()
    } else if s.starts_with("ko") || s.starts_with("kr") {
        "（한국어）".to_string()
    } else if s.starts_with("es") {
        "（Español）".to_string()
    } else if s.starts_with("pt") {
        "（Português）".to_string()
    } else if s.starts_with("nl") {
        "（Nederlands）".to_string()
    } else if s.starts_with("pl") {
        "（Polski）".to_string()
    } else if s.starts_with("tr") {
        "（Türkçe）".to_string()
    } else if s.starts_with("ro") {
        "（Română）".to_string()
    } else if s.starts_with("hi") {
        "（हिन्दी）".to_string()
    } else if s.starts_with("id") {
        "（Bahasa Indonesia）".to_string()
    } else if s.starts_with("ms") {
        "（Bahasa Melayu）".to_string()
    } else if s.starts_with("th") {
        "（ไทย）".to_string()
    } else if s.starts_with("vi") {
        "（Tiếng Việt）".to_string()
    } else {
        "（English）".to_string()
    }
}

fn build_prompt(
    mut template: String,
    report: &Value,
    use_kb: bool,
    ui_lang: Option<&str>,
) -> String {
    let mut report_for_prompt = report.clone();
    if let Some(obj) = report_for_prompt.as_object_mut() {
        obj.remove("kb");
        obj.remove("outputs");
        obj.remove("mermaid_text");
        obj.remove("trial_token");
    }

    let report_json =
        serde_json::to_string_pretty(&report_for_prompt).unwrap_or_else(|_| "{}".to_string());
    let mermaid = report
        .get("mermaid_text")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let kb = report.get("kb").cloned().unwrap_or(Value::Null);
    let kb_block = if use_kb {
        let hits = kb
            .get("hits")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if hits.is_empty() {
            String::new()
        } else {
            let cleaned_hits: Vec<Value> = hits
                .into_iter()
                .map(|h| {
                    serde_json::json!({
                        "dna_id": h.get("dna_id").cloned().unwrap_or(Value::Null),
                        "case_numbers": h.get("case_numbers").cloned().unwrap_or(Value::Null),
                        "issue_location": h.get("issue_location").cloned().unwrap_or(Value::Null),
                        "diagnosis": h.get("diagnosis").cloned().unwrap_or(Value::Null),
                        "root_cause": h.get("root_cause").cloned().unwrap_or(Value::Null),
                        "call_process": h.get("call_process").cloned().unwrap_or(Value::Null)
                    })
                })
                .collect();

            let kb_json = serde_json::to_string_pretty(&serde_json::json!({"hits": cleaned_hits}))
                .unwrap_or_else(|_| "null".to_string());
            format!(
                r#"
<案例知识(已检索命中)>
```json
{kb_json}
```
"#
            )
        }
    } else {
        String::new()
    };

    let injected = format!(
        r#"
<JSON 数据>
```json
{report_json}
```
{kb_block}
<Mermaid 时序图>
```mermaid
{mermaid}
```
"#
    );

    template = template.replace("{程序插入}", &injected);
    template = template.replace("{UI-Lang}", &ui_lang_hint(ui_lang));
    template
}

fn build_system_prompt(
    report: &Value,
    use_kb: bool,
    ui_lang: Option<&str>,
    prompt_auto: bool,
    prompt_path: Option<&str>,
) -> Result<String> {
    let template = read_prompt_template(prompt_auto, prompt_path)?;
    Ok(build_prompt(template, report, use_kb, ui_lang))
}

fn normalize_chat_role(role: &str) -> Option<&'static str> {
    match role {
        "user" => Some("user"),
        "assistant" => Some("assistant"),
        _ => None,
    }
}

fn build_chat_messages(
    report: &Value,
    messages: Vec<ChatMessage>,
    use_kb: bool,
    ui_lang: Option<&str>,
    prompt_auto: bool,
    prompt_path: Option<&str>,
) -> Result<Vec<Value>> {
    let system_prompt = build_system_prompt(report, use_kb, ui_lang, prompt_auto, prompt_path)?;

    let mut out: Vec<Value> = Vec::with_capacity(messages.len() + 1);
    out.push(serde_json::json!({"role":"system","content": system_prompt}));

    for m in messages {
        let role = normalize_chat_role(m.role.trim())
            .ok_or_else(|| anyhow!("invalid role: {}", m.role))?;
        out.push(serde_json::json!({"role": role, "content": m.content}));
    }

    Ok(out)
}

fn can_use_plain_chat(access: &UsageAccess) -> bool {
    matches!(access.auth_state.as_str(), "online_active" | "offline_full")
}

async fn ensure_plain_chat_allowed() -> Result<(), String> {
    let access = resolve_usage_access().await?;
    if can_use_plain_chat(&access) {
        Ok(())
    } else {
        Err("该功能仅对订阅版或正式授权开放，请先升级后使用。".to_string())
    }
}

fn build_plain_system_prompt(ui_lang: Option<&str>) -> String {
    format!(
        "你是精通 4G/5G/IMS 信令分析的专家。当前没有 PCAP 与结构化信令数据，用户将以自然语言描述呼叫过程。\n要求：\n1) 仅基于用户描述推理，明确区分事实、推断与不确定项；\n2) 优先给出可执行的排查路径（抓包点、关键网元、应关注字段/错误码）；\n3) 不得编造具体错误码、时序消息或网元行为；\n4) 回答语言使用软件界面语言{}。",
        ui_lang_hint(ui_lang)
    )
}

fn build_plain_chat_messages(messages: Vec<ChatMessage>, ui_lang: Option<&str>) -> Result<Vec<Value>> {
    let system_prompt = build_plain_system_prompt(ui_lang);
    let mut out: Vec<Value> = Vec::with_capacity(messages.len() + 1);
    out.push(serde_json::json!({"role":"system","content": system_prompt}));
    for m in messages {
        let role = normalize_chat_role(m.role.trim())
            .ok_or_else(|| anyhow!("invalid role: {}", m.role))?;
        out.push(serde_json::json!({"role": role, "content": m.content}));
    }
    Ok(out)
}

fn llm_debug_log_path() -> PathBuf {
    std::env::temp_dir()
        .join("llmshark")
        .join("llm_requests.jsonl")
}

fn append_llm_debug_record(url: &str, body: &Value) {
    let p = llm_debug_log_path();
    if let Some(dir) = p.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let f = fs::OpenOptions::new().create(true).append(true).open(&p);
    let mut f = match f {
        Ok(v) => v,
        Err(_) => return,
    };
    let rec = serde_json::json!({
        "ts": chrono::Local::now().to_rfc3339(),
        "url": url,
        "body": body,
    });
    let _ = writeln!(f, "{}", rec);
}

async fn call_llm_messages(cfg: LlmConfig, messages: Vec<Value>) -> Result<String> {
    let request_id = LOG_SEQ.fetch_add(1, Ordering::Relaxed);
    let start = Instant::now();
    let endpoint = cfg.endpoint.trim().to_string();
    let model = cfg.model.trim().to_string();
    let temperature = cfg.temperature;
    let message_count = messages.len();
    if !(0.0..=2.0).contains(&cfg.temperature) {
        log_event(
            "ERROR",
            "llm_request_invalid",
            vec![
                ("id", request_id.to_string()),
                ("temperature", cfg.temperature.to_string()),
            ],
        );
        return Err(anyhow!("temperature 必须在 [0,2]"));
    }
    if cfg.endpoint.trim().is_empty() || cfg.model.trim().is_empty() {
        log_event(
            "ERROR",
            "llm_request_invalid",
            vec![
                ("id", request_id.to_string()),
                ("endpoint", endpoint.clone()),
                ("model", model.clone()),
            ],
        );
        return Err(anyhow!("endpoint/model 不能为空"));
    }

    let url = normalize_chat_completions_url(&cfg.endpoint);
    log_event(
        "INFO",
        "llm_request_start",
        vec![
            ("id", request_id.to_string()),
            ("endpoint", endpoint.clone()),
            ("model", model.clone()),
            ("temperature", temperature.to_string()),
            ("messages", message_count.to_string()),
            ("stream", "false".to_string()),
        ],
    );

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    if !cfg.api_key.trim().is_empty() {
        let v = format!("Bearer {}", cfg.api_key.trim());
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&v)?,
        );
    }

    let body = serde_json::json!({
      "model": cfg.model,
      "temperature": cfg.temperature,
      "stream": false,
      "messages": messages
    });

    append_llm_debug_record(&url, &body);

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(60))
        .timeout(Duration::from_secs(900))
        .build()?;

    let resp = client
        .post(url)
        .headers(headers)
        .json(&body)
        .send()
        .await
        .inspect_err(|e| {
            log_event(
                "ERROR",
                "llm_request_failed",
                vec![
                    ("id", request_id.to_string()),
                    ("duration_ms", start.elapsed().as_millis().to_string()),
                    ("error", e.to_string()),
                ],
            );
        })?;
    let status = resp.status();
    let text = resp.text().await?;

    if !status.is_success() {
        log_event(
            "ERROR",
            "llm_request_failed",
            vec![
                ("id", request_id.to_string()),
                ("duration_ms", start.elapsed().as_millis().to_string()),
                ("status", status.as_u16().to_string()),
                ("body_len", text.len().to_string()),
            ],
        );
        return Err(anyhow!("LLM 请求失败: {} {}", status.as_u16(), text));
    }

    let v: Value = serde_json::from_str(&text).inspect_err(|e| {
        log_event(
            "ERROR",
            "llm_response_invalid",
            vec![
                ("id", request_id.to_string()),
                ("duration_ms", start.elapsed().as_millis().to_string()),
                ("error", e.to_string()),
            ],
        );
    })?;
    let content = v["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("")
        .to_string();
    if content.trim().is_empty() {
        log_event(
            "ERROR",
            "llm_response_empty",
            vec![
                ("id", request_id.to_string()),
                ("duration_ms", start.elapsed().as_millis().to_string()),
            ],
        );
        return Err(anyhow!("LLM 返回为空"));
    }
    log_event(
        "INFO",
        "llm_request_done",
        vec![
            ("id", request_id.to_string()),
            ("duration_ms", start.elapsed().as_millis().to_string()),
            ("output_len", content.len().to_string()),
        ],
    );
    Ok(content)
}

enum LlmCommit {
    Analysis { token: String, limit: u32 },
    Chat { token: String, limit: u32 },
}

fn commit_llm_usage(commit: &LlmCommit) -> Result<(), String> {
    match commit {
        LlmCommit::Analysis { token, limit } => trial_commit(token, *limit),
        LlmCommit::Chat { token, limit } => chat_commit(token, *limit),
    }
}

struct ChatGuard {
    token: Option<String>,
    keep: bool,
}

impl Drop for ChatGuard {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        if let Some(t) = self.token.as_deref() {
            chat_cleanup_reservation(t);
        }
    }
}

async fn call_llm_stream_messages(
    window: &Window,
    cfg: LlmConfig,
    messages: Vec<Value>,
    commit: Option<LlmCommit>,
) -> Result<()> {
    let request_id = LOG_SEQ.fetch_add(1, Ordering::Relaxed);
    let start = Instant::now();
    let endpoint = cfg.endpoint.trim().to_string();
    let model = cfg.model.trim().to_string();
    let temperature = cfg.temperature;
    let message_count = messages.len();
    if !(0.0..=2.0).contains(&cfg.temperature) {
        return Err(anyhow!("temperature 必须在 [0,2]"));
    }
    if cfg.endpoint.trim().is_empty() || cfg.model.trim().is_empty() {
        return Err(anyhow!("endpoint/model 不能为空"));
    }

    let label = window.label().to_string();
    let label_guard = label.clone();
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    {
        let mut m = stream_cancel_map().lock().unwrap();
        m.insert(label.clone(), cancel_tx);
    }
    struct CancelGuard {
        label: String,
    }
    impl Drop for CancelGuard {
        fn drop(&mut self) {
            if let Ok(mut m) = stream_cancel_map().lock() {
                m.remove(&self.label);
            }
        }
    }
    let _guard = CancelGuard { label: label_guard };

    let url = normalize_chat_completions_url(&cfg.endpoint);
    log_event(
        "INFO",
        "llm_request_start",
        vec![
            ("id", request_id.to_string()),
            ("endpoint", endpoint.clone()),
            ("model", model.clone()),
            ("temperature", temperature.to_string()),
            ("messages", message_count.to_string()),
            ("stream", "true".to_string()),
            ("label", label.clone()),
        ],
    );

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    if !cfg.api_key.trim().is_empty() {
        let v = format!("Bearer {}", cfg.api_key.trim());
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&v)?,
        );
    }

    let body = serde_json::json!({
      "model": cfg.model,
      "temperature": cfg.temperature,
      "stream": true,
      "messages": messages
    });

    append_llm_debug_record(&url, &body);

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(600))
        .build()?;

    let resp = tokio::select! {
        r = client.post(url).headers(headers).json(&body).send() => r?,
        _ = cancel_rx.changed() => {
            let _ = window.emit("llm_stream_done", serde_json::json!({"cancelled": true}));
            log_event(
                "WARN",
                "llm_stream_cancelled",
                vec![
                    ("id", request_id.to_string()),
                    ("duration_ms", start.elapsed().as_millis().to_string()),
                    ("label", label.clone()),
                ],
            );
            return Ok(());
        }
    };

    let status = resp.status();
    if !status.is_success() {
        let text_fut = resp.text();
        let text = tokio::select! {
            t = text_fut => t.unwrap_or_default(),
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    let _ = window.emit("llm_stream_done", serde_json::json!({"cancelled": true}));
                    return Ok(());
                }
                String::new()
            }
        };
        log_event(
            "ERROR",
            "llm_request_failed",
            vec![
                ("id", request_id.to_string()),
                ("duration_ms", start.elapsed().as_millis().to_string()),
                ("status", status.as_u16().to_string()),
                ("body_len", text.len().to_string()),
            ],
        );
        return Err(anyhow!("LLM 请求失败: {} {}", status.as_u16(), text));
    }

    if let Some(c) = commit.as_ref() {
        commit_llm_usage(c).map_err(|e| anyhow!(e))?;
    }

    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    if !ct.contains("text/event-stream") {
        let text_fut = resp.text();
        let text = tokio::select! {
            t = text_fut => t.unwrap_or_default(),
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    let _ = window.emit("llm_stream_done", serde_json::json!({"cancelled": true}));
                    return Ok(());
                }
                String::new()
            }
        };
        let v: Value = serde_json::from_str(&text)?;
        let content = v["choices"][0]["message"]["content"].as_str().unwrap_or("");
        if !content.is_empty() {
            window.emit("llm_stream_chunk", serde_json::json!({"delta": content}))?;
        }
        window.emit("llm_stream_done", serde_json::json!({}))?;
        log_event(
            "INFO",
            "llm_stream_done",
            vec![
                ("id", request_id.to_string()),
                ("duration_ms", start.elapsed().as_millis().to_string()),
                ("chunks", if content.is_empty() { "0" } else { "1" }.to_string()),
                ("chars", content.len().to_string()),
                ("label", label.clone()),
            ],
        );
        return Ok(());
    }

    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    let mut chunk_count: u64 = 0;
    let mut char_count: usize = 0;

    loop {
        tokio::select! {
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    window.emit("llm_stream_done", serde_json::json!({"cancelled": true}))?;
                    return Ok(());
                }
            }
            item = stream.next() => {
                let Some(item) = item else { break; };
                let bytes = item?;
                buf.push_str(&String::from_utf8_lossy(&bytes));

                while let Some(idx) = buf.find("\n\n") {
                    let event = buf[..idx].to_string();
                    buf = buf[idx + 2..].to_string();

                    for line in event.lines() {
                        let Some(data) = line.trim_start().strip_prefix("data:") else {
                            continue;
                        };
                        let data = data.trim();
                        if data.is_empty() {
                            continue;
                        }
                        if data == "[DONE]" {
                            window.emit("llm_stream_done", serde_json::json!({}))?;
                            return Ok(());
                        }

                        let v: Value = match serde_json::from_str(data) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        let delta = v["choices"][0]["delta"]["content"].as_str().unwrap_or("");
                        if !delta.is_empty() {
                            window.emit("llm_stream_chunk", serde_json::json!({"delta": delta}))?;
                            chunk_count += 1;
                            char_count += delta.len();
                        }
                    }
                }
            }
        }
    }

    window.emit("llm_stream_done", serde_json::json!({}))?;
    log_event(
        "INFO",
        "llm_stream_done",
        vec![
            ("id", request_id.to_string()),
            ("duration_ms", start.elapsed().as_millis().to_string()),
            ("chunks", chunk_count.to_string()),
            ("chars", char_count.to_string()),
            ("label", label.clone()),
        ],
    );
    Ok(())
}

async fn call_llm(cfg: LlmConfig, prompt: String) -> Result<String> {
    call_llm_messages(
        cfg,
        vec![serde_json::json!({"role":"user","content": prompt})],
    )
    .await
}

fn find_repo_root_from(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(p) = cur {
        if p.join("rust").join("parser").join("Cargo.toml").is_file() {
            return Some(p.to_path_buf());
        }
        cur = p.parent();
    }
    None
}

fn find_parser_exe() -> Result<PathBuf> {
    let mut bases: Vec<PathBuf> = Vec::new();

    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            bases.push(dir.to_path_buf());
        }
    }
    if let Ok(cwd) = env::current_dir() {
        bases.push(cwd);
    }

    for b in bases {
        let direct = [
            b.join("parser.exe"),
            b.join("_up_").join("parser.exe"),
            b.join("resources").join("parser.exe"),
            b.join("resources").join("bin").join("parser.exe"),
            b.join("resources").join("_up_").join("parser.exe"),
            b.join("resources")
                .join("_up_")
                .join("bin")
                .join("parser.exe"),
            b.join("bin").join("parser.exe"),
            b.join("_up_").join("bin").join("parser.exe"),
        ];
        for p in direct {
            if p.is_file() {
                return Ok(p);
            }
        }

        if let Some(repo_root) = find_repo_root_from(b.as_path()) {
            let release = repo_root
                .join("rust")
                .join("parser")
                .join("target")
                .join("release")
                .join("parser.exe");
            if release.is_file() {
                return Ok(release);
            }

            let debug = repo_root
                .join("rust")
                .join("parser")
                .join("target")
                .join("debug")
                .join("parser.exe");
            if debug.is_file() {
                return Ok(debug);
            }
        }
    }

    Err(anyhow!(
        "找不到 parser.exe：请先在 rust\\parser 下编译（rust\\parser\\target\\release\\parser.exe），或在桌面打包资源目录中携带 parser.exe"
    ))
}

fn resolve_user_kb_path(input: Option<String>) -> Option<String> {
    let raw = input.unwrap_or_default();
    let raw = raw.trim().to_string();
    if raw.is_empty() {
        return None;
    }

    let p = PathBuf::from(&raw);
    if p.is_absolute() && p.is_file() {
        return Some(raw);
    }

    let mut bases: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            bases.push(dir.to_path_buf());
        }
    }
    if let Ok(cwd) = env::current_dir() {
        bases.push(cwd);
    }

    for b in bases {
        if let Some(repo_root) = find_repo_root_from(&b) {
            let candidate = repo_root.join(&p);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }

    None
}

fn run_parser(args: &[String]) -> Result<String> {
    let request_id = LOG_SEQ.fetch_add(1, Ordering::Relaxed);
    let start = Instant::now();
    let exe = find_parser_exe()?;
    log_event(
        "INFO",
        "parser_start",
        vec![
            ("id", request_id.to_string()),
            ("exe", exe.to_string_lossy().to_string()),
            ("args_count", args.len().to_string()),
            ("args", args.join(" ")),
        ],
    );
    let mut cmd = Command::new(&exe);
    cmd.args(args);

    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const DETACHED_PROCESS: u32 = 0x00000008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }

    let output = cmd.output()?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        log_event(
            "ERROR",
            "parser_failed",
            vec![
                ("id", request_id.to_string()),
                ("duration_ms", start.elapsed().as_millis().to_string()),
                (
                    "status_code",
                    output.status.code().unwrap_or(-1).to_string(),
                ),
                ("stderr_len", stderr.len().to_string()),
            ],
        );
        return Err(anyhow!(
            "parser 执行失败: {}\n{}\nexe={}",
            output.status.code().unwrap_or(-1),
            stderr,
            exe.display()
        ));
    }

    log_event(
        "INFO",
        "parser_done",
        vec![
            ("id", request_id.to_string()),
            ("duration_ms", start.elapsed().as_millis().to_string()),
            ("stdout_len", stdout.len().to_string()),
            ("stderr_len", stderr.len().to_string()),
        ],
    );
    Ok(stdout)
}

fn parse_bridge_message(payload: &str) -> Result<BridgeMessage, String> {
    let value: serde_json::Value = serde_json::from_str(payload).map_err(|e| e.to_string())?;
    if let serde_json::Value::String(inner) = value {
        return serde_json::from_str(&inner).map_err(|e| e.to_string());
    }
    serde_json::from_value(value).map_err(|e| e.to_string())
}

#[cfg(target_os = "windows")]
fn store_config_debug(cfg: &common_store_windows::StoreConfig) -> serde_json::Value {
    let plan_store_ids: Vec<serde_json::Value> = cfg
        .plan_store_ids
        .iter()
        .map(|(plan_id, store_id)| serde_json::json!({ "planId": plan_id, "storeId": store_id }))
        .collect();
    let entitlement_store_ids: Vec<serde_json::Value> = cfg
        .entitlement_store_ids
        .iter()
        .map(|(plan_id, store_id)| serde_json::json!({ "planId": plan_id, "storeId": store_id }))
        .collect();
    serde_json::json!({
        "productPageId": cfg.product_page_id,
        "planStoreIds": plan_store_ids,
        "entitlementStoreIds": entitlement_store_ids,
        "hwndTitleKeywords": cfg.hwnd_title_keywords,
        "debug": cfg.debug_enabled
    })
}

#[tauri::command]
async fn native_bridge_post(app: tauri::AppHandle, payload: String) -> Result<Value, String> {
    let msg = parse_bridge_message(&payload)?;
    let kind = msg.kind.trim();
    if kind.is_empty() {
        return Err("invalid_message".to_string());
    }
    #[cfg(target_os = "windows")]
    {
        let cfg = common_store_windows::StoreConfig::from_conf();
        let out = match kind {
            "list_products" => common_store_windows::list_products(&cfg).await,
            "purchase" => {
                let pid = msg.product_id.unwrap_or_default();
                let pid = pid.trim();
                if pid.is_empty() {
                    return Ok(serde_json::json!({ "ok": false, "errorCode": "INVALID_PRODUCT" }));
                }
                let plan = common_store_windows::resolve_plan_id(&cfg, pid)
                    .unwrap_or(pid)
                    .to_string();
                common_store_windows::purchase(&app, &cfg, &plan).await
            }
            "restore_purchases" => common_store_windows::restore(&app, &cfg).await,
            "get_entitlement_status" => common_store_windows::entitlement_status(&app, &cfg).await,
            "get_store_config" => Ok(serde_json::json!({ "ok": true, "config": store_config_debug(&cfg) })),
            "manage_subscriptions" => common_store_windows::manage_subscriptions().await,
            "open_store_product_page" => common_store_windows::open_store_product_page(&cfg).await,
            "clear_trial_history" => common_store_windows::clear_trial_history(&app).await,
            _ => Ok(serde_json::json!({ "ok": false, "errorCode": "UNKNOWN_ACTION" })),
        }?;
        let ok = out
            .get("ok")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let error_code = out
            .get("errorCode")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        log_event(
            "INFO",
            "native_bridge_post",
            vec![
                ("kind", kind.to_string()),
                ("ok", ok.to_string()),
                ("error_code", error_code),
            ],
        );
        Ok(out)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = app;
        let _ = kind;
        let out = serde_json::json!({ "ok": false, "errorCode": "STORE_UNAVAILABLE" });
        log_event(
            "WARN",
            "native_bridge_post",
            vec![("kind", "non_windows".to_string()), ("ok", "false".to_string())],
        );
        Ok(out)
    }
}

#[tauri::command]
fn license_status() -> Result<LicenseStatusDto, String> {
    let status = compute_license_status();
    log_event(
        "INFO",
        "license_status",
        vec![
            ("ok", status.ok.to_string()),
            ("reason", status.reason.clone().unwrap_or_default()),
            ("kind", status.kind.clone().unwrap_or_default()),
            ("expire", status.expire.clone().unwrap_or_default()),
        ],
    );
    Ok(status)
}

#[tauri::command]
async fn usage_auth_state() -> Result<UsageAuthStateDto, String> {
    let access = resolve_usage_access().await?;
    Ok(UsageAuthStateDto {
        state: access.auth_state,
        subscription_type: access.subscription_type,
        license_name: access.license_name,
        license_expire: access.license_expire,
        license_kind: access.license_kind,
    })
}

#[tauri::command]
async fn mobile_auth_qr() -> Result<MobileAuthQrDto, String> {
    let access = resolve_usage_access().await?;
    let (plan_tier, topn_limit, daily_analysis_limit, valid_days) = match access.subscription_type.as_deref() {
        Some("pro_year") => ("yearly", 10, 10, 7),
        Some("pro_month") => ("monthly", 5, 10, 3),
        _ if access.auth_state == "offline_full" => ("yearly", 10, 10, 7),
        _ => ("free", 2, 3, 1),
    };
    let now = chrono::Utc::now();
    let qr_expires_at = (now + chrono::Duration::minutes(5)).timestamp();
    let license_expire_at = (now + chrono::Duration::days(valid_days)).to_rfc3339();
    let mut payload = llm_license::MobileAuthPayload {
        license_id: access
            .license_name
            .clone()
            .unwrap_or_else(|| "desktop-subscription".to_string()),
        plan_tier: plan_tier.to_string(),
        topn_limit,
        daily_analysis_limit,
        qr_issued_at: now.to_rfc3339(),
        qr_expires_at: chrono::DateTime::from_timestamp(qr_expires_at, 0)
            .map(|d| d.to_rfc3339())
            .unwrap_or_default(),
        license_issued_at: now.to_rfc3339(),
        license_expire_at,
        nonce: format!(
            "{}-{}",
            now.timestamp_millis(),
            LOG_SEQ.fetch_add(1, Ordering::Relaxed)
        ),
        signature: String::new(),
    };
    payload.signature =
        llm_license::sign_mobile_auth_payload(&payload).map_err(|e| format!("{e}"))?;
    let payload = serde_json::to_string(&payload).map_err(|e| format!("{e}"))?;
    let qr_svg = QrCode::new(payload.as_bytes())
        .map_err(|e| format!("qr_encode_failed: {e}"))?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(320, 320)
        .dark_color(qrcode::render::svg::Color("#111111"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    Ok(MobileAuthQrDto {
        payload,
        qr_svg,
        qr_expires_at,
        public_key_pem: llm_license::mobile_auth_public_key_pem().to_string(),
    })
}

#[tauri::command]
fn license_export_feature(path: String) -> Result<(), String> {
    log_line("INFO", &format!("license_export_feature path={}", path));
    let p = PathBuf::from(path);
    match llm_license::export_feature_signature(Path::new(&p)) {
        Ok(()) => {
            log_line(
                "INFO",
                &format!(
                    "license_export_feature ok exists={} len={}",
                    p.is_file(),
                    fs::metadata(&p).map(|m| m.len()).unwrap_or(0)
                ),
            );
            Ok(())
        }
        Err(e) => {
            log_line("ERROR", &format!("license_export_feature failed: {e}"));
            Err(e.to_string())
        }
    }
}

#[tauri::command]
fn license_import(path: String) -> Result<LicenseStatusDto, String> {
    let src = PathBuf::from(&path);
    if !src.is_file() {
        return Err("指定的授权文件不存在".to_string());
    }
    let dst = preferred_license_path();
    if let Some(parent) = dst.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::copy(&src, &dst).map_err(|e| e.to_string())?;
    let status = compute_license_status();
    log_event(
        "INFO",
        "license_import",
        vec![
            ("src", src.to_string_lossy().to_string()),
            ("dst", dst.to_string_lossy().to_string()),
            ("ok", status.ok.to_string()),
            ("reason", status.reason.clone().unwrap_or_default()),
        ],
    );
    Ok(status)
}

#[tauri::command]
fn detect_tshark() -> Result<Option<String>, String> {
    fn normalize_path_display(p: &Path) -> String {
        let mut s = p.to_string_lossy().to_string();
        if cfg!(target_os = "windows") {
            if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
                s = format!(r"\\{rest}");
            } else if let Some(rest) = s.strip_prefix(r"\\?\") {
                s = rest.to_string();
            }
        }
        s
    }

    let exe = if cfg!(target_os = "windows") {
        "tshark.exe"
    } else {
        "tshark"
    };

    let mut candidates: Vec<PathBuf> = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Some(p) = env::var_os("ProgramFiles") {
            candidates.push(PathBuf::from(p).join("Wireshark").join(exe));
        }
        if let Some(p) = env::var_os("ProgramFiles(x86)") {
            candidates.push(PathBuf::from(p).join("Wireshark").join(exe));
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        candidates.push(PathBuf::from("/usr/bin").join(exe));
        candidates.push(PathBuf::from("/usr/local/bin").join(exe));
        candidates.push(PathBuf::from("/opt/homebrew/bin").join(exe));
    }

    if let Some(paths) = env::var_os("PATH") {
        for p in env::split_paths(&paths) {
            candidates.push(p.join(exe));
        }
    }

    let mut seen: HashSet<String> = HashSet::new();
    for c in candidates {
        let k = c.to_string_lossy().to_lowercase();
        if !seen.insert(k) {
            continue;
        }
        if !c.is_file() {
            continue;
        }
        let out = fs::canonicalize(&c).unwrap_or(c);
        let found = normalize_path_display(&out);
        log_event(
            "INFO",
            "detect_tshark",
            vec![("found", "true".to_string()), ("path", found.clone())],
        );
        return Ok(Some(found));
    }

    log_event(
        "WARN",
        "detect_tshark",
        vec![("found", "false".to_string())],
    );
    Ok(None)
}

#[tauri::command]
async fn pcap_summary(
    pcap_path: String,
    tshark: Option<String>,
    filter: Option<String>,
    max_size_kb: Option<u64>,
) -> Result<Value, String> {
    let start = Instant::now();
    let access = resolve_usage_access().await?;
    
    // Use provided max_size_kb or calculate based on license
    let effective_max_size_kb = max_size_kb.unwrap_or_else(|| get_max_pcap_size_kb(&access));
    
    let pcap_path_log = pcap_path.clone();
    let tshark_log = tshark.clone().unwrap_or_default();
    let filter_log = filter.clone().unwrap_or_default();
    log_event(
        "INFO",
        "pcap_summary_start",
        vec![
            ("pcap", pcap_path_log),
            ("tshark", tshark_log),
            ("filter", filter_log),
            ("max_size_kb", effective_max_size_kb.to_string()),
            (
                "has_license",
                access.license_path.is_some().to_string(),
            ),
        ],
    );
    let mut args = vec!["--summary".to_string(), "--pcap".to_string(), pcap_path];
    if let Some(lp) = access.license_path.as_ref() {
        args.push("--license".to_string());
        args.push(lp.to_string_lossy().to_string());
    }
    if let Some(f) = filter.as_ref() {
        args.push("--filter".to_string());
        args.push(f.to_string());
    }
    args.push("--max-size-kb".to_string());
    args.push(effective_max_size_kb.to_string());
    if let Some(t) = tshark.as_ref() {
        if !t.trim().is_empty() {
            args.push("--tshark".to_string());
            args.push(t.to_string());
        }
    }

    let out = run_parser(&args).map_err(|e| e.to_string())?;
    let value: Value = serde_json::from_str(&out).map_err(|e| format!("summary JSON 解析失败: {e}"))?;
    let summary = value.get("summary").unwrap_or(&value);
    let file_size = summary
        .get("file_size_bytes")
        .and_then(|v| v.as_u64())
        .map(|v| v.to_string())
        .unwrap_or_default();
    let packet_count = summary
        .get("packet_count")
        .and_then(|v| v.as_u64())
        .map(|v| v.to_string())
        .unwrap_or_default();
    let signaling_count = summary
        .get("signaling_count")
        .and_then(|v| v.as_u64())
        .map(|v| v.to_string())
        .unwrap_or_default();
    let too_large = summary
        .get("too_large")
        .and_then(|v| v.as_bool())
        .map(|v| v.to_string())
        .unwrap_or_default();
    let stop_reason = summary
        .get("stop_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    log_event(
        "INFO",
        "pcap_summary_done",
        vec![
            ("duration_ms", start.elapsed().as_millis().to_string()),
            ("file_size_bytes", file_size),
            ("packet_count", packet_count),
            ("signaling_count", signaling_count),
            ("too_large", too_large),
            ("stop_reason", stop_reason),
        ],
    );
    Ok(value)
}

#[tauri::command]
async fn pcap_analyze(
    pcap_path: String,
    tshark: Option<String>,
    filter: Option<String>,
    max_size_kb: Option<u64>,
    kb_path: Option<String>,
    kb_enabled: Option<bool>,
    ui_lang: Option<String>,
) -> Result<Value, String> {
    let start = Instant::now();
    let access = resolve_usage_access().await?;
    
    // Use provided max_size_kb or calculate based on license
    let effective_max_size_kb = max_size_kb.unwrap_or_else(|| get_max_pcap_size_kb(&access));
    
    let pcap_path_log = pcap_path.clone();
    let tshark_log = tshark.clone().unwrap_or_default();
    let filter_log = filter.clone().unwrap_or_default();
    let kb_path_log = kb_path.clone().unwrap_or_default();
    let ui_lang_log = ui_lang.clone().unwrap_or_default();

    struct TrialGuard {
        token: Option<String>,
        keep: bool,
    }
    impl Drop for TrialGuard {
        fn drop(&mut self) {
            if self.keep {
                return;
            }
            if let Some(t) = self.token.as_deref() {
                trial_cleanup_reservation(t);
            }
        }
    }

    let mut trial_guard = if let Some(lim) = access.limits.as_ref() {
        let token = trial_reserve_for_pcap(&lim.license_id, lim.analysis_limit)?;
        TrialGuard {
            token: Some(token),
            keep: false,
        }
    } else {
        TrialGuard {
            token: None,
            keep: true,
        }
    };

    let tmp = std::env::temp_dir()
        .join("llmshark")
        .join(format!("{}", chrono::Local::now().format("%Y%m%d_%H%M%S")));
    let _ = fs::create_dir_all(&tmp);

    let report_json = tmp.join("report.json");
    let signaling_json = tmp.join("signaling.json");
    let signaling_csv = tmp.join("signaling.csv");
    let mermaid = tmp.join("mermaid.txt");
    let analysis_json = tmp.join("analysis.json");

    let mut args = vec![
        "--pcap".to_string(),
        pcap_path,
        "--report-json".to_string(),
        report_json.to_string_lossy().to_string(),
        "--json".to_string(),
        signaling_json.to_string_lossy().to_string(),
        "--csv".to_string(),
        signaling_csv.to_string_lossy().to_string(),
        "--mermaid".to_string(),
        mermaid.to_string_lossy().to_string(),
        "--analysis-json".to_string(),
        analysis_json.to_string_lossy().to_string(),
    ];

    if let Some(lp) = access.license_path.as_ref() {
        args.push("--license".to_string());
        args.push(lp.to_string_lossy().to_string());
    }

    if let Some(f) = filter.as_ref() {
        args.push("--filter".to_string());
        args.push(f.to_string());
    }
    args.push("--max-size-kb".to_string());
    args.push(effective_max_size_kb.to_string());
    if let Some(t) = tshark.as_ref() {
        if !t.trim().is_empty() {
            args.push("--tshark".to_string());
            args.push(t.to_string());
        }
    }
    if let Some(l) = ui_lang.as_ref() {
        args.push("--ui-lang".to_string());
        args.push(l.to_string());
    }
    let kb_enabled = kb_enabled.unwrap_or(true);
    log_event(
        "INFO",
        "pcap_analyze_start",
        vec![
            ("pcap", pcap_path_log),
            ("tshark", tshark_log),
            ("filter", filter_log),
            ("max_size_kb", effective_max_size_kb.to_string()),
            ("kb_enabled", kb_enabled.to_string()),
            ("kb_path", kb_path_log),
            ("ui_lang", ui_lang_log),
            (
                "has_license",
                access.license_path.is_some().to_string(),
            ),
        ],
    );
    if kb_enabled {
        let kb_user = resolve_user_kb_path(kb_path);
        if let Some(k) = kb_user {
            args.push("--kb-user-path".to_string());
            args.push(k);
        }
    } else {
        args.push("--no-kb".to_string());
    }

    run_parser(&args).map_err(|e| e.to_string())?;

    let report_text = fs::read_to_string(&report_json).map_err(|e| e.to_string())?;
    let mut report_v: Value = serde_json::from_str(&report_text).map_err(|e| e.to_string())?;

    report_v["outputs"]["report_json"] = Value::String(report_json.to_string_lossy().to_string());
    report_v["outputs"]["signaling_json"] =
        Value::String(signaling_json.to_string_lossy().to_string());
    report_v["outputs"]["signaling_csv"] =
        Value::String(signaling_csv.to_string_lossy().to_string());
    report_v["outputs"]["mermaid"] = Value::String(mermaid.to_string_lossy().to_string());
    report_v["outputs"]["analysis_json"] =
        Value::String(analysis_json.to_string_lossy().to_string());

    let summary = report_v.get("summary").cloned().unwrap_or(Value::Null);
    let analysis = report_v.get("analysis").cloned().unwrap_or(Value::Null);
    let call_status = analysis
        .get("call_status")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let failure_reason = analysis
        .get("failure_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let protocols = summary
        .get("detected_protocols")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    log_event(
        "INFO",
        "pcap_analyze_done",
        vec![
            ("duration_ms", start.elapsed().as_millis().to_string()),
            ("call_status", call_status),
            ("failure_reason", failure_reason),
            ("protocols", protocols),
            ("report_json", report_json.to_string_lossy().to_string()),
            ("signaling_json", signaling_json.to_string_lossy().to_string()),
            ("signaling_csv", signaling_csv.to_string_lossy().to_string()),
            ("mermaid", mermaid.to_string_lossy().to_string()),
            ("analysis_json", analysis_json.to_string_lossy().to_string()),
        ],
    );
    if let Some(t) = trial_guard.token.as_ref() {
        report_v["trial_token"] = Value::String(t.clone());
        trial_guard.keep = true;
    }

    Ok(report_v)
}

#[tauri::command]
fn read_json_file(path: String) -> Result<Value, String> {
    log_event(
        "INFO",
        "read_json_file",
        vec![("path", path.clone())],
    );
    let txt = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&txt).map_err(|e| e.to_string())
}

#[tauri::command]
fn ui_log_event(event: String, fields: Option<HashMap<String, String>>) -> Result<(), String> {
    let name = if event.trim().is_empty() {
        "ui_event".to_string()
    } else {
        event
    };
    let mut line = format!("event={name}");
    if let Some(map) = fields {
        for (k, v) in map {
            line.push(' ');
            line.push_str(&sanitize_log_value(&k));
            line.push('=');
            line.push_str(&sanitize_log_value(&v));
        }
    }
    log_line("INFO", &line);
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct LlmValidateResult {
    detail: String,
}

#[tauri::command]
async fn llm_validate(cfg: LlmConfig) -> Result<LlmValidateResult, String> {
    let start = Instant::now();
    log_event(
        "INFO",
        "llm_validate_start",
        vec![
            ("endpoint", cfg.endpoint.clone()),
            ("model", cfg.model.clone()),
            ("temperature", cfg.temperature.to_string()),
            ("use_kb", cfg.use_kb.to_string()),
            ("ui_lang", cfg.ui_lang.clone().unwrap_or_default()),
        ],
    );
    let cfg = materialize_trial_cfg(cfg);
    let content = call_llm_messages(
        cfg,
        vec![serde_json::json!({"role":"user","content":"ping"})],
    )
    .await
    .map_err(|e| e.to_string())?;

    let detail: String = content.chars().take(120).collect();
    log_event(
        "INFO",
        "llm_validate_done",
        vec![
            ("duration_ms", start.elapsed().as_millis().to_string()),
            ("detail_len", detail.len().to_string()),
        ],
    );
    Ok(LlmValidateResult { detail })
}

#[tauri::command]
async fn llm_analyze(cfg: LlmConfig, report: Value) -> Result<String, String> {
    let start = Instant::now();
    log_event(
        "INFO",
        "llm_analyze_start",
        vec![
            ("endpoint", cfg.endpoint.clone()),
            ("model", cfg.model.clone()),
            ("temperature", cfg.temperature.to_string()),
            ("use_kb", cfg.use_kb.to_string()),
            ("prompt_auto", cfg.prompt_auto.to_string()),
            ("ui_lang", cfg.ui_lang.clone().unwrap_or_default()),
        ],
    );
    let commit = resolve_llm_analysis_trial(&report).await?;
    let template = read_prompt_template(cfg.prompt_auto, cfg.prompt_path.as_deref())
        .map_err(|e| e.to_string())?;
    let prompt = build_prompt(template, &report, cfg.use_kb, cfg.ui_lang.as_deref());
    let cfg = materialize_trial_cfg(cfg);
    let out = call_llm(cfg, prompt).await.map_err(|e| e.to_string())?;
    if let Some(c) = commit.as_ref() {
        commit_llm_usage(c).map_err(|e| e.to_string())?;
    }
    log_event(
        "INFO",
        "llm_analyze_done",
        vec![
            ("duration_ms", start.elapsed().as_millis().to_string()),
            ("output_len", out.len().to_string()),
        ],
    );
    Ok(out)
}

#[tauri::command]
async fn llm_analyze_stream(window: Window, cfg: LlmConfig, report: Value) -> Result<(), String> {
    log_event(
        "INFO",
        "llm_analyze_stream_start",
        vec![
            ("endpoint", cfg.endpoint.clone()),
            ("model", cfg.model.clone()),
            ("temperature", cfg.temperature.to_string()),
            ("use_kb", cfg.use_kb.to_string()),
            ("prompt_auto", cfg.prompt_auto.to_string()),
            ("ui_lang", cfg.ui_lang.clone().unwrap_or_default()),
        ],
    );
    let commit = resolve_llm_analysis_trial(&report).await?;
    let template = read_prompt_template(cfg.prompt_auto, cfg.prompt_path.as_deref())
        .map_err(|e| e.to_string())?;
    let prompt = build_prompt(template, &report, cfg.use_kb, cfg.ui_lang.as_deref());
    let messages = vec![serde_json::json!({"role":"user","content": prompt})];
    let cfg = materialize_trial_cfg(cfg);
    call_llm_stream_messages(&window, cfg, messages, commit)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn llm_chat(
    cfg: LlmConfig,
    report: Value,
    messages: Vec<ChatMessage>,
) -> Result<String, String> {
    let start = Instant::now();
    log_event(
        "INFO",
        "llm_chat_start",
        vec![
            ("endpoint", cfg.endpoint.clone()),
            ("model", cfg.model.clone()),
            ("temperature", cfg.temperature.to_string()),
            ("use_kb", cfg.use_kb.to_string()),
            ("prompt_auto", cfg.prompt_auto.to_string()),
            ("ui_lang", cfg.ui_lang.clone().unwrap_or_default()),
            ("messages_count", messages.len().to_string()),
        ],
    );
    let commit = resolve_llm_chat_trial(&report).await?;
    let mut chat_guard = if let Some(LlmCommit::Chat { token, .. }) = commit.as_ref() {
        ChatGuard {
            token: Some(token.clone()),
            keep: false,
        }
    } else {
        ChatGuard {
            token: None,
            keep: true,
        }
    };

    let msgs = build_chat_messages(
        &report,
        messages,
        cfg.use_kb,
        cfg.ui_lang.as_deref(),
        cfg.prompt_auto,
        cfg.prompt_path.as_deref(),
    )
    .map_err(|e| e.to_string())?;

    let cfg = materialize_trial_cfg(cfg);
    let cfg = materialize_trial_cfg(cfg);
    let out = call_llm_messages(cfg, msgs)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(c) = commit.as_ref() {
        commit_llm_usage(c).map_err(|e| e.to_string())?;
        chat_guard.keep = true;
    }
    drop(chat_guard);

    log_event(
        "INFO",
        "llm_chat_done",
        vec![
            ("duration_ms", start.elapsed().as_millis().to_string()),
            ("output_len", out.len().to_string()),
        ],
    );
    Ok(out)
}

#[tauri::command]
async fn llm_chat_stream(
    window: Window,
    cfg: LlmConfig,
    report: Value,
    messages: Vec<ChatMessage>,
) -> Result<(), String> {
    log_event(
        "INFO",
        "llm_chat_stream_start",
        vec![
            ("endpoint", cfg.endpoint.clone()),
            ("model", cfg.model.clone()),
            ("temperature", cfg.temperature.to_string()),
            ("use_kb", cfg.use_kb.to_string()),
            ("prompt_auto", cfg.prompt_auto.to_string()),
            ("ui_lang", cfg.ui_lang.clone().unwrap_or_default()),
            ("messages_count", messages.len().to_string()),
        ],
    );
    let commit = resolve_llm_chat_trial(&report).await?;
    let mut chat_guard = if let Some(LlmCommit::Chat { token, .. }) = commit.as_ref() {
        ChatGuard {
            token: Some(token.clone()),
            keep: false,
        }
    } else {
        ChatGuard {
            token: None,
            keep: true,
        }
    };

    let msgs = build_chat_messages(
        &report,
        messages,
        cfg.use_kb,
        cfg.ui_lang.as_deref(),
        cfg.prompt_auto,
        cfg.prompt_path.as_deref(),
    )
    .map_err(|e| e.to_string())?;
    let cfg = materialize_trial_cfg(cfg);
    let res = call_llm_stream_messages(&window, cfg, msgs, commit)
        .await
        .map_err(|e| e.to_string());
    if res.is_ok() {
        chat_guard.keep = true;
    }
    drop(chat_guard);
    res
}

#[tauri::command]
async fn llm_chat_plain(cfg: LlmConfig, messages: Vec<ChatMessage>) -> Result<String, String> {
    let start = Instant::now();
    log_event(
        "INFO",
        "llm_chat_plain_start",
        vec![
            ("endpoint", cfg.endpoint.clone()),
            ("model", cfg.model.clone()),
            ("temperature", cfg.temperature.to_string()),
            ("ui_lang", cfg.ui_lang.clone().unwrap_or_default()),
            ("messages_count", messages.len().to_string()),
        ],
    );
    ensure_plain_chat_allowed().await?;
    let msgs = build_plain_chat_messages(messages, cfg.ui_lang.as_deref()).map_err(|e| e.to_string())?;
    let cfg = materialize_trial_cfg(cfg);
    let out = call_llm_messages(cfg, msgs).await.map_err(|e| e.to_string())?;
    log_event(
        "INFO",
        "llm_chat_plain_done",
        vec![
            ("duration_ms", start.elapsed().as_millis().to_string()),
            ("output_len", out.len().to_string()),
        ],
    );
    Ok(out)
}

#[tauri::command]
async fn llm_chat_plain_stream(
    window: Window,
    cfg: LlmConfig,
    messages: Vec<ChatMessage>,
) -> Result<(), String> {
    log_event(
        "INFO",
        "llm_chat_plain_stream_start",
        vec![
            ("endpoint", cfg.endpoint.clone()),
            ("model", cfg.model.clone()),
            ("temperature", cfg.temperature.to_string()),
            ("ui_lang", cfg.ui_lang.clone().unwrap_or_default()),
            ("messages_count", messages.len().to_string()),
        ],
    );
    ensure_plain_chat_allowed().await?;
    let msgs = build_plain_chat_messages(messages, cfg.ui_lang.as_deref()).map_err(|e| e.to_string())?;
    let cfg = materialize_trial_cfg(cfg);
    call_llm_stream_messages(&window, cfg, msgs, None)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn llm_stream_cancel(window: Window) -> Result<(), String> {
    let label = window.label().to_string();
    let tx = stream_cancel_map()
        .lock()
        .ok()
        .and_then(|m| m.get(&label).cloned());
    if let Some(tx) = tx {
        let _ = tx.send(true);
    }
    log_event(
        "INFO",
        "llm_stream_cancel",
        vec![("label", label)],
    );
    Ok(())
}

fn main() {
    init_logging();
    log_event("INFO", "tauri_builder_start", vec![]);
    tauri::Builder::default()
        .setup(|app| {
            log_event("INFO", "tauri_setup", vec![]);
            let _ = APP_HANDLE.set(app.handle());
            if let Err(e) = ensure_feature_file() {
                log_event(
                    "WARN",
                    "feature_file_init_failed",
                    vec![("error", e)],
                );
            }
            if let Err(e) = tauri::async_runtime::block_on(init_usage_access_cache()) {
                log_event(
                    "WARN",
                    "usage_access_cache_init_failed",
                    vec![("error", e)],
                );
            }
            log_event("INFO", "tauri_setup_done", vec![]);
            Ok(())
        })
        .on_page_load(|window, _| {
            log_event(
                "INFO",
                "tauri_page_load",
                vec![("label", window.label().to_string())],
            );
        })
        .invoke_handler(tauri::generate_handler![
            native_bridge_post,
            license_status,
            usage_auth_state,
            mobile_auth_qr,
            license_export_feature,
            license_import,
            detect_tshark,
            pcap_summary,
            pcap_analyze,
            read_json_file,
            ui_log_event,
            llm_validate,
            llm_analyze,
            llm_analyze_stream,
            llm_chat,
            llm_chat_stream,
            llm_chat_plain,
            llm_chat_plain_stream,
            llm_stream_cancel
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
