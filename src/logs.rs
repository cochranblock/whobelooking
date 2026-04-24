// All Rights Reserved — The Cochran Block, LLC
//! Daily-rolling log appender + Gemini Man restart snapshots.
//!
//! Logs land at `~/.local/share/{project}/logs/`:
//!   current.YYYY-MM-DD     — today's log, rolls at UTC midnight
//!   snapshot-pre-restart.{ISO_TS}  — snapshot taken when Gemini Man hands over
//!
//! Retention: max 30 rolled files (handled by tracing-appender's max_log_files).
//! Snapshots are never auto-pruned — they mark code-change boundaries.
//!
//! Drop-in usage:
//!   let _guard = logs::init("whobelooking").expect("logs init");
//!   logs::snapshot_pre_restart("whobelooking");   // before kill_old()

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const RETAIN_DAYS: usize = 30;

/// Keep the returned `Guard` alive for the lifetime of the process;
/// dropping it flushes the async writer.
pub struct Guard {
    _guard: WorkerGuard,
}

pub fn logs_dir(project: &str) -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(project)
        .join("logs")
}

/// Initialise tracing with a daily-rolling file appender + stderr writer.
/// Default filter is "info"; overridden by RUST_LOG.
pub fn init(project: &str) -> std::io::Result<Guard> {
    let dir = logs_dir(project);
    std::fs::create_dir_all(&dir)?;

    let file = rolling::Builder::new()
        .rotation(rolling::Rotation::DAILY)
        .filename_prefix("current")
        .filename_suffix("log")
        .max_log_files(RETAIN_DAYS)
        .build(&dir)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let (nb_file, guard) = tracing_appender::non_blocking(file);

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(std::io::stderr).with_target(true))
        .with(
            fmt::layer()
                .with_writer(nb_file)
                .with_ansi(false)
                .with_target(true),
        )
        .init();

    Ok(Guard { _guard: guard })
}

/// Copy today's current log to `snapshot-pre-restart.{ISO_TS}` before Gemini
/// Man kills the old process. Called from the NEW pid before `kill_old()`.
/// Silent on error — a missing log or permission issue isn't worth aborting.
pub fn snapshot_pre_restart(project: &str) {
    let dir = logs_dir(project);
    let today = ymd_today();
    let src = dir.join(format!("current.{}", today));
    let src_alt = dir.join(format!("current.{}.log", today));
    let source = if src.exists() {
        src
    } else if src_alt.exists() {
        src_alt
    } else {
        return;
    };
    let dst = dir.join(format!("snapshot-pre-restart.{}.log", iso_timestamp()));
    let _ = std::fs::copy(&source, &dst);
}

/// Return `/tmp/{project}.log` as a legacy fallback so operators who still
/// tail that path see a deprecation breadcrumb.
pub fn legacy_fallback_message(project: &str) -> String {
    let new = logs_dir(project).display().to_string();
    format!(
        "/tmp/{}.log is legacy — canonical logs are at {}",
        project, new
    )
}

// ---- date helpers (no chrono dep) ----

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// UTC today as "YYYY-MM-DD".
fn ymd_today() -> String {
    let secs = now_secs();
    let days = (secs / 86400) as i64;
    let (y, m, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// UTC now as "YYYYMMDD-HHMMSS" — compact, filename-safe.
fn iso_timestamp() -> String {
    let secs = now_secs();
    let days = (secs / 86400) as i64;
    let (y, m, d) = days_to_ymd(days);
    let hod = secs % 86400;
    let h = hod / 3600;
    let mm = (hod % 3600) / 60;
    let s = hod % 60;
    format!("{:04}{:02}{:02}-{:02}{:02}{:02}", y, m, d, h, mm, s)
}

/// Convert days-since-epoch → (year, month, day) via Howard Hinnant's algorithm.
fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = y + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

/// For callers that want the canonical path as a `Path` (e.g. to scp off-box).
pub fn current_log_path(project: &str) -> PathBuf {
    logs_dir(project).join(format!("current.{}.log", ymd_today()))
}

pub fn current_log_path_prefix(project: &str) -> PathBuf {
    logs_dir(project).join(format!("current.{}", ymd_today()))
}

#[allow(dead_code)]
pub fn snapshot_all_existing(project: &str) -> std::io::Result<Vec<PathBuf>> {
    let dir = logs_dir(project);
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(&dir)? {
        let p = entry?.path();
        if p.file_name()
            .and_then(|f| f.to_str())
            .map(|s| s.starts_with("snapshot-pre-restart."))
            .unwrap_or(false)
        {
            out.push(p);
        }
    }
    Ok(out)
}

// placate unused-import if tracing_subscriber features shift
#[allow(dead_code)]
fn _keep(p: &Path) -> bool {
    p.exists()
}
