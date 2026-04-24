// All Rights Reserved — The Cochran Block, LLC
//! Visitor logging — CF-Connecting-IP extraction, per-request tracing,
//! per-(date, ip, path) counters in a sled tree.

use axum::{extract::Request, http::HeaderMap, middleware::Next, response::Response};
use sled::{Db, Tree};
use std::sync::OnceLock;

static DB: OnceLock<Db> = OnceLock::new();
static VISITS: OnceLock<Tree> = OnceLock::new();

fn db() -> &'static Db {
    DB.get_or_init(|| {
        let dir = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("whobelooking");
        let _ = std::fs::create_dir_all(&dir);
        sled::open(dir).expect("sled open (visits)")
    })
}

fn tree() -> &'static Tree {
    VISITS.get_or_init(|| db().open_tree("visits").expect("open visits tree"))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn today_days() -> u64 {
    now_secs() / 86400
}

fn header_str<'a>(h: &'a HeaderMap, n: &str) -> &'a str {
    h.get(n).and_then(|v| v.to_str().ok()).unwrap_or("")
}

/// Extract real client IP. Priority: CF-Connecting-IP → X-Forwarded-For first → "".
pub fn client_ip(headers: &HeaderMap) -> String {
    let cf = header_str(headers, "cf-connecting-ip");
    if !cf.is_empty() {
        return cf.to_string();
    }
    let xff = header_str(headers, "x-forwarded-for");
    if let Some(first) = xff.split(',').next() {
        let trimmed = first.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    String::new()
}

/// Increment (date, ip, path) counter and update first/last timestamps.
/// Key format: `{date}|{ip}|{path}`. Pipe separator avoids ambiguity with
/// colons in IPv6 addresses and rare colons in URL paths.
pub fn record(ip: &str, path: &str) {
    let d = today_days();
    let key = format!("{}|{}|{}", d, ip, path);
    let now = now_secs();
    let _ = tree().update_and_fetch(key.as_bytes(), |old| {
        let (count, first) = match old {
            Some(v) => {
                let s = String::from_utf8_lossy(v);
                let mut p = s.splitn(3, '|');
                let c: u64 = p.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                let f: u64 = p.next().and_then(|s| s.parse().ok()).unwrap_or(now);
                (c + 1, f)
            }
            None => (1, now),
        };
        Some(format!("{}|{}|{}", count, first, now).into_bytes())
    });
}

/// Middleware: extract IP + UA + referer + country, log via tracing, record to sled.
pub async fn log_middleware(req: Request, next: Next) -> Response {
    let ip = client_ip(req.headers());
    let ua = header_str(req.headers(), "user-agent").to_string();
    let ref_ = header_str(req.headers(), "referer").to_string();
    let country = header_str(req.headers(), "cf-ipcountry").to_string();
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    record(&ip, &path);

    tracing::info!(
        "visit ip={} cc={} method={} path={} ua={:?} ref={:?}",
        ip, country, method, path, ua, ref_
    );

    next.run(req).await
}

/// (ip, path, count, first_ts, last_ts)
pub type VisitRow = (String, String, u64, u64, u64);

/// List all visits for a date (days-since-epoch).
pub fn list_for_date(date_days: u64) -> Vec<VisitRow> {
    let prefix = format!("{}|", date_days);
    let mut out = Vec::new();
    for kv in tree().scan_prefix(prefix.as_bytes()).flatten() {
        let k = String::from_utf8_lossy(&kv.0);
        let v = String::from_utf8_lossy(&kv.1);
        let kparts: Vec<&str> = k.splitn(3, '|').collect();
        if kparts.len() != 3 {
            continue;
        }
        let ip = kparts[1].to_string();
        let path = kparts[2].to_string();
        let vp: Vec<&str> = v.splitn(3, '|').collect();
        let c: u64 = vp.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let f: u64 = vp.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let l: u64 = vp.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        out.push((ip, path, c, f, l));
    }
    out
}

/// Today as days-since-epoch.
pub fn today() -> u64 {
    today_days()
}

/// Skip-list of paths that are NOT useful for surface-area scanning
/// (every site has these; they tell you nothing about exposure).
const BORING_PATHS: &[&str] = &[
    "/",
    "/robots.txt",
    "/favicon.ico",
    "/favicon.png",
    "/sitemap.xml",
    "/apple-touch-icon.png",
    "/apple-touch-icon-precomposed.png",
    "/cdn-cgi/rum",
    "/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js",
    "/cdn-cgi/l/email-protection",
    "/admin",
    "/admin/visits",
];

fn is_boring(path: &str) -> bool {
    BORING_PATHS.contains(&path)
}

/// Aggregate every distinct path ever observed across the visits tree, with
/// total hit counts. Sorted by hits descending. This is the surface-area-scan
/// corpus: paths attackers (and other bots) have probed for. Filters:
///   - `min_hits`: drop paths with fewer hits (de-noise)
///   - `attack_only`: skip BORING_PATHS (always-present paths)
pub fn corpus_paths(min_hits: u64, attack_only: bool) -> Vec<(String, u64)> {
    let mut totals: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for kv in tree().iter().flatten() {
        let k = String::from_utf8_lossy(&kv.0);
        let v = String::from_utf8_lossy(&kv.1);
        // key format: {date}|{ip}|{path}
        let parts: Vec<&str> = k.splitn(3, '|').collect();
        if parts.len() != 3 {
            continue;
        }
        let path = parts[2].to_string();
        if attack_only && is_boring(&path) {
            continue;
        }
        let count: u64 = v
            .splitn(3, '|')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        *totals.entry(path).or_insert(0) += count;
    }
    let mut out: Vec<(String, u64)> = totals.into_iter().filter(|(_, n)| *n >= min_hits).collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}
