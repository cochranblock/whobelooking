// Unlicense — public domain — whobelooking.org
//! `/api/enrichment.json` — daily-rolled IP→org snapshot from the RDAP cache.
//!
//! The browser-side `/try` page consults this on load before doing fresh
//! RDAP lookups: anything found here resolves instantly, anything missing
//! falls through to a live RDAP query (and gets cached client-side).
//!
//! That's the moat. Every customer's RDAP work pre-warms every other
//! customer's report, without anyone uploading their logs.
//!
//! Privacy posture: this endpoint exposes only IP→org strings. No traffic
//! patterns, no paths, no UAs, no timestamps from any customer. It's the
//! same data ARIN would hand you — just pre-resolved, cached, and grouped.

use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(serde::Serialize)]
struct Snapshot {
    version: u32,
    generated_at: u64,
    /// IP literal → org name. Resolved-from-PTR or RDAP, whichever was richer.
    ips: BTreeMap<String, String>,
    /// CIDR (e.g. "8.8.8.0/24") → org name. Walked when an IP doesn't have an
    /// exact match in `ips`.
    cidrs: BTreeMap<String, String>,
}

struct CachedBody {
    built_at: Instant,
    json: Vec<u8>,
    etag: String,
    entry_count: usize,
}

static CACHE: OnceLock<Mutex<Option<CachedBody>>> = OnceLock::new();
const REBUILD_AFTER: Duration = Duration::from_secs(3600);

fn cache() -> &'static Mutex<Option<CachedBody>> {
    CACHE.get_or_init(|| Mutex::new(None))
}

fn rdap_db_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("whobelooking")
        .join("rdap_cache.db")
}

/// Pull the most informative org-ish string out of a stored `rdap::Info`.
/// We don't share the struct to avoid a binary↔web cyclic mod dep — the
/// stored shape is stable JSON, so reading by field name is fine.
fn org_from_info_bytes(value: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(value).ok()?;
    let pick = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    pick("org")
        .or_else(|| pick("name"))
        .or_else(|| pick("admin"))
}

fn build_snapshot() -> Result<CachedBody, String> {
    let db = sled::open(rdap_db_path()).map_err(|e| format!("sled open: {}", e))?;

    let mut snap = Snapshot {
        version: 1,
        generated_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        ips: BTreeMap::new(),
        cidrs: BTreeMap::new(),
    };

    for kv in db.scan_prefix(b"ip:").flatten() {
        let Ok(k) = std::str::from_utf8(&kv.0) else {
            continue;
        };
        let Some(ip) = k.strip_prefix("ip:") else {
            continue;
        };
        if let Some(org) = org_from_info_bytes(&kv.1) {
            snap.ips.insert(ip.to_string(), org);
        }
    }
    for kv in db.scan_prefix(b"cidr:").flatten() {
        let Ok(k) = std::str::from_utf8(&kv.0) else {
            continue;
        };
        let Some(cidr) = k.strip_prefix("cidr:") else {
            continue;
        };
        if let Some(org) = org_from_info_bytes(&kv.1) {
            snap.cidrs.insert(cidr.to_string(), org);
        }
    }

    // Drop the sled handle now so the file lock releases before we return
    // (the next CLI `whobelooking report` invocation needs to grab it).
    drop(db);

    let entry_count = snap.ips.len() + snap.cidrs.len();
    let json = serde_json::to_vec(&snap).map_err(|e| format!("serialize: {}", e))?;
    let etag = format!("\"snap-v1-{}-{}\"", snap.generated_at, entry_count);
    Ok(CachedBody {
        built_at: Instant::now(),
        json,
        etag,
        entry_count,
    })
}

/// `/api/enrichment.json`. Hourly-cached snapshot of the RDAP IP→org cache.
/// Compression is handled by the global `tower_http::CompressionLayer` —
/// we always emit raw JSON with the right cache headers.
pub async fn snapshot() -> Response {
    // Try-rebuild-then-serve. We hold the mutex only across the rebuild
    // path; concurrent requests during a rebuild block briefly. In the
    // hot path (cache fresh) the lock is held for nanoseconds.
    let mut guard = match cache().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let stale = guard
        .as_ref()
        .map(|c| c.built_at.elapsed() > REBUILD_AFTER)
        .unwrap_or(true);
    if stale {
        match build_snapshot() {
            Ok(b) => {
                tracing::info!(
                    "enrichment snapshot rebuilt: {} entries, {} bytes",
                    b.entry_count,
                    b.json.len()
                );
                // OTEL metric — no-op when feature is off. Tracks how often
                // the snapshot gets rebuilt and how large it is, so an
                // operator on a slow sled can spot bloat over time.
                crate::otel::metrics::instruments().enrichment_rebuilt(b.entry_count as u64);
                *guard = Some(b);
            }
            Err(e) => {
                tracing::warn!("enrichment snapshot rebuild failed: {}", e);
                if guard.is_none() {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("snapshot unavailable: {}", e),
                    )
                        .into_response();
                }
                // Else: serve the stale-but-existing cache; better than 503.
            }
        }
    }
    let body = guard
        .as_ref()
        .expect("cache populated after build/serve check");

    let mut h = axum::http::HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600, stale-while-revalidate=86400"),
    );
    if let Ok(v) = HeaderValue::from_str(&body.etag) {
        h.insert(header::ETAG, v);
    }
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );

    (h, body.json.clone()).into_response()
}
