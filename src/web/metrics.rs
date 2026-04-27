// All Rights Reserved — The Cochran Block, LLC
//! `/metrics` — minimal Prometheus text-format endpoint.
//!
//! No `metrics` crate dependency. We track a small fixed set of counters
//! relevant to the product: HTTP requests by status class, order states,
//! RDAP cache size, queue capacity. New counters get added when something
//! breaks and we wished we'd had visibility.
//!
//! Token-gated like `/admin` — operator can scrape it from a localhost
//! cron, no public exposure.

use axum::extract::Query;
use axum::http::HeaderValue;
use axum::http::header;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Snapshot of all in-memory counters — serialized to bincode+zstd on SIGTERM
/// so the next process (Gemini Man handoff) can restore and continue counting.
#[derive(Serialize, Deserialize, Default)]
pub struct ProcessState {
    pub http_2xx: u64,
    pub http_3xx: u64,
    pub http_4xx: u64,
    pub http_5xx: u64,
    pub order_creates_ok: u64,
    pub order_creates_rejected: u64,
    pub downloads_authed: u64,
    pub downloads_404: u64,
    pub saved_at: u64,
}

impl ProcessState {
    pub fn capture() -> Self {
        ProcessState {
            http_2xx: HTTP_REQUESTS_2XX.load(Ordering::Relaxed),
            http_3xx: HTTP_REQUESTS_3XX.load(Ordering::Relaxed),
            http_4xx: HTTP_REQUESTS_4XX.load(Ordering::Relaxed),
            http_5xx: HTTP_REQUESTS_5XX.load(Ordering::Relaxed),
            order_creates_ok: ORDER_CREATES_OK.load(Ordering::Relaxed),
            order_creates_rejected: ORDER_CREATES_REJECTED.load(Ordering::Relaxed),
            downloads_authed: DOWNLOADS_AUTHED.load(Ordering::Relaxed),
            downloads_404: DOWNLOADS_404.load(Ordering::Relaxed),
            saved_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }

    pub fn apply(&self) {
        HTTP_REQUESTS_2XX.fetch_add(self.http_2xx, Ordering::Relaxed);
        HTTP_REQUESTS_3XX.fetch_add(self.http_3xx, Ordering::Relaxed);
        HTTP_REQUESTS_4XX.fetch_add(self.http_4xx, Ordering::Relaxed);
        HTTP_REQUESTS_5XX.fetch_add(self.http_5xx, Ordering::Relaxed);
        ORDER_CREATES_OK.fetch_add(self.order_creates_ok, Ordering::Relaxed);
        ORDER_CREATES_REJECTED.fetch_add(self.order_creates_rejected, Ordering::Relaxed);
        DOWNLOADS_AUTHED.fetch_add(self.downloads_authed, Ordering::Relaxed);
        DOWNLOADS_404.fetch_add(self.downloads_404, Ordering::Relaxed);
    }
}

#[derive(Deserialize)]
pub struct MetricsQuery {
    pub token: Option<String>,
}

// --- counters ---
// Plain atomics; bump from any handler. Process-lifetime totals.

pub static HTTP_REQUESTS_2XX: AtomicU64 = AtomicU64::new(0);
pub static HTTP_REQUESTS_3XX: AtomicU64 = AtomicU64::new(0);
pub static HTTP_REQUESTS_4XX: AtomicU64 = AtomicU64::new(0);
pub static HTTP_REQUESTS_5XX: AtomicU64 = AtomicU64::new(0);
pub static ORDER_CREATES_OK: AtomicU64 = AtomicU64::new(0);
pub static ORDER_CREATES_REJECTED: AtomicU64 = AtomicU64::new(0);
pub static DOWNLOADS_AUTHED: AtomicU64 = AtomicU64::new(0);
pub static DOWNLOADS_404: AtomicU64 = AtomicU64::new(0);

/// Bump the right counter for an HTTP status code.
pub fn record_status(code: u16) {
    let counter = match code {
        200..=299 => &HTTP_REQUESTS_2XX,
        300..=399 => &HTTP_REQUESTS_3XX,
        400..=499 => &HTTP_REQUESTS_4XX,
        500..=599 => &HTTP_REQUESTS_5XX,
        _ => return,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

fn check_token(q: &MetricsQuery) -> bool {
    let expected = std::env::var("ADMIN_TOKEN").unwrap_or_else(|_| "changeme".into());
    q.token.as_deref() == Some(&expected)
}

pub async fn endpoint(Query(q): Query<MetricsQuery>) -> Response {
    if !check_token(&q) {
        let mut resp = Response::new("unauthorized".to_string().into());
        *resp.status_mut() = axum::http::StatusCode::UNAUTHORIZED;
        return resp;
    }

    // Live gauges sampled at scrape time.
    let store = crate::orders::Store::open().ok();
    let pending = store.as_ref().map(|s| s.pending_count()).unwrap_or(0);
    let total = store
        .as_ref()
        .and_then(|s| s.list_all().ok())
        .map(|v| v.len())
        .unwrap_or(0);

    let mut body = String::with_capacity(2048);
    use std::fmt::Write;

    let _ = writeln!(
        body,
        "# HELP whobelooking_http_requests_total HTTP responses by status class"
    );
    let _ = writeln!(body, "# TYPE whobelooking_http_requests_total counter");
    let _ = writeln!(
        body,
        "whobelooking_http_requests_total{{class=\"2xx\"}} {}",
        HTTP_REQUESTS_2XX.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        body,
        "whobelooking_http_requests_total{{class=\"3xx\"}} {}",
        HTTP_REQUESTS_3XX.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        body,
        "whobelooking_http_requests_total{{class=\"4xx\"}} {}",
        HTTP_REQUESTS_4XX.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        body,
        "whobelooking_http_requests_total{{class=\"5xx\"}} {}",
        HTTP_REQUESTS_5XX.load(Ordering::Relaxed)
    );

    let _ = writeln!(
        body,
        "# HELP whobelooking_orders_created_total Orders accepted by the queue"
    );
    let _ = writeln!(body, "# TYPE whobelooking_orders_created_total counter");
    let _ = writeln!(
        body,
        "whobelooking_orders_created_total{{result=\"ok\"}} {}",
        ORDER_CREATES_OK.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        body,
        "whobelooking_orders_created_total{{result=\"rejected\"}} {}",
        ORDER_CREATES_REJECTED.load(Ordering::Relaxed)
    );

    let _ = writeln!(
        body,
        "# HELP whobelooking_downloads_total Report download attempts"
    );
    let _ = writeln!(body, "# TYPE whobelooking_downloads_total counter");
    let _ = writeln!(
        body,
        "whobelooking_downloads_total{{result=\"authed\"}} {}",
        DOWNLOADS_AUTHED.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        body,
        "whobelooking_downloads_total{{result=\"not_found\"}} {}",
        DOWNLOADS_404.load(Ordering::Relaxed)
    );

    let _ = writeln!(
        body,
        "# HELP whobelooking_orders_pending Orders currently in `Pending` state"
    );
    let _ = writeln!(body, "# TYPE whobelooking_orders_pending gauge");
    let _ = writeln!(body, "whobelooking_orders_pending {}", pending);

    let _ = writeln!(
        body,
        "# HELP whobelooking_orders_total Orders across all states (lifetime)"
    );
    let _ = writeln!(body, "# TYPE whobelooking_orders_total gauge");
    let _ = writeln!(body, "whobelooking_orders_total {}", total);

    let mut resp = Response::new(body.into());
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    resp
}
