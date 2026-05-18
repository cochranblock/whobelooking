// All Rights Reserved — The Cochran Block, LLC
//! Router for whobelooking.org

use axum::{
    Router,
    response::IntoResponse,
    routing::{get, post},
};
use tower_http::{compression::CompressionLayer, trace::TraceLayer};

use super::{admin, detect, enrichment, metrics, openapi, pages, scan, try_page};

pub fn build() -> Router {
    Router::new()
        // Public
        .route("/", get(pages::demo))
        .route("/about", get(pages::index))
        // Order form removed — whobelooking is free / Unlicense / public domain.
        // Old /order paths now redirect to the GitHub repo (clone & run yourself).
        .route(
            "/order",
            get(|| async {
                axum::response::Redirect::permanent("https://github.com/cochranblock/whobelooking")
            }),
        )
        .route(
            "/order/checkout",
            post(|| async {
                axum::response::Redirect::permanent("https://github.com/cochranblock/whobelooking")
            }),
        )
        .route(
            "/order/confirmed",
            get(|| async {
                axum::response::Redirect::permanent("https://github.com/cochranblock/whobelooking")
            }),
        )
        .route("/status/{id}", get(pages::job_status))
        .route("/download/{id}", get(pages::download_report))
        .route(
            "/download/{id}/session",
            post(pages::create_download_session),
        )
        .route("/queue", get(pages::queue_status))
        .route("/health", get(pages::health))
        .route("/robots.txt", get(pages::robots))
        .route("/llms.txt", get(pages::llms_txt))
        // /try — drop your log, get the demo experience entirely in your browser.
        // Server never sees a line of customer data; we just serve the static page.
        .route("/try", get(try_page::index))
        .route("/try/", get(try_page::index))
        // /api/enrichment.json — public IP→org snapshot from the RDAP cache.
        // Pre-warms the in-browser /try lookups so common ranges (Microsoft,
        // Google, AWS) resolve instantly without each visitor re-doing RDAP.
        .route("/api/enrichment.json", get(enrichment::snapshot))
        // Detect — in-browser WASM column-type detector + classifier.
        // Customer logs never leave the customer; we just serve the static bundle.
        .route("/detect", get(detect::index))
        .route("/detect/", get(detect::index))
        .route("/detect/wbl_detect.js", get(detect::js))
        .route("/detect/wbl_detect_bg.wasm", get(detect::wasm))
        // Scan — automated diagnostic surface area scan.
        .route("/scan", get(scan::index))
        .route("/scan/", get(scan::index))
        .route("/api/probe", get(scan::probe))
        .route("/api/scan/status", get(scan::status))
        .route("/api/scan/pay", post(scan::pay))
        .route("/api/scan/gate", post(scan::gate))
        .route("/api/scan/finalize", post(scan::finalize))
        .route("/api/scan/feedback", post(super::feedback::submit))
        .route("/openapi.json", get(openapi::json))
        .route("/docs", get(openapi::ui))
        .route("/docs/", get(openapi::ui))
        .route("/skill", get(openapi::skill_md))
        .route("/skill.md", get(openapi::skill_md))
        .route("/install-skill.sh", get(openapi::install_skill_sh))
        // Admin (token-gated)
        .route("/admin", get(admin::dashboard))
        .route("/metrics", get(metrics::endpoint))
        .fallback(pages::not_found)
        .layer(CompressionLayer::new().zstd(true))
        .layer(axum::middleware::from_fn(redirect_legacy_hosts))
        .layer(axum::middleware::from_fn(super::visits::log_middleware))
        .layer(TraceLayer::new_for_http())
}

/// 301 anything served at the legacy whobelooking.org / .com hostnames over
/// to whobelooking.cochranblock.org. The product is consolidating onto a
/// single subdomain under the cochranblock umbrella; old domains stay live
/// only as redirectors so existing inbound links keep working.
async fn redirect_legacy_hosts(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(host) = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
    {
        let h = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
        let legacy = matches!(
            h.as_str(),
            "whobelooking.org"
                | "www.whobelooking.org"
                | "whobelooking.com"
                | "www.whobelooking.com"
        );
        if legacy {
            let pq = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/");
            let target = format!("https://whobelooking.cochranblock.org{}", pq);
            return axum::response::Redirect::permanent(&target).into_response();
        }
    }
    next.run(req).await
}
