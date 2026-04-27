// All Rights Reserved — The Cochran Block, LLC
//! Router for whobelooking.org

use axum::{
    Router,
    routing::{get, post},
};
use tower_http::{compression::CompressionLayer, trace::TraceLayer};

use super::{admin, checkout, detect, metrics, pages, scan};

pub fn build() -> Router {
    Router::new()
        // Public
        .route("/", get(pages::demo))
        .route("/about", get(pages::index))
        .route("/order", get(pages::order_form))
        .route("/order/checkout", post(checkout::create_checkout))
        .route("/order/confirmed", get(checkout::checkout_success))
        .route("/status/{id}", get(pages::job_status))
        .route("/download/{id}", get(pages::download_report))
        .route(
            "/download/{id}/session",
            post(pages::create_download_session),
        )
        .route("/queue", get(pages::queue_status))
        .route("/health", get(pages::health))
        .route("/robots.txt", get(pages::robots))
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
        .route("/api/scan/pay", post(scan::pay))
        .route("/api/scan/gate", post(scan::gate))
        .route("/api/scan/finalize", post(scan::finalize))
        // Admin (token-gated)
        .route("/admin", get(admin::dashboard))
        .route("/metrics", get(metrics::endpoint))
        .fallback(pages::not_found)
        .layer(CompressionLayer::new().zstd(true))
        .layer(axum::middleware::from_fn(super::visits::log_middleware))
        .layer(TraceLayer::new_for_http())
}
