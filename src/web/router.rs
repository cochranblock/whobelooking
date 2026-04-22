// All Rights Reserved — The Cochran Block, LLC
//! Router for whobelooking.org

use axum::{Router, routing::get};
use tower_http::{
    compression::CompressionLayer,
    trace::TraceLayer,
};

use super::pages;

pub fn build() -> Router {
    Router::new()
        .route("/", get(pages::index))
        .route("/order", get(pages::order_form))
        .route("/queue", get(pages::queue_status))
        .route("/health", get(pages::health))
        .fallback(pages::not_found)
        .layer(CompressionLayer::new().zstd(true))
        .layer(TraceLayer::new_for_http())
}
