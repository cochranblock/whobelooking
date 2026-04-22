// All Rights Reserved — The Cochran Block, LLC
//! Router for whobelooking.org

use axum::{Router, routing::{get, post}};
use tower_http::{
    compression::CompressionLayer,
    trace::TraceLayer,
};

use super::{checkout, pages};

pub fn build() -> Router {
    Router::new()
        .route("/", get(pages::demo))
        .route("/about", get(pages::index))
        .route("/order", get(pages::order_form))
        .route("/order/checkout", post(checkout::create_checkout))
        .route("/order/confirmed", get(checkout::checkout_success))
        .route("/queue", get(pages::queue_status))
        .route("/health", get(pages::health))
        .route("/robots.txt", get(pages::robots))
        .fallback(pages::not_found)
        .layer(CompressionLayer::new().zstd(true))
        .layer(TraceLayer::new_for_http())
}
