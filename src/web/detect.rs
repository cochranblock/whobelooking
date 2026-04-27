// All Rights Reserved — The Cochran Block, LLC
//! `/detect` — serves the in-browser column-type detector.  All three assets
//! (HTML, JS bindings, WASM module) are embedded into the binary at compile
//! time so the deploy story stays "one binary, zero static directory".

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};

const HTML: &str = include_str!("../../static/detect/index.html");
const JS: &str = include_str!("../../static/detect/wbl_detect.js");
const WASM: &[u8] = include_bytes!("../../static/detect/wbl_detect_bg.wasm");

fn headers(content_type: &'static str, cache: &'static str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    // The detector is purely client-side — explicitly forbid the page from
    // ever issuing an outbound POST/fetch back to us with customer data.
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-eval'; \
             style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
             font-src 'self' https://fonts.gstatic.com; \
             connect-src 'self'; img-src 'self' data:; \
             frame-ancestors 'none'",
        ),
    );
    h
}

pub async fn index() -> Response {
    (
        headers("text/html; charset=utf-8", "public, max-age=300"),
        HTML,
    )
        .into_response()
}

pub async fn js() -> Response {
    (
        headers(
            "application/javascript; charset=utf-8",
            "public, max-age=86400",
        ),
        JS,
    )
        .into_response()
}

pub async fn wasm() -> Response {
    (
        headers("application/wasm", "public, max-age=86400"),
        Body::from(WASM),
    )
        .into_response()
}
