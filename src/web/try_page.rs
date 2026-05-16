// Unlicense — public domain — whobelooking.org
//! `/try` — single-file in-browser visitor-intelligence tool.
//!
//! Pure client-side: the user drops an access log, the browser parses,
//! classifies, enriches (DoH PTR + RDAP), and renders the demo-style
//! 3-pane layout. The server never sees a single log line.
//!
//! ## Airgap mode — configurable enrichment endpoints
//!
//! Operators on isolated networks can point `/try` at internal mirrors
//! instead of the public DoH / RDAP / font endpoints. Configuration is
//! env-var driven, substituted into the served HTML at request time, and
//! reflected in the CSP `connect-src` so the browser actually allows
//! the calls:
//!
//!   * `WBL_DOH_URL`           — DoH endpoint (default `https://cloudflare-dns.com/dns-query`)
//!   * `WBL_RDAP_BASE`         — RDAP service base (default `https://rdap.org`)
//!   * `WBL_ENRICHMENT_URL`    — snapshot URL (default `/api/enrichment.json`)
//!   * `WBL_FONTS_HREF`        — Google Fonts stylesheet href (default the standard googleapis link;
//!     set to empty to drop the `<link>` tag entirely — fonts fall back to the local CSS family stack)
//!   * `WBL_AIRGAP_NOTICE`     — banner text rendered in the drop-zone when set; useful for
//!     showing "OFFLINE MODE · routing through local resolver" to operators
//!
//! ## Privacy posture
//!
//! Even with default endpoints, customer log content never leaves the
//! browser. What DOES leave: DoH PTR queries (one per IPv4), RDAP whois
//! queries (one per /24), and a fetch for the snapshot fast-path. On a
//! configured airgap deploy all of these point at internal hosts, so
//! the browser's network panel shows zero external traffic.

use axum::{
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};

const HTML_TEMPLATE: &str = include_str!("../../static/try/index.html");

/// Resolve the configured value or fall back to `default`. Trim and reject
/// any whitespace-only env-var that would otherwise produce a broken URL.
fn env_or(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => default.to_string(),
    }
}

/// Allow callers to drop a knob entirely by setting the env var to
/// an empty string. Used for `WBL_FONTS_HREF` so airgap deploys can
/// omit the Google Fonts link cleanly. Returns `None` if the env var
/// is set-but-empty; `Some(default)` if unset; `Some(value)` otherwise.
fn env_or_unset(key: &str, default: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if v.trim().is_empty() => None,
        Ok(v) => Some(v.trim().to_string()),
        Err(_) => Some(default.to_string()),
    }
}

/// Extract the scheme+host[:port] from a URL for CSP `connect-src` use.
/// CSP wants source expressions, not full URLs with paths.
fn origin_of(url: &str) -> String {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    match after_scheme {
        Some(rest) => {
            let host = rest.split('/').next().unwrap_or(rest);
            let scheme = if url.starts_with("https://") {
                "https://"
            } else {
                "http://"
            };
            format!("{}{}", scheme, host)
        }
        // Same-origin / relative URL → no extra source expression needed.
        None => String::new(),
    }
}

struct Endpoints {
    doh_url: String,
    rdap_base: String,
    snapshot_url: String,
    fonts_href: Option<String>,
    airgap_notice: String,
}

fn endpoints() -> Endpoints {
    Endpoints {
        doh_url: env_or("WBL_DOH_URL", "https://cloudflare-dns.com/dns-query"),
        rdap_base: env_or("WBL_RDAP_BASE", "https://rdap.org"),
        snapshot_url: env_or("WBL_ENRICHMENT_URL", "/api/enrichment.json"),
        fonts_href: env_or_unset(
            "WBL_FONTS_HREF",
            "https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700&family=Rajdhani:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap",
        ),
        airgap_notice: env_or("WBL_AIRGAP_NOTICE", ""),
    }
}

/// Replace `__WBL_TOKEN__` placeholders in the static HTML with the
/// resolved endpoint values. Done at request time because the env may
/// change between deploys; the result is small so we don't bother
/// caching. If a performance concern materializes later, wrap this in a
/// `OnceLock` keyed on a snapshot of the env vars.
fn render(eps: &Endpoints) -> String {
    let fonts_link = match &eps.fonts_href {
        Some(href) => format!(
            r#"<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="{}" rel="stylesheet">"#,
            href
        ),
        None => String::new(),
    };
    let notice = if eps.airgap_notice.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div style="background:#0d0d14;border:1px solid var(--orange);color:var(--orange);padding:10px 18px;margin:12px 0;font-size:11px;letter-spacing:.15em;text-transform:uppercase;text-align:center;">{}</div>"#,
            html_escape::encode_text(&eps.airgap_notice)
        )
    };
    HTML_TEMPLATE
        .replace("__WBL_DOH_URL__", &eps.doh_url)
        .replace("__WBL_RDAP_BASE__", &eps.rdap_base)
        .replace("__WBL_ENRICHMENT_URL__", &eps.snapshot_url)
        .replace("__WBL_FONTS_LINK__", &fonts_link)
        .replace("__WBL_AIRGAP_NOTICE__", &notice)
}

// Tiny inline HTML-escaper — pulling in a crate for one call site would be
// silly. Same shape as the rest of the codebase uses for user-visible text.
mod html_escape {
    pub fn encode_text(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#39;"),
                _ => out.push(c),
            }
        }
        out
    }
}

fn headers(eps: &Endpoints) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );

    // CSP must include whatever connect-src destinations the configured
    // endpoints resolve to. We compute the source expressions per-request;
    // an airgap deploy that points DoH at `https://dns.internal.gov`
    // gets a CSP `connect-src` that allows exactly that host — no
    // accidental allow-list bloat.
    let doh_origin = origin_of(&eps.doh_url);
    let rdap_origin = origin_of(&eps.rdap_base);
    let snapshot_origin = origin_of(&eps.snapshot_url);
    let mut connect_src = vec!["'self'".to_string()];
    for origin in [&doh_origin, &rdap_origin, &snapshot_origin] {
        if !origin.is_empty() && !connect_src.contains(origin) {
            connect_src.push(origin.clone());
        }
    }
    // The default RDAP service redirects to per-RIR hosts. When the
    // operator hasn't overridden RDAP, keep the legacy allow-list so
    // existing deploys don't break; when overridden, only the configured
    // host is allowed.
    if eps.rdap_base == "https://rdap.org" {
        for legacy in [
            "https://rdap.arin.net",
            "https://rdap.db.ripe.net",
            "https://rdap.apnic.net",
            "https://rdap.lacnic.net",
            "https://rdap.afrinic.net",
        ] {
            if !connect_src.iter().any(|s| s == legacy) {
                connect_src.push(legacy.to_string());
            }
        }
    }

    let (style_src, font_src) = match &eps.fonts_href {
        Some(_) => (
            "'self' 'unsafe-inline' https://fonts.googleapis.com",
            "'self' https://fonts.gstatic.com",
        ),
        None => ("'self' 'unsafe-inline'", "'self'"),
    };

    let csp = format!(
        "default-src 'self'; \
         script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; \
         style-src {}; \
         font-src {}; \
         img-src 'self' data:; \
         frame-src 'self' blob:; \
         connect-src {}; \
         frame-ancestors 'none'",
        style_src,
        font_src,
        connect_src.join(" "),
    );
    if let Ok(v) = HeaderValue::from_str(&csp) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    h
}

pub async fn index() -> Response {
    let eps = endpoints();
    let html = render(&eps);
    (headers(&eps), html).into_response()
}
