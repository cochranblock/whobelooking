// All Rights Reserved — The Cochran Block, LLC
//! Threat classifier — input is a single row's typed values, output is one of
//! the seven KOVA threat tiers.  Mirrors `whobelooking::redact::classify` but
//! works on detected columns instead of raw paths/UAs (which the schema
//! detector has already located for us).

use crate::schema::{ColumnKind, ColumnReport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RowSignal {
    CredHunt,
    Exploit,
    WpProbe,
    LlmProbe,
    Crawler,
    Buyer,
    Browser,
}

impl RowSignal {
    pub fn name(self) -> &'static str {
        match self {
            RowSignal::CredHunt => "CRED_HUNT",
            RowSignal::Exploit => "EXPLOIT",
            RowSignal::WpProbe => "WP_PROBE",
            RowSignal::LlmProbe => "LLM_PROBE",
            RowSignal::Crawler => "CRAWLER",
            RowSignal::Buyer => "BUYER",
            RowSignal::Browser => "BROWSER",
        }
    }
}

/// Classify one row.  Caller passes the schema (so we know which column is the
/// path and which is the UA) plus the row's split cells.
pub fn classify(schema: &[ColumnReport], row: &[&str]) -> RowSignal {
    let mut path: &str = "";
    let mut ua: &str = "";
    for col in schema {
        if let Some(cell) = row.get(col.index) {
            match col.kind {
                ColumnKind::UrlPath if path.is_empty() => path = cell,
                ColumnKind::UserAgent if ua.is_empty() => ua = cell,
                _ => {}
            }
        }
    }

    let pl: LowerView = LowerView::new(path);
    let ul: LowerView = LowerView::new(ua);

    if pl.contains_any(&[
        ".env",
        ".aws",
        ".git/",
        ".ssh",
        ".npmrc",
        ".boto",
        ".pgpass",
        ".pypirc",
        "credentials",
        "id_rsa",
        ".dockerconfigjson",
    ]) {
        return RowSignal::CredHunt;
    }
    if pl.contains_any(&[
        "phpmyadmin",
        "adminer",
        "shell.php",
        "config.php",
        "/cgi-bin/",
        "/manager/html",
        "/admin/serverconfig",
        "/actuator/env",
        "/swagger",
    ]) {
        return RowSignal::Exploit;
    }
    if pl.contains_any(&[
        "wp-admin",
        "wp-login",
        "wp-includes",
        "wlwmanifest",
        "xmlrpc",
        "wordpress",
        "/3.php",
        "xmrlpc",
    ]) {
        return RowSignal::WpProbe;
    }
    if pl.contains_any(&[
        "/v1/completions",
        "/v1/embeddings",
        "/v1/models",
        "/v1/chat",
    ]) {
        return RowSignal::LlmProbe;
    }
    if ul.contains_any(&[
        "googlebot",
        "bingbot",
        "gptbot",
        "chatgpt",
        "anthropic",
        "applebot",
        "bytespider",
        "yandexbot",
        "duckduck",
        "linkedinbot",
        "ccbot",
        "facebookexternalhit",
        "crawl",
        " bot",
        "spider",
    ]) {
        return RowSignal::Crawler;
    }
    const BUYER: &[&str] = &[
        "/order",
        "/contact",
        "/pricing",
        "/about",
        "/products",
        "/services",
        "/checkout",
        "/govdocs",
        "/sbir",
        "/dcaa",
        "/vre",
        "/book",
        "/booking",
        "/intake",
    ];
    if pl.contains_any(BUYER) {
        return RowSignal::Buyer;
    }
    RowSignal::Browser
}

/// Stack-resident lowercase view — avoids a `String` allocation per row in the
/// hot path. Holds the original slice plus a flag set during construction so
/// `contains_any` can do a case-insensitive search via `eq_ignore_ascii_case`.
#[derive(Clone, Copy)]
struct LowerView<'a> {
    raw: &'a str,
}

impl<'a> LowerView<'a> {
    fn new(raw: &'a str) -> Self {
        Self { raw }
    }

    fn contains_any(&self, needles: &[&str]) -> bool {
        if self.raw.is_empty() {
            return false;
        }
        let bytes = self.raw.as_bytes();
        for needle in needles {
            let nb = needle.as_bytes();
            if nb.is_empty() || nb.len() > bytes.len() {
                continue;
            }
            for window in bytes.windows(nb.len()) {
                if window.eq_ignore_ascii_case(nb) {
                    return true;
                }
            }
        }
        false
    }
}
