// Unlicense — public domain — whobelooking.org
//! WASM bindings.  Compiled only for `target_arch = "wasm32"`.
//!
//! Three groups of exports:
//!
//! 1. Legacy schema/row API (kept for backwards compatibility with the
//!    existing `/detect` page):
//!      * `detect(text, max_rows)` → SchemaReport JSON
//!      * `classify_rows(text, max_rows)` → array of `{row_index, signal, ip}`
//!
//! 2. The full report pipeline — what `/try` calls:
//!      * `ReportSession::new(text, source_label)` — parse + aggregate
//!      * `ReportSession::ips_to_enrich()` — list the JS layer must look up
//!      * `ReportSession::f402(json)` — splice in rDNS/org
//!      * `ReportSession::f405()` — final standalone HTML string
//!      * `ReportSession::stats()` — small JSON for the loading UI
//!
//! 3. One-shot convenience:
//!      * `render_report(text, source_label)` — parse + aggregate + render in
//!        one call, no enrichment. Used for the fast first paint before the
//!        JS layer has resolved any DoH/RDAP.

use crate::aggregate::{f401, f402, f403, t108};
use crate::parse::f400;
use crate::report::f405;
use crate::{classify::classify, schema::detect_schema};
use serde::Serialize;
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn _start() {
    #[cfg(feature = "panic-hook")]
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn detect(text: &str, max_rows: u32) -> Result<JsValue, JsValue> {
    let max = if max_rows == 0 {
        1024
    } else {
        max_rows as usize
    };
    let report = detect_schema(text, max);
    serde_wasm_bindgen::to_value(&report).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[derive(Serialize)]
struct t150<'a> {
    row_index: usize,
    signal: &'static str,
    ip: Option<&'a str>,
}

#[wasm_bindgen]
pub fn classify_rows(text: &str, max_rows: u32) -> Result<JsValue, JsValue> {
    let max = if max_rows == 0 {
        4096
    } else {
        max_rows as usize
    };
    let schema = detect_schema(text, max);
    let delim = schema.delimiter;
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .skip(if schema.had_header { 1 } else { 0 })
        .collect();
    let ip_col = schema
        .columns
        .iter()
        .find(|c| matches!(c.kind, crate::schema::ColumnKind::Ip))
        .map(|c| c.index);

    let mut out: Vec<t150> = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        let cells: Vec<&str> = line.split(delim).map(str::trim).collect();
        let signal = classify(&schema.columns, &cells).name();
        let ip = ip_col.and_then(|idx| cells.get(idx).copied());
        out.push(t150 {
            row_index: i,
            signal,
            ip,
        });
    }
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ── Session-based pipeline ────────────────────────────────────────────────
//
// JS holds the handle; the WASM owns the t107 so it doesn't
// have to be serialized across the FFI boundary on every render. JS still
// has to do the DoH PTR + RDAP fetches itself (browsers force network
// through JS), so the enrichment overlay comes back across as one JSON
// blob and is applied in-place.

#[wasm_bindgen]
#[wasm_bindgen(js_name = ReportSession)]
/// t109 = ReportSession
pub struct t109 {
    report: crate::aggregate::t107,
    source: String,
    parse_stats: crate::parse::t102,
}

#[derive(Serialize)]
struct t151 {
    parsed: usize,
    skipped: usize,
    format: String,
    unique_ips: usize,
    distinct_paths: usize,
    days: usize,
    class_counts: BTreeMap<String, u32>,
}

fn f470(json: &str) -> Result<BTreeMap<String, t108>, String> {
    let raw =
        crate::json_lite::f304(json).ok_or_else(|| "enrichment json malformed".to_string())?;
    let mut out: BTreeMap<String, t108> = BTreeMap::new();
    for (ip, fields) in raw {
        let mut e = t108::default();
        if let Some(v) = fields.get("rdns") {
            if !v.is_empty() {
                e.rdns = Some(v.clone());
            }
        }
        if let Some(v) = fields.get("org") {
            if !v.is_empty() {
                e.org = Some(v.clone());
            }
        }
        if let Some(v) = fields.get("org_country") {
            if !v.is_empty() {
                e.org_country = Some(v.clone());
            }
        }
        if let Some(v) = fields.get("country") {
            if !v.is_empty() && e.org_country.is_none() {
                e.org_country = Some(v.clone());
            }
        }
        out.insert(ip, e);
    }
    Ok(out)
}

/// Hard cap on log input the WASM session will accept. 512 MiB is roughly
/// a full day of Logpush traffic for a busy site (Cloudflare itself caps
/// individual log batches around the 100 MB mark). Past this size the per-
/// event `String` allocations explode and the tab OOMs without a catchable
/// error on the JS side — so we refuse early with a typed error instead.
pub const MAX_INPUT_BYTES: usize = 512 * 1024 * 1024;

#[wasm_bindgen(js_class = "ReportSession")]
impl t109 {
    /// Returns `Err(JsValue)` when the input is empty or larger than
    /// `MAX_INPUT_BYTES`. JS sees a normal thrown error and can render a
    /// friendly message instead of a blank tab.
    #[wasm_bindgen(constructor)]
    pub fn new(text: &str, source_label: &str) -> Result<t109, JsValue> {
        if text.is_empty() {
            return Err(JsValue::from_str("empty input"));
        }
        if text.len() > MAX_INPUT_BYTES {
            return Err(JsValue::from_str(&format!(
                "input too large: {} bytes (limit {} bytes / {} MiB) — try splitting the log",
                text.len(),
                MAX_INPUT_BYTES,
                MAX_INPUT_BYTES / 1024 / 1024,
            )));
        }
        let parse_result = f400(text);
        let report = f401(&parse_result.events);
        Ok(t109 {
            report,
            source: source_label.to_string(),
            parse_stats: parse_result.stats,
        })
    }

    /// JSON-string list of IPv4 addresses the browser should DoH+RDAP for.
    /// IPv6 is intentionally excluded in v0 — the reverse zone is its own
    /// beast and a partial result is better than blocking the report.
    #[wasm_bindgen(js_name = ipsToEnrich)]
    pub fn ips_to_enrich(&self) -> Result<JsValue, JsValue> {
        let list = f403(&self.report);
        serde_wasm_bindgen::to_value(&list).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Apply an enrichment overlay built in JS:
    /// `{ "1.2.3.4": { "rdns": "...", "org": "...", "org_country": "..." }, ... }`
    /// Missing keys keep their old values; missing IPs are ignored.
    #[wasm_bindgen(js_name = applyEnrichment)]
    pub fn f402(&mut self, json: &str) -> Result<(), JsValue> {
        let map = f470(json).map_err(|e| JsValue::from_str(&e))?;
        f402(&mut self.report, &map);
        Ok(())
    }

    /// Render the full standalone HTML report — what the user downloads.
    #[wasm_bindgen(js_name = renderHtml)]
    pub fn f405(&self) -> String {
        f405(&self.report, &self.source)
    }

    /// Small JSON blob the loading UI displays (parsed/skipped count,
    /// detected format, class breakdown). No customer-data leakage; safe
    /// to log to the page.
    #[wasm_bindgen(js_name = stats)]
    pub fn stats(&self) -> Result<JsValue, JsValue> {
        let s = t151 {
            parsed: self.parse_stats.parsed,
            skipped: self.parse_stats.skipped,
            format: self.parse_stats.format.clone(),
            unique_ips: self.report.ips.len(),
            distinct_paths: self.report.distinct_paths,
            days: self.report.days.len(),
            class_counts: self.report.class_counts.clone(),
        };
        serde_wasm_bindgen::to_value(&s).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

/// One-shot fast path: parse + aggregate + render with no enrichment.
/// Used by `/try` to paint a first report instantly while the JS layer
/// kicks off DoH + RDAP in parallel.
#[wasm_bindgen(js_name = renderReport)]
pub fn render_report(text: &str, source_label: &str) -> String {
    let parsed = f400(text);
    let report = f401(&parsed.events);
    f405(&report, source_label)
}
