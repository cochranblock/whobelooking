// Unlicense — public domain — whobelooking.org
//! `wbl-detect` — log parsing, schema detection, threat classification, and
//! HTML report rendering. One crate, two targets.
//!
//! Compiles native (called by the `whobelooking` binary's report path and by
//! `/api/scan/run?format=html`) and to `wasm32-unknown-unknown` (loaded by
//! the `/try` page, where the user drops a log and the browser does all
//! work). Customer rows never leave the customer's machine — that's the
//! whole point of the WASM build.
//!
//! ## KOVA compression map (local — wbl-detect's range)
//!
//! Identifiers follow the kova tokenization convention: functions get
//! `fN` prefixes, types/structs/enums get `tN`. The mapping below is the
//! source of truth; doc-comments at each definition cross-reference back.
//!
//! Number range: f400–f499 (avoids collisions with kova's f1–f300 namespace
//! documented in `~/kova/docs/compression_map.md`).
//!
//! ### Public surface
//!   * `f400 = parse_log`              — line / CSV / JSONL parsers
//!   * `f454 = parse_packet_data`      — binary pcap + hex-dump entry point
//!   * `f401 = aggregate`              — per-IP rollup + classify
//!   * `f402 = apply_enrichment`       — splice rDNS / org / country back in, re-classify
//!   * `f403 = ips_needing_enrichment` — list of IPs the browser must DoH+RDAP
//!   * `f404 = classify_ip`            — IP → IpClass priority lattice
//!   * `f405 = render_html`            — full standalone HTML document
//!   * `f406 = get_probes`             — canonical surface-area probe list → JS array (WASM)
//!
//! ### Types
//!   * `t100 = Event`             — one parsed log line
//!   * `t101 = LogFormat`         — detected input shape
//!   * `t102 = ParseStats`        — parsed / skipped / format triple
//!   * `t103 = ParseResult`       — events + stats
//!   * `t104 = IpClass`           — Threat / Institutional / Organic / Bot
//!   * `t105 = IpRecord`          — per-IP rollup
//!   * `t106 = DayStat`           — per-day hits + unique-IPs
//!   * `t107 = AggregatedReport`  — whole-log report
//!   * `t108 = IpEnrichment`      — overlay shape JS passes back
//!   * `t109 = ReportSession`     — WASM-exposed session handle
//!
//! ### Internal helpers (not re-exported)
//!   * `f410..f424` — parse.rs (regexes, date math, CSV split, RFC3339)
//!   * `f425..f431` — parse.rs (OTEL, syslog, ELK/Splunk unwrappers)
//!   * `f432..f434` — parse.rs (HAProxy, W3C fields header, W3C line)
//!   * `f435`       — parse.rs (raw IP extraction)
//!   * `f436..f439` — parse.rs (ALB, Azure JSON, GCP JSON, generic JSON)
//!   * `f454..f457` — parse.rs (pcap/hex-dump: binary entry, hex decoder, packet iterator, per-packet)
//!   * `f430`       — aggregate.rs (`is_ipv4`)
//!   * `f440..f453` — report.rs (escape, format, render-section helpers)
//!   * `f470`       — wasm_api.rs (`parse_enrichment`)
//!   * `f300..f306` — json_lite.rs (private scanner; see `mod json_lite`)
//!
//! JS-facing names are preserved via `#[wasm_bindgen(js_name = ...)]`
//! attributes — the JS layer sees `ReportSession`, `renderHtml`,
//! `applyEnrichment`, `ipsToEnrich` regardless of the Rust-side `tN`/`fN`
//! identifiers.

#![forbid(unsafe_code)]
// kova tokenization convention requires these — `tN` are snake_case-by-rule
// (lowercase + digits), `fN` are also snake_case but Rust expects function
// names to be snake_case so no warning there. The `non_camel_case_types`
// allow covers `t100..t199`. `dead_code` is for helpers used only on the
// wasm32 build; `unused_imports` keeps the tokenized re-export list from
// noising up the warnings list during refactors.
#![allow(non_camel_case_types, non_snake_case, dead_code, unused_imports)]

pub mod aggregate;
pub mod classify;
pub mod parse;
pub mod probes;
pub mod report;
pub mod schema;

// json_lite is an internal utility — it only exists to spare the WASM build
// from depending on `serde_json`. Callers consume parsed JSON through the
// public surface (`f400` for CF JSONL, `t109::applyEnrichment` for the
// overlay), so the scanner stays crate-private and isn't part of the
// library's API contract.
mod json_lite;

#[cfg(target_arch = "wasm32")]
mod wasm_api;

pub use aggregate::{f401, f402, f403, f404, t104, t105, t106, t107, t108};
pub use classify::{RowSignal, classify};
pub use parse::{f400, f454, t100, t101, t102, t103};
pub use report::f405;
pub use schema::{ColumnKind, ColumnReport, SchemaReport, detect_schema};
