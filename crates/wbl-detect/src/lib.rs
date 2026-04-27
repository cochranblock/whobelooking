// All Rights Reserved — The Cochran Block, LLC
//! `wbl-detect` — universal log/CSV column-type detector + threat classifier.
//!
//! Runs both natively (called from `whobelooking detect`) and in the browser
//! (compiled to wasm32-unknown-unknown, called from `/detect`'s drag-drop UI).
//! Customer rows never leave the customer's machine — that is the whole point.
//!
//! Pattern: per-column, run a fixed roster of regexes against the first N rows;
//! the regex with the highest match-rate wins (subject to a confidence floor).
//! Once columns are typed we route them into the threat classifier.

#![forbid(unsafe_code)]

pub mod classify;
pub mod schema;

#[cfg(target_arch = "wasm32")]
mod wasm_api;

pub use classify::{RowSignal, classify};
pub use schema::{ColumnKind, ColumnReport, SchemaReport, detect_schema};
