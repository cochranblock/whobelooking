// All Rights Reserved — The Cochran Block, LLC
//! WASM bindings.  Compiled only for `target_arch = "wasm32"`.
//! Exposes two entry points to JS:
//!   * `detect(text, max_rows)` — returns SchemaReport JSON
//!   * `classify_rows(text, max_rows)` — detects schema then classifies every row,
//!     returns array of `{row_index, signal, ip}` so the UI can colour the table.

use crate::{classify::classify, schema::detect_schema};
use serde::Serialize;
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
struct ClassifiedRow<'a> {
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

    let mut out: Vec<ClassifiedRow> = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        let cells: Vec<&str> = line.split(delim).map(str::trim).collect();
        let signal = classify(&schema.columns, &cells).name();
        let ip = ip_col.and_then(|idx| cells.get(idx).copied());
        out.push(ClassifiedRow {
            row_index: i,
            signal,
            ip,
        });
    }
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}
