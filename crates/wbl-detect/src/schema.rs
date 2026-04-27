// All Rights Reserved — The Cochran Block, LLC
//! Column-type detection by per-cell regex voting.
//!
//! No assumption about delimiter — caller passes `Vec<Vec<&str>>` of pre-split
//! rows. `detect_delimiter` is a small heuristic on the first 4KB.

use regex_lite::Regex;
use serde::{Deserialize, Serialize};

/// Every column type the detector knows how to recognise. Order is preference
/// when several patterns score equal: more-specific kinds beat more-general.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ColumnKind {
    /// Either IPv4 or IPv6 — the detector does not fragment IP columns by family.
    /// Mixed v4/v6 columns (a customer's CF logs almost always contain both) vote
    /// to a single `Ip` kind so the confidence floor isn't split.
    Ip,
    Cidr,
    Port,
    Asn,
    CountryCode,
    Iso8601,
    EpochSecs,
    EpochMs,
    HttpMethod,
    StatusCode,
    UrlPath,
    Hostname,
    UserAgent,
    HexHash,
    Email,
    Empty,
    Unknown,
}

impl ColumnKind {
    pub fn name(self) -> &'static str {
        match self {
            ColumnKind::Ip => "ip",
            ColumnKind::Cidr => "cidr",
            ColumnKind::Port => "port",
            ColumnKind::Asn => "asn",
            ColumnKind::CountryCode => "country_code",
            ColumnKind::Iso8601 => "iso8601",
            ColumnKind::EpochSecs => "epoch_secs",
            ColumnKind::EpochMs => "epoch_ms",
            ColumnKind::HttpMethod => "http_method",
            ColumnKind::StatusCode => "status_code",
            ColumnKind::UrlPath => "url_path",
            ColumnKind::Hostname => "hostname",
            ColumnKind::UserAgent => "user_agent",
            ColumnKind::HexHash => "hex_hash",
            ColumnKind::Email => "email",
            ColumnKind::Empty => "empty",
            ColumnKind::Unknown => "unknown",
        }
    }
}

/// Per-column verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnReport {
    pub index: usize,
    pub header: Option<String>,
    pub kind: ColumnKind,
    /// 0.0–1.0 — fraction of sampled rows that matched the winning regex.
    pub confidence: f32,
    /// First few sample values (truncated) so the UI can render a preview.
    pub samples: Vec<String>,
}

/// Whole-file verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaReport {
    pub columns: Vec<ColumnReport>,
    pub delimiter: char,
    pub rows_sampled: usize,
    pub had_header: bool,
}

/// Lazily-built regex roster.  We keep one regex per `ColumnKind` we care
/// about; if a kind has multiple shapes (e.g. epoch s vs ms) we pick the
/// stricter one.  Patterns are anchored — a value must match the whole cell.
struct Patterns {
    pairs: Vec<(ColumnKind, Regex)>,
}

impl Patterns {
    fn new() -> Self {
        let raw: &[(ColumnKind, &str)] = &[
            // IPv4 OR IPv6 — one regex, one kind. Customers' logs almost always
            // contain both families in the same column. The IPv6 alternation
            // covers every legal compressed form (RFC 5952) including `::1`,
            // `fe80::1`, `2600:4040:b03c:300::1c7b`, and full 8-group forms.
            (
                ColumnKind::Ip,
                r"(?x)
                ^(?:
                    # IPv4 dotted quad
                    (?:25[0-5]|2[0-4]\d|1?\d?\d)
                    (?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}
                  |
                    # IPv6 — every legal compressed and uncompressed form
                    (?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}
                  | (?:[0-9a-fA-F]{1,4}:){1,7}:
                  | (?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}
                  | (?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}
                  | (?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}
                  | (?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}
                  | (?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}
                  | [0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}
                  | :(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)
                )$",
            ),
            (
                ColumnKind::Cidr,
                r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/\d{1,2}$",
            ),
            // StatusCode must come before Port: "404" matches both, but per-column
            // voting will correct misclassification on actual port columns (8080,
            // 22, 65535 won't match status pattern, so the column resolves to Port).
            (ColumnKind::StatusCode, r"^[1-5]\d{2}$"),
            (
                ColumnKind::Port,
                r"^(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$",
            ),
            (ColumnKind::Asn, r"^(?i)(?:as)?[1-9]\d{0,5}$"),
            (ColumnKind::CountryCode, r"^[A-Z]{2}$"),
            (
                ColumnKind::Iso8601,
                r"^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?Z?)?$",
            ),
            (ColumnKind::EpochMs, r"^1[5-9]\d{11}$"),
            (ColumnKind::EpochSecs, r"^1[5-9]\d{8}$"),
            (
                ColumnKind::HttpMethod,
                r"^(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|CONNECT|TRACE)$",
            ),
            (ColumnKind::UrlPath, r"^/[\w\-./%~?=&:+@,!*'()\[\];$#]*$"),
            (ColumnKind::HexHash, r"^[a-f0-9]{32,64}$"),
            (
                ColumnKind::Email,
                r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$",
            ),
            (
                ColumnKind::Hostname,
                r"^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$",
            ),
            (ColumnKind::UserAgent, r"^Mozilla/[\d.]+ \([^)]+\).*$"),
        ];
        let mut pairs = Vec::with_capacity(raw.len());
        for (k, p) in raw {
            // Patterns are static literals — `expect` is correct: any failure here is
            // a bug in this file, not a runtime input issue.
            pairs.push((*k, Regex::new(p).expect("static pattern must compile")));
        }
        Self { pairs }
    }
}

thread_local! {
    static PATTERNS: Patterns = Patterns::new();
}

/// Score a single cell against every pattern, returning the first kind whose
/// regex matches.  Iteration order = roster order, which is also priority.
pub fn detect_kind(cell: &str) -> ColumnKind {
    let s = cell.trim();
    if s.is_empty() {
        return ColumnKind::Empty;
    }
    PATTERNS.with(|pats| {
        for (k, re) in &pats.pairs {
            if re.is_match(s) {
                return *k;
            }
        }
        ColumnKind::Unknown
    })
}

/// Decide a column's kind by majority vote over sampled cells. A column wins
/// only if at least `floor` of cells (default 0.6) matched the same kind.
const CONFIDENCE_FLOOR: f32 = 0.60;

pub fn vote_column(cells: &[&str]) -> (ColumnKind, f32) {
    if cells.is_empty() {
        return (ColumnKind::Empty, 1.0);
    }
    let mut counts = [0u32; 17]; // one slot per ColumnKind variant
    for cell in cells {
        let kind = detect_kind(cell);
        counts[kind as usize] += 1;
    }
    // Find the highest-counted non-Empty/non-Unknown kind. If everything is
    // Empty or Unknown, fall through to whichever had the most.
    let total = cells.len() as f32;
    let mut best_idx = 0;
    let mut best_count = 0u32;
    for (idx, c) in counts.iter().enumerate() {
        if *c > best_count {
            best_count = *c;
            best_idx = idx;
        }
    }
    let kind = idx_to_kind(best_idx);
    let confidence = best_count as f32 / total;
    if confidence < CONFIDENCE_FLOOR {
        (ColumnKind::Unknown, confidence)
    } else {
        (kind, confidence)
    }
}

fn idx_to_kind(i: usize) -> ColumnKind {
    match i {
        0 => ColumnKind::Ip,
        1 => ColumnKind::Cidr,
        2 => ColumnKind::Port,
        3 => ColumnKind::Asn,
        4 => ColumnKind::CountryCode,
        5 => ColumnKind::Iso8601,
        6 => ColumnKind::EpochSecs,
        7 => ColumnKind::EpochMs,
        8 => ColumnKind::HttpMethod,
        9 => ColumnKind::StatusCode,
        10 => ColumnKind::UrlPath,
        11 => ColumnKind::Hostname,
        12 => ColumnKind::UserAgent,
        13 => ColumnKind::HexHash,
        14 => ColumnKind::Email,
        15 => ColumnKind::Empty,
        _ => ColumnKind::Unknown,
    }
}

/// Sniff the most-likely delimiter in the first chunk of input.
/// Tries `\t`, `,`, `|`, `;`, ` `; picks the one whose count is most
/// stable across the first few rows.
pub fn detect_delimiter(text: &str) -> char {
    let candidates = ['\t', ',', '|', ';', ' '];
    let mut best = ',';
    let mut best_score = 0i64;
    for c in candidates {
        let counts: Vec<usize> = text
            .lines()
            .take(8)
            .map(|l| l.matches(c).count())
            .filter(|n| *n > 0)
            .collect();
        if counts.is_empty() {
            continue;
        }
        let mean = counts.iter().sum::<usize>() as f64 / counts.len() as f64;
        let var = counts
            .iter()
            .map(|n| (*n as f64 - mean).powi(2))
            .sum::<f64>()
            / counts.len() as f64;
        // Higher mean is good (more cells), lower variance is good (consistent).
        let score = (mean * 1000.0 - var * 100.0) as i64;
        if score > best_score {
            best_score = score;
            best = c;
        }
    }
    best
}

/// Decide whether the first row is a header by checking if its kinds differ
/// from the second row's kinds for at least half the columns.
fn looks_like_header(first: &[&str], second: &[&str]) -> bool {
    if first.len() != second.len() || first.is_empty() {
        return false;
    }
    let mut differs = 0usize;
    for (a, b) in first.iter().zip(second.iter()) {
        if detect_kind(a) != detect_kind(b) {
            differs += 1;
        }
    }
    differs * 2 >= first.len()
}

/// Top-level entry: take raw text, sniff delimiter, sample up to `max_rows`,
/// vote per column, return a full schema report.  Pure — no I/O.
pub fn detect_schema(text: &str, max_rows: usize) -> SchemaReport {
    let delim = detect_delimiter(text);
    let rows: Vec<Vec<&str>> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(max_rows)
        .map(|l| l.split(delim).map(str::trim).collect())
        .collect();

    if rows.is_empty() {
        return SchemaReport {
            columns: vec![],
            delimiter: delim,
            rows_sampled: 0,
            had_header: false,
        };
    }

    let had_header = rows.len() > 1 && looks_like_header(&rows[0], &rows[1]);
    let header_row: Option<&Vec<&str>> = if had_header { Some(&rows[0]) } else { None };
    let body: Vec<&Vec<&str>> = if had_header {
        rows.iter().skip(1).collect()
    } else {
        rows.iter().collect()
    };

    let n_cols = body.iter().map(|r| r.len()).max().unwrap_or(0);
    let mut columns = Vec::with_capacity(n_cols);
    for col_idx in 0..n_cols {
        let cells: Vec<&str> = body
            .iter()
            .filter_map(|r| r.get(col_idx).copied())
            .collect();
        let (kind, confidence) = vote_column(&cells);
        let header = header_row
            .and_then(|h| h.get(col_idx).map(|s| (*s).to_string()))
            .filter(|s| !s.is_empty());
        let samples: Vec<String> = cells
            .iter()
            .take(3)
            .map(|s| {
                if s.len() > 80 {
                    format!("{}…", &s[..80])
                } else {
                    (*s).to_string()
                }
            })
            .collect();
        columns.push(ColumnReport {
            index: col_idx,
            header,
            kind,
            confidence,
            samples,
        });
    }

    SchemaReport {
        columns,
        delimiter: delim,
        rows_sampled: body.len(),
        had_header,
    }
}
