// Unlicense — public domain — whobelooking.org
//! Log-line parser. Recognizes ten shapes:
//!   1. whobelooking-native   `… visit ip=… cc=… method=… path=… ua="…" ref="…"`
//!   2. nginx/apache combined `IP - - [date] "METHOD PATH …" status size "ref" "ua"`
//!   3. Cloudflare Logpush JSONL (one JSON object per line)
//!   4. Cloudflare Logpush CSV (first row contains CF field names)
//!   5. OTEL / OTLP JSON (line-delimited logRecord objects)
//!   6. Syslog (RFC 3164 / RFC 5424) wrapping an inner HTTP log line
//!   7. ELK / Logstash JSON (grok-parsed fields or `message` unwrap)
//!   8. Splunk export (JSON `_raw` or KV `_raw="..."`)
//!   9. W3C Extended Log Format / IIS (column layout declared by `#Fields:`)
//!  10. HAProxy HTTP mode log (default format with optional capture blocks)
//!
//! Output is `Vec<t100>` — uniform shape regardless of input format. The
//! per-IP aggregator downstream doesn't care which format produced an event.

use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// t100 = Event
pub struct t100 {
    pub ts: i64,
    pub ip: String,
    pub cc: String,
    pub method: String,
    pub path: String,
    pub ua: String,
    pub referrer: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// t101 = LogFormat
pub enum t101 {
    WblNative,
    Combined,
    CloudflareJsonl,
    CloudflareCsv,
    /// OpenTelemetry log records (OTLP/JSON, line-delimited). HTTP
    /// semantic-convention attributes get unwrapped into the `t100`
    /// Event shape; the newer `client.address` / `http.request.method`
    /// / `user_agent.original` conventions are tried first, with the
    /// older `net.peer.ip` / `http.method` / `http.user_agent` names
    /// as fallbacks.
    Otel,
    /// Syslog (RFC 3164 or RFC 5424) wrapping an inner HTTP log line.
    /// Common with rsyslog forwarders, Splunk Universal Forwarder, and
    /// most enterprise SIEM ingest paths. The wrapper carries priority +
    /// timestamp + hostname, then a free-form message; the message is
    /// usually a verbatim nginx/apache combined log line.
    Syslog,
    /// ELK / Logstash JSON. Either pre-parsed grok fields at the top level
    /// (`clientip`, `verb`, `request`, `agent`) or a `message` field with
    /// the raw nginx/apache line.
    Elk,
    /// Splunk export. JSON line with a `_raw` field containing the
    /// original log content, OR a KV-formatted line `_raw="..." key=val`.
    /// Either way the `_raw` is the actual HTTP log record; we unwrap
    /// it and re-route through the regular parsers.
    Splunk,
    /// W3C Extended Log Format (also covers IIS W3C logs). Column order is
    /// declared by a `#Fields:` directive; lines starting with `#` are
    /// directives or comments and are skipped.
    W3c,
    /// HAProxy HTTP mode log. Default format: `IP:PORT [date] frontend
    /// backend/server Tq/Tw/Tc/Tr/Tt status bytes ... "METHOD PATH HTTP/v"`.
    HaProxy,
    /// Raw text extraction fallback. No recognised log format was found;
    /// IPv4 addresses were scraped from the raw content via regex. Used for
    /// ACAS/Nessus output, email headers, config dumps, or any unstructured
    /// text that contains IP addresses.
    Raw,
    Mixed,
    Unknown,
}

impl t101 {
    pub fn name(self) -> &'static str {
        match self {
            t101::WblNative => "whobelooking-native",
            t101::Combined => "nginx/apache combined",
            t101::CloudflareJsonl => "cloudflare-jsonl",
            t101::CloudflareCsv => "cloudflare-csv",
            t101::Otel => "otel",
            t101::Syslog => "syslog",
            t101::Elk => "elk",
            t101::Splunk => "splunk",
            t101::W3c => "w3c-extended",
            t101::HaProxy => "haproxy",
            t101::Raw => "raw",
            t101::Mixed => "mixed",
            t101::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
/// t102 = ParseStats
pub struct t102 {
    pub parsed: usize,
    pub skipped: usize,
    pub format: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
/// t103 = ParseResult
pub struct t103 {
    pub events: Vec<t100>,
    pub stats: t102,
}

fn f410() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})")
            .expect("static wbl-ts pattern")
    })
}

fn f411() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"visit ip=(\S+) cc=(\S+) method=(\S+) path=(\S+) ua="([^"]*)" ref="([^"]*)""#)
            .expect("static wbl-line pattern")
    })
}

fn f412() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]+" (\d{3}) \S+ "([^"]*)" "([^"]*)""#,
        )
        .expect("static combined pattern")
    })
}

fn f413() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\x1b\[[0-9;]*m").expect("static ansi pattern"))
}

fn f414(m: &str) -> Option<u32> {
    Some(match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// Days-from-civil epoch — no chrono dep. Reference algorithm (Howard Hinnant).
/// Returns days since 1970-01-01 for the given Gregorian date.
fn f415(y: i32, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as i64;
    let doy = (153 * (m as i64 + (if m > 2 { -3 } else { 9 })) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146097 + doe - 719468
}

fn f416(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> i64 {
    f415(y, mo, d) * 86400 + (h as i64) * 3600 + (mi as i64) * 60 + (s as i64)
}

/// Minimal RFC4180-ish CSV row split. Handles quoted fields with embedded
/// commas and `""` escapes. Good enough for CF Logpush CSV exports.
///
/// Bytes are accumulated into a `Vec<u8>` and converted to `String` per
/// field — pushing each byte as `c as char` would silently treat UTF-8
/// continuation bytes as Latin-1 codepoints and corrupt every non-ASCII
/// field. The delimiters we split on (`,`, `"`) are ASCII, so each accumulated
/// buffer is guaranteed-valid UTF-8 and `from_utf8` cannot fail in practice;
/// `from_utf8_lossy` keeps that contract honest if the input ever isn't.
fn f417(line: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut in_q = false;
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_q {
            if c == b'"' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'"' {
                    buf.push(b'"');
                    i += 2;
                    continue;
                }
                in_q = false;
            } else {
                buf.push(c);
            }
        } else if c == b',' {
            out.push(String::from_utf8_lossy(&std::mem::take(&mut buf)).into_owned());
        } else if c == b'"' && buf.is_empty() {
            in_q = true;
        } else {
            buf.push(c);
        }
        i += 1;
    }
    out.push(String::from_utf8_lossy(&buf).into_owned());
    out
}

/// CF timestamps are RFC3339 strings, epoch seconds, ms, or nanoseconds.
fn f418(v: &str) -> i64 {
    let trimmed = v.trim();
    if trimmed.is_empty() {
        return 0;
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = trimmed.parse::<i64>() {
            if n > 1_000_000_000_000_000 {
                return n / 1_000_000_000;
            }
            if n > 1_000_000_000_000 {
                return n / 1_000;
            }
            return n;
        }
    }
    f419(trimmed).unwrap_or(0)
}

/// Loose RFC3339 / ISO 8601 parser. Accepts:
///   * `YYYY-MM-DDTHH:MM:SS`
///   * `YYYY-MM-DD HH:MM:SS` (space separator)
///   * Optional fractional seconds: `.\d+`
///   * Optional TZ suffix: `Z`, `±HH:MM`, or `±HHMM`
///
/// Anything else after position 18 returns `None`. The old version
/// silently accepted `"2026-01-15T18:42:11garbagezzz"` — bytes past 18
/// were scanned only for a `+`/`-`, so malformed timestamps produced
/// clean unix values instead of being skipped by the caller.
fn f419(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let y: i32 = s.get(0..4)?.parse().ok()?;
    if bytes.get(4)? != &b'-' {
        return None;
    }
    let mo: u32 = s.get(5..7)?.parse().ok()?;
    if bytes.get(7)? != &b'-' {
        return None;
    }
    let d: u32 = s.get(8..10)?.parse().ok()?;
    let sep = *bytes.get(10)?;
    if sep != b'T' && sep != b' ' {
        return None;
    }
    let h: u32 = s.get(11..13)?.parse().ok()?;
    if bytes.get(13)? != &b':' {
        return None;
    }
    let mi: u32 = s.get(14..16)?.parse().ok()?;
    if bytes.get(16)? != &b':' {
        return None;
    }
    let se: u32 = s.get(17..19)?.parse().ok()?;

    let mut unix = f416(y, mo, d, h, mi, se);
    let mut rest = &bytes[19..];

    // Optional fractional seconds — `.` followed by one or more digits.
    if let Some(b'.') = rest.first().copied() {
        let mut k = 1;
        while k < rest.len() && rest[k].is_ascii_digit() {
            k += 1;
        }
        if k == 1 {
            return None; // dot with no digits
        }
        rest = &rest[k..];
    }

    // Optional TZ suffix. The only acceptable shapes are: empty, `Z`,
    // `±HHMM`, or `±HH:MM`. Anything else is malformed.
    match rest.first().copied() {
        None => Some(unix),
        Some(b'Z') if rest.len() == 1 => Some(unix),
        Some(c) if c == b'+' || c == b'-' => {
            let sign: i64 = if c == b'+' { -1 } else { 1 };
            let tail = &rest[1..];
            let (hh, mm) = if tail.len() == 5 && tail[2] == b':' {
                let hh: i64 = std::str::from_utf8(&tail[0..2]).ok()?.parse().ok()?;
                let mm: i64 = std::str::from_utf8(&tail[3..5]).ok()?.parse().ok()?;
                (hh, mm)
            } else if tail.len() == 4 && tail.iter().all(|b| b.is_ascii_digit()) {
                let hh: i64 = std::str::from_utf8(&tail[0..2]).ok()?.parse().ok()?;
                let mm: i64 = std::str::from_utf8(&tail[2..4]).ok()?.parse().ok()?;
                (hh, mm)
            } else {
                return None;
            };
            if !(0..=14).contains(&hh) || !(0..=59).contains(&mm) {
                return None;
            }
            unix += sign * (hh * 3600 + mm * 60);
            Some(unix)
        }
        _ => None,
    }
}

fn f420(d: &str) -> i64 {
    // "15/Jan/2026:18:42:11 +0000"
    let bytes = d.as_bytes();
    if bytes.len() < 20 {
        return 0;
    }
    let day: u32 = match d.get(0..2).and_then(|x| x.parse().ok()) {
        Some(v) => v,
        None => return 0,
    };
    let mon = match d.get(3..6).and_then(f414) {
        Some(v) => v,
        None => return 0,
    };
    let year: i32 = match d.get(7..11).and_then(|x| x.parse().ok()) {
        Some(v) => v,
        None => return 0,
    };
    let hour: u32 = match d.get(12..14).and_then(|x| x.parse().ok()) {
        Some(v) => v,
        None => return 0,
    };
    let min: u32 = match d.get(15..17).and_then(|x| x.parse().ok()) {
        Some(v) => v,
        None => return 0,
    };
    let sec: u32 = match d.get(18..20).and_then(|x| x.parse().ok()) {
        Some(v) => v,
        None => return 0,
    };
    f416(year, mon, day, hour, min, sec)
}

/// CF Logpush field aliases. JSON, CSV, and the older "raw" exports all
/// give these fields slightly different names — match by membership.
const CF_FIELDS: &[(&str, &[&str])] = &[
    ("ip", &["ClientIP", "client_ip", "clientIP"]),
    (
        "path",
        &[
            "ClientRequestPath",
            "client_request_path",
            "clientRequestPath",
        ],
    ),
    (
        "method",
        &[
            "ClientRequestMethod",
            "client_request_method",
            "clientRequestMethod",
        ],
    ),
    (
        "ua",
        &[
            "ClientRequestUserAgent",
            "client_request_user_agent",
            "clientRequestUserAgent",
            "userAgent",
        ],
    ),
    (
        "cc",
        &[
            "ClientCountry",
            "client_country",
            "clientCountryName",
            "ClientCountryName",
        ],
    ),
    (
        "ref",
        &[
            "ClientRequestReferer",
            "client_request_referer",
            "clientRequestReferer",
        ],
    ),
    (
        "ts",
        &[
            "EdgeStartTimestamp",
            "edge_start_timestamp",
            "edgeStartTimestamp",
            "datetime",
        ],
    ),
];

fn f421<'a>(
    map: &'a std::collections::BTreeMap<String, String>,
    names: &[&str],
) -> Option<&'a str> {
    for n in names {
        if let Some(v) = map.get(*n) {
            if !v.is_empty() {
                return Some(v.as_str());
            }
        }
    }
    None
}

fn f422(obj: &std::collections::BTreeMap<String, String>) -> Option<t100> {
    let ip = f421(obj, CF_FIELDS[0].1)
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())?;
    let path = f421(obj, CF_FIELDS[1].1)
        .map(|s| s.to_string())
        .unwrap_or_else(|| "/".into());
    let method = f421(obj, CF_FIELDS[2].1)
        .map(|s| s.to_string())
        .unwrap_or_else(|| "GET".into());
    let ua = f421(obj, CF_FIELDS[3].1).unwrap_or("").to_string();
    let cc = f421(obj, CF_FIELDS[4].1).unwrap_or("").to_string();
    let referrer = f421(obj, CF_FIELDS[5].1).unwrap_or("").to_string();
    let ts = f421(obj, CF_FIELDS[6].1).map(f418).unwrap_or(0);
    Some(t100 {
        ts,
        ip,
        cc,
        method,
        path,
        ua: truncate(ua, 256),
        referrer: truncate(referrer, 256),
    })
}

fn truncate(mut s: String, max: usize) -> String {
    if s.len() > max {
        s.truncate(max);
    }
    s
}

struct W3cIdx {
    date: Option<usize>,
    time: Option<usize>,
    ip: Option<usize>,
    method: Option<usize>,
    path: Option<usize>,
    query: Option<usize>,
    ua: Option<usize>,
    referer: Option<usize>,
}

/// f425 = parse_otel_line.
///
/// Decode a single OTLP/JSON logRecord into a `t100` Event. Used for OTEL
/// log exports — line-delimited records emitted by an OTLP collector,
/// SDK, or sidecar. We grab the standard HTTP semantic-convention
/// attributes; the line is skipped if no IP can be resolved (an OTEL log
/// without a client address isn't an HTTP server log).
///
/// We support both OTEL HTTP semantic-convention vintages:
///   * **Stable (≥1.21):** `client.address`, `url.path`, `http.request.method`,
///     `user_agent.original`
///   * **Experimental / pre-1.21:** `net.peer.ip` / `http.client_ip`,
///     `http.target` / `http.url`, `http.method`, `http.user_agent`
///
/// The walker is regex-free — it scans the line for `"key":"..."` /
/// `"value":{"...Value":"..."}` pairs without building a JSON AST. That
/// keeps the WASM build lean (we'd otherwise need a deeper JSON walker).
fn f425(line: &str) -> Option<t100> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }
    // Quick shape detection: at least one OTEL-ish marker has to be
    // present, otherwise this is some other JSON dialect.
    let is_otel = trimmed.contains(r#""timeUnixNano""#)
        || trimmed.contains(r#""severityNumber""#)
        || trimmed.contains(r#""severityText""#)
        || (trimmed.contains(r#""attributes":["#) && trimmed.contains(r#""value":{"#));
    if !is_otel {
        return None;
    }

    // Newer convention first, older as fallback.
    let ip = f426(
        trimmed,
        &["client.address", "net.peer.ip", "http.client_ip"],
    )?;
    if ip.is_empty() {
        return None;
    }
    let path =
        f426(trimmed, &["url.path", "http.target", "http.url"]).unwrap_or_else(|| "/".into());
    let method =
        f426(trimmed, &["http.request.method", "http.method"]).unwrap_or_else(|| "GET".into());
    let ua = f426(trimmed, &["user_agent.original", "http.user_agent"]).unwrap_or_default();
    let cc = f426(
        trimmed,
        &[
            "client.country",
            "geo.country.code",
            "geo.country_iso_code",
            "http.client_country",
        ],
    )
    .unwrap_or_default();
    let referrer = f426(trimmed, &["http.referer", "http.referrer"]).unwrap_or_default();
    let ts = f427(trimmed);

    Some(t100 {
        ts,
        ip,
        cc,
        method,
        path,
        ua: truncate(ua, 256),
        referrer: truncate(referrer, 256),
    })
}

/// f426 = otel_attr.
///
/// Pull the string value of the first matching attribute key from an OTLP
/// JSON line. Tries each key in `keys` in order; returns the first hit.
/// Handles `stringValue` (most common), `intValue` (OTLP encodes int64
/// as a quoted string for JS-precision reasons), `doubleValue`, and
/// `boolValue`.
fn f426(line: &str, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(v) = f426_one(line, k) {
            return Some(v);
        }
    }
    None
}

fn f426_one(line: &str, key: &str) -> Option<String> {
    // Locate `"key":"<key>"` — both with and without whitespace tolerated
    // via a simple substring match. OTLP exporters never inject whitespace
    // between the colon and the string, so a strict match is fine in
    // practice.
    let needle = format!("\"key\":\"{}\"", key);
    let pos = line.find(&needle)?;
    let after = &line[pos + needle.len()..];
    // The value object follows the key, typically as `,"value":{...}`.
    let val_pos = after.find("\"value\":{")?;
    let after_val = &after[val_pos + "\"value\":{".len()..];
    // Within the value object, look for the typed sub-field. Order
    // reflects frequency in real CF / OTEL exports.
    for shape in [
        "\"stringValue\":\"",
        "\"intValue\":\"",
        "\"boolValue\":",
        "\"doubleValue\":",
    ] {
        if let Some(p) = after_val.find(shape) {
            let v_start = p + shape.len();
            let rest = &after_val[v_start..];
            // String/int are quoted; bool/double are not.
            let quoted = shape.ends_with('"');
            let end_idx = if quoted {
                // First unescaped `"`. JSON escapes within OTEL values
                // are vanishingly rare; if they appear, the truncation
                // here is conservative (drop at the first `"`).
                rest.find('"')?
            } else {
                rest.find([',', '}', ' ']).unwrap_or(rest.len())
            };
            return Some(rest[..end_idx].to_string());
        }
    }
    None
}

/// f427 = otel_timestamp.
///
/// Extract `timeUnixNano` and normalize to unix seconds. OTLP encodes the
/// timestamp as either a quoted string (the spec-compliant shape, dodging
/// JS Number precision) or a bare integer. The same heuristic as the
/// JSONL parser disambiguates ns / ms / s by magnitude.
fn f427(line: &str) -> i64 {
    let marker = "\"timeUnixNano\":";
    let pos = match line.find(marker) {
        Some(p) => p,
        None => return 0,
    };
    let after = line[pos + marker.len()..].trim_start();
    let s = if let Some(stripped) = after.strip_prefix('"') {
        let end = stripped.find('"').unwrap_or(0);
        &stripped[..end]
    } else {
        let end = after.find([',', '}']).unwrap_or(after.len());
        after[..end].trim()
    };
    if let Ok(n) = s.parse::<i64>() {
        if n > 1_000_000_000_000_000 {
            return n / 1_000_000_000;
        }
        if n > 1_000_000_000_000 {
            return n / 1_000;
        }
        return n;
    }
    0
}

/// f429 = parse_elk_line.
///
/// Recognize ELK / Logstash / Splunk-JSON-formatted lines and either
/// build the Event directly (when grok-parsed fields are present at the
/// top level) or fall back to unwrapping `message` / `_raw` and re-running
/// the inner content through the text-line parser.
///
/// Markers checked: `@timestamp` (Logstash convention), `clientip` /
/// `client_ip` (default grok `COMBINEDAPACHELOG` field name), `_raw`
/// (Splunk JSON export). Lines that don't carry at least one are
/// rejected so we don't grab arbitrary CF JSONL by accident.
fn f429(line: &str) -> Option<(t100, t101)> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }
    let has_at_ts = trimmed.contains(r#""@timestamp""#);
    let has_grok = trimmed.contains(r#""clientip""#) || trimmed.contains(r#""client_ip""#);
    let has_raw = trimmed.contains(r#""_raw""#);
    if !has_at_ts && !has_grok && !has_raw {
        return None;
    }

    let map = crate::json_lite::f300(trimmed)?;

    // Detection tag for the format-tracker. `_raw` always means Splunk;
    // top-level `@timestamp` / `clientip` means Logstash/ELK.
    let detected = if has_raw { t101::Splunk } else { t101::Elk };

    // Path 1 — direct grok fields. Logstash's default nginx pipeline emits
    // `clientip`, `verb`, `request`, `agent`, `response` (status code) as
    // top-level keys. When those are present we have everything we need
    // without unwrapping the raw line.
    let ip_direct = map
        .get("clientip")
        .or_else(|| map.get("client_ip"))
        .filter(|s| !s.is_empty());
    if let Some(ip) = ip_direct {
        let path = map
            .get("request")
            .or_else(|| map.get("url"))
            .or_else(|| map.get("path"))
            .cloned()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "/".into());
        let method = map
            .get("verb")
            .or_else(|| map.get("method"))
            .cloned()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "GET".into());
        let ua = map
            .get("agent")
            .or_else(|| map.get("useragent"))
            .or_else(|| map.get("user_agent"))
            .or_else(|| map.get("http_user_agent"))
            .cloned()
            .unwrap_or_default();
        let cc = map.get("geoip_country_code").cloned().unwrap_or_default();
        let ts = map.get("@timestamp").map(|s| f418(s)).unwrap_or(0);
        let referrer = map
            .get("referrer")
            .or_else(|| map.get("referer"))
            .cloned()
            .unwrap_or_default();
        return Some((
            t100 {
                ts,
                ip: ip.clone(),
                cc,
                method,
                path,
                ua: truncate(ua, 256),
                referrer: truncate(referrer, 256),
            },
            detected,
        ));
    }

    // Path 2 — fall back to `message` / `_raw` and re-parse the inner
    // content. Most rsyslog-fed Logstash pipelines don't grok-parse; the
    // `message` field carries the literal nginx line.
    let inner = map
        .get("message")
        .or_else(|| map.get("_raw"))
        .filter(|s| !s.is_empty())?
        .clone();
    let event = f424(&inner)?;
    Some((event, detected))
}

/// f431 = unwrap_splunk_kv.
///
/// Splunk SPL CLI / `splunk export` non-JSON output: key=value pairs with
/// `_raw="<original line>"`. The inner content is the original HTTP log
/// record; we extract and return it for re-parse. Handles `\"` escapes
/// the way Splunk emits them.
///
/// Returns `None` if the line isn't Splunk-shaped (no `_raw="` substring
/// or no closing quote). The format-tracker sees a Splunk parse only
/// when the inner re-parse succeeds against one of the regular parsers.
fn f431(line: &str) -> Option<String> {
    let needle = "_raw=\"";
    let pos = line.find(needle)?;
    let after = &line[pos + needle.len()..];
    // Walk to the matching closing `"`, honoring `\"` escapes. Splunk
    // uses backslash-quote escaping (not CSV's `""` style).
    //
    // Accumulate into `Vec<u8>` then `from_utf8_lossy` once at the end —
    // pushing each byte as `c as char` would silently treat UTF-8
    // continuation bytes as Latin-1 (same trap that bit the CSV
    // splitter in #1 of the master review).
    let bytes = after.as_bytes();
    let mut buf: Vec<u8> = Vec::with_capacity(after.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && i + 1 < bytes.len() {
            buf.push(bytes[i + 1]);
            i += 2;
            continue;
        }
        if c == b'"' {
            return Some(String::from_utf8_lossy(&buf).into_owned());
        }
        buf.push(c);
        i += 1;
    }
    // Unterminated `_raw="...` — bad shape, drop the line.
    None
}

fn haproxy_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d+ \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})")
            .expect("haproxy pattern")
    })
}

/// f432 = parse_haproxy_line
///
/// HAProxy HTTP mode log. Default format (no capture headers):
///   `IP:PORT [DD/Mon/YYYY:HH:MM:SS.mmm] frontend backend/server
///    Tq/Tw/Tc/Tr/Tt status bytes - - flags ... "METHOD PATH HTTP/version"`
///
/// With `capture request header` configured, optional `{val}` blocks appear
/// before the request line; a single-value `{...}` block immediately before
/// the request line is extracted as UA if it contains no `|`.
///
/// IPv6 client addresses (`[::1]:port`) are not handled — HAProxy wraps them
/// in brackets which collides with the timestamp `[...]` pattern.
fn f432(line: &str) -> Option<t100> {
    let m = haproxy_re().captures(line)?;
    let ip = m.get(1)?.as_str().to_string();
    let ts = f420(m.get(2)?.as_str());

    // Request line is the LAST `"..."` in the log entry.
    let end = line.rfind('"')?;
    let start = line[..end].rfind('"')?;
    let req = &line[start + 1..end];
    if req.is_empty() {
        return None;
    }
    let mut parts = req.splitn(3, ' ');
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    // Sanity: HTTP verb must not contain `/`; path must start with `/` or be `*`.
    if method.contains('/') || (!path.starts_with('/') && path != "*") {
        return None;
    }

    // Best-effort UA: scan `{value}` capture blocks immediately before `"...`,
    // walking backwards through consecutive blocks to find the first non-empty
    // single-value (no `|`) block. HAProxy capture lists emit multiple `{}`
    // blocks in declaration order; the UA block may not be the last one.
    let before = line[..start].trim_end();
    let ua = {
        let mut scan = before;
        let mut found = String::new();
        while scan.ends_with('}') {
            let cb_end = scan.len() - 1;
            if let Some(cb_start) = scan[..cb_end].rfind('{') {
                let inner = scan[cb_start + 1..cb_end].trim();
                if !inner.is_empty() && inner != "-" && !inner.contains('|') {
                    found = inner.to_string();
                    break;
                }
                // Empty or multi-value block — keep scanning backwards.
                scan = scan[..cb_start].trim_end();
            } else {
                break;
            }
        }
        found
    };

    Some(t100 {
        ts,
        ip,
        cc: String::new(),
        method,
        path,
        ua: truncate(ua, 256),
        referrer: String::new(),
    })
}

/// f433 = parse_w3c_fields_header
///
/// Parse a W3C Extended Log Format `#Fields:` directive and return column
/// index positions for the fields we extract. Matching is case-insensitive.
/// IIS uses parenthesised HTTP header names (`cs(User-Agent)`, `cs(Referer)`).
fn f433(fields_line: &str) -> W3cIdx {
    let s = fields_line.trim().trim_start_matches('#').trim();
    let body = if s.len() >= 7 && s[..7].eq_ignore_ascii_case("fields:") {
        &s[7..]
    } else {
        s
    };
    let mut idx = W3cIdx {
        date: None,
        time: None,
        ip: None,
        method: None,
        path: None,
        query: None,
        ua: None,
        referer: None,
    };
    for (i, field) in body.split_whitespace().enumerate() {
        match field.to_ascii_lowercase().as_str() {
            "date" => idx.date = Some(i),
            "time" => idx.time = Some(i),
            "c-ip" => idx.ip = Some(i),
            "cs-method" => idx.method = Some(i),
            "cs-uri-stem" => idx.path = Some(i),
            "cs-uri-query" => idx.query = Some(i),
            "cs(user-agent)" => idx.ua = Some(i),
            "cs(referer)" => idx.referer = Some(i),
            _ => {}
        }
    }
    idx
}

/// f434 = parse_w3c_line
///
/// Parse one W3C Extended Log Format data line using the column map from
/// `f433`. Fields with value `-` are absent. W3C encodes spaces in header
/// values (User-Agent, Referer) as `+`. Lines starting with `#` are
/// directives and must not be passed here (caller filters them).
fn f434(line: &str, idx: &W3cIdx) -> Option<t100> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    let ip = idx
        .ip
        .and_then(|i| cols.get(i))
        .filter(|s| **s != "-" && !s.is_empty())
        .map(|s| s.to_string())?;

    let ts = match (idx.date, idx.time) {
        (Some(di), Some(ti)) => {
            let d = cols.get(di).copied().filter(|s| *s != "-").unwrap_or("");
            let t = cols
                .get(ti)
                .copied()
                .filter(|s| *s != "-")
                .unwrap_or("00:00:00");
            if d.is_empty() {
                0
            } else {
                f419(&format!("{}T{}", d, t)).unwrap_or(0)
            }
        }
        (Some(di), None) => {
            let d = cols.get(di).copied().filter(|s| *s != "-").unwrap_or("");
            if d.is_empty() {
                0
            } else {
                f419(&format!("{}T00:00:00", d)).unwrap_or(0)
            }
        }
        _ => 0,
    };

    let method = idx
        .method
        .and_then(|i| cols.get(i))
        .filter(|s| **s != "-")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "GET".into());

    let mut path = idx
        .path
        .and_then(|i| cols.get(i))
        .filter(|s| **s != "-")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "/".into());

    if let Some(qi) = idx.query {
        if let Some(q) = cols.get(qi).filter(|s| **s != "-" && !s.is_empty()) {
            path.push('?');
            path.push_str(q);
        }
    }

    let ua = idx
        .ua
        .and_then(|i| cols.get(i))
        .filter(|s| **s != "-")
        .map(|s| s.replace('+', " "))
        .unwrap_or_default();

    let referrer = idx
        .referer
        .and_then(|i| cols.get(i))
        .filter(|s| **s != "-")
        .map(|s| s.replace('+', " "))
        .unwrap_or_default();

    Some(t100 {
        ts,
        ip,
        cc: String::new(),
        method,
        path,
        ua: truncate(ua, 256),
        referrer: truncate(referrer, 256),
    })
}

fn ipv4_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?:^|[^0-9])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[^0-9]|$)")
            .expect("ipv4 pattern")
    })
}

/// f435 = extract_raw_ips
///
/// Last-resort fallback for unstructured input (ACAS/Nessus output, email
/// headers, config dumps, paste-bin text, etc.). Regex-scans the entire
/// text for IPv4 addresses, validates each octet is 0–255, deduplicates,
/// and returns one synthetic `t100` per unique IP. Each appearance of the
/// same IP in the text increments its hit count via repeated synthetic
/// events — callers aggregate with `f401` as normal.
///
/// No timestamp, method, path, or UA is synthesised — those fields are
/// left empty so enrichment (rDNS/RDAP) carries the full weight of
/// identification.
fn f435(text: &str) -> Vec<t100> {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for cap in ipv4_re().captures_iter(text) {
        let ip = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if ip.is_empty() {
            continue;
        }
        // Validate all four octets are ≤ 255.
        let valid = ip
            .split('.')
            .filter_map(|o| o.parse::<u16>().ok())
            .filter(|&o| o <= 255)
            .count()
            == 4;
        if valid {
            *counts.entry(ip.to_string()).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .flat_map(|(ip, n)| {
            (0..n).map(move |_| t100 {
                ts: 0,
                ip: ip.clone(),
                cc: String::new(),
                method: String::new(),
                path: String::new(),
                ua: String::new(),
                referrer: String::new(),
            })
        })
        .collect()
}

/// f428 = unwrap_syslog.
///
/// If `line` starts with a syslog priority header (`<NNN>` where NNN is
/// 1-3 ASCII digits), unwrap it and return the inner message. Caller then
/// re-runs the inner content through the regular parsers (wbl-native,
/// nginx, JSONL, OTEL). Returns `None` if no syslog header is present.
///
/// Handles both vintages:
///   * **RFC 3164 (BSD):** `<134>May 16 18:42:11 host app: inner...`
///   * **RFC 5424:** `<134>1 2026-05-16T18:42:11Z host app proc msgid - inner...`
///
/// The strategy is conservative: skip the prefix bytes up to and including
/// the LAST distinguishing delimiter (RFC 3164 uses `: ` after the tag;
/// RFC 5424 uses ` - ` or `] ` after structured-data). If the heuristic
/// can't find a clean cut, return the whole line minus just the priority —
/// the inner parsers will try their luck.
fn f428(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    if bytes.first() != Some(&b'<') {
        return None;
    }
    // Skip past `<NNN>`. Must be at most 4 chars (3 digits + closing `>`).
    let close = bytes.iter().take(5).position(|b| *b == b'>')?;
    if close < 2 {
        return None;
    }
    // Validate digits between `<` and `>`.
    if !bytes[1..close].iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let rest = &line[close + 1..];
    let rest_bytes = rest.as_bytes();

    // RFC 5424 — `VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD SP MSG`.
    // We walk the structured fields by token-count (5 spaces after version)
    // rather than searching for ` - ` or `] `, which both occur naturally
    // inside the structured fields and the wrapped HTTP message and would
    // give the wrong cut.
    if rest_bytes
        .first()
        .map(|b| b.is_ascii_digit())
        .unwrap_or(false)
        && rest_bytes.get(1) == Some(&b' ')
    {
        let mut idx = 2; // past "<version> "
        // Skip TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID — five
        // whitespace-separated tokens. Each loop iteration consumes one
        // token plus the trailing space.
        for _ in 0..5 {
            while idx < rest_bytes.len() && rest_bytes[idx] != b' ' {
                idx += 1;
            }
            if idx < rest_bytes.len() {
                idx += 1;
            }
        }
        if idx >= rest_bytes.len() {
            return Some("");
        }
        // STRUCTURED-DATA is `-` (nil) or one-or-more `[...]` blocks
        // concatenated with no inter-block whitespace.
        if rest_bytes[idx] == b'-' && (idx + 1 >= rest_bytes.len() || rest_bytes[idx + 1] == b' ') {
            idx += 1;
            if idx < rest_bytes.len() && rest_bytes[idx] == b' ' {
                idx += 1;
            }
        } else if rest_bytes[idx] == b'[' {
            // Walk past consecutive `[...]` blocks. We don't track quoted
            // strings inside the block — the spec says SD-PARAM values
            // CAN contain `]` if escaped, but in practice they don't
            // appear in real-world syslog forwarder output.
            while idx < rest_bytes.len() && rest_bytes[idx] == b'[' {
                while idx < rest_bytes.len() && rest_bytes[idx] != b']' {
                    idx += 1;
                }
                if idx < rest_bytes.len() {
                    idx += 1; // step past `]`
                }
            }
            if idx < rest_bytes.len() && rest_bytes[idx] == b' ' {
                idx += 1;
            }
        }
        return Some(rest[idx..].trim_start());
    }

    // RFC 3164: `<NNN>Mmm dd HH:MM:SS host tag: message`. The clearest
    // delimiter is the first `: ` after the priority header — that
    // follows the program tag and precedes the actual message.
    if let Some(idx) = rest.find(": ") {
        return Some(rest[idx + 2..].trim_start());
    }
    // No `: ` — return everything after the priority. Inner parsers
    // will probably skip, but we did our part.
    Some(rest.trim_start())
}

/// Try `line` against the wbl-native and combined formats. Returns the
/// event if either matches, else `None`. Cheap — caller has already stripped
/// ANSI noise.
fn f424(line: &str) -> Option<t100> {
    if let (Some(ts), Some(m)) = (f410().captures(line), f411().captures(line)) {
        let y: i32 = ts.get(1)?.as_str().parse().ok()?;
        let mo: u32 = ts.get(2)?.as_str().parse().ok()?;
        let d: u32 = ts.get(3)?.as_str().parse().ok()?;
        let h: u32 = ts.get(4)?.as_str().parse().ok()?;
        let mi: u32 = ts.get(5)?.as_str().parse().ok()?;
        let se: u32 = ts.get(6)?.as_str().parse().ok()?;
        return Some(t100 {
            ts: f416(y, mo, d, h, mi, se),
            ip: m.get(1)?.as_str().to_string(),
            cc: m.get(2)?.as_str().to_string(),
            method: m.get(3)?.as_str().to_string(),
            path: m.get(4)?.as_str().to_string(),
            ua: truncate(m.get(5)?.as_str().to_string(), 256),
            referrer: truncate(m.get(6)?.as_str().to_string(), 256),
        });
    }
    if let Some(m) = f412().captures(line) {
        return Some(t100 {
            ts: f420(m.get(2)?.as_str()),
            ip: m.get(1)?.as_str().to_string(),
            cc: String::new(),
            method: m.get(3)?.as_str().to_string(),
            path: m.get(4)?.as_str().to_string(),
            ua: truncate(m.get(7)?.as_str().to_string(), 256),
            referrer: truncate(m.get(6)?.as_str().to_string(), 256),
        });
    }
    None
}

/// Top-level: take a whole log file as `&str`, return parsed events and
/// per-format counts. Detects the format from the first non-blank line
/// (CSV header sniff for Cloudflare CSV; `{` prefix for JSONL; else
/// text-line shapes). Mixed-format files fall back to per-line parsing.
/// f400 = parse_log
pub fn f400(text: &str) -> t103 {
    let mut events: Vec<t100> = Vec::new();
    let mut parsed = 0usize;
    let mut skipped = 0usize;
    let mut json_malformed = 0usize;
    let mut format = t101::Unknown;

    // First non-empty line drives format detection.
    let lines = text.lines();
    let mut first_real: Option<&str> = None;
    let mut leading_blanks = 0usize;
    for l in lines {
        if l.trim().is_empty() {
            leading_blanks += 1;
            continue;
        }
        first_real = Some(l);
        break;
    }

    let mut csv_idx: Option<Vec<(usize, &'static str)>> = None;
    if let Some(first) = first_real {
        let plain = f413().replace_all(first, "");
        if plain.contains(',') {
            let headers = f417(&plain);
            let mut idx: Vec<(usize, &'static str)> = Vec::new();
            for (key, syns) in CF_FIELDS {
                for (i, h) in headers.iter().enumerate() {
                    if syns.iter().any(|s| s.eq_ignore_ascii_case(h)) {
                        idx.push((i, *key));
                        break;
                    }
                }
            }
            if idx.iter().any(|(_, k)| *k == "ip") {
                csv_idx = Some(idx);
                format = t101::CloudflareCsv;
            }
        }
    }

    // Scan the file for a W3C Extended Log Format #Fields: directive.
    // Scan all lines (not just initial ones) because directives can follow
    // log-rotation header blocks mid-file.
    let mut w3c_idx: Option<W3cIdx> = None;
    for l in text.lines() {
        let t = l.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with('#') {
            let inner = t.trim_start_matches('#').trim();
            if inner.len() >= 7 && inner[..7].eq_ignore_ascii_case("fields:") {
                w3c_idx = Some(f433(t));
                break;
            }
            continue;
        }
        break;
    }

    // Rebuild iterator from the top — simpler than threading state and the
    // file is already in memory at this point.
    let _ = leading_blanks;
    let all_lines = text.lines().peekable();
    let mut is_first_real = true;

    // Closure: update the running `format` label when a new shape is seen.
    // First successful parse → that shape. Disagreeing shape → Mixed.
    let bump_format = |seen: t101, current: &mut t101| {
        if *current == t101::Unknown {
            *current = seen;
        } else if *current != seen {
            *current = t101::Mixed;
        }
    };

    for raw in all_lines {
        if raw.trim().is_empty() {
            continue;
        }
        let line = f413().replace_all(raw, "").to_string();

        // Skip the CSV header row exactly once. After this, every line
        // tries every parser in order until one accepts it — that's what
        // makes Mixed-format files actually parse instead of silently
        // dropping anything that doesn't fit the first line's shape.
        if csv_idx.is_some() && is_first_real {
            is_first_real = false;
            continue;
        }
        is_first_real = false;

        // W3C directive / comment lines — skip without counting as malformed.
        // Mid-file #Fields: updates (log rotation) refresh the column map.
        if line.trim_start().starts_with('#') {
            let inner = line.trim_start().trim_start_matches('#').trim_start();
            if inner.len() >= 7 && inner[..7].eq_ignore_ascii_case("fields:") {
                w3c_idx = Some(f433(&line));
            }
            continue;
        }

        // Outer unwrappers — syslog priority header and Splunk `_raw="..."`
        // key-value wrapping. Either strips its envelope and routes the
        // inner content through the rest of the parsers. Format tracking
        // remembers we saw a wrapped line, so the final `format` label
        // reflects the wrapper, not the unwrapped inner content.
        let (effective_line, was_syslog) = match f428(&line) {
            Some(inner) => (inner.to_string(), true),
            None => (line.clone(), false),
        };
        let (effective_line, was_splunk_kv) = if was_syslog {
            (effective_line, false)
        } else {
            match f431(&effective_line) {
                Some(inner) => (inner, true),
                None => (effective_line, false),
            }
        };
        let line = effective_line;

        // Attempt 1: CSV (only when we sniffed a header). A line is
        // accepted as CSV only when it has at least as many columns as
        // the header — otherwise we'd take a comma-free line (eg. an
        // nginx combined-format row) and stuff the entire string into
        // the `ClientIP` slot. The `max_idx` is the highest index the
        // header mapped, so the row must reach it to count.
        if let Some(idx_map) = &csv_idx {
            let max_idx = idx_map.iter().map(|(i, _)| *i).max().unwrap_or(0);
            let cols = f417(&line);
            if cols.len() > max_idx {
                let mut obj: std::collections::BTreeMap<String, String> =
                    std::collections::BTreeMap::new();
                for (i, key) in idx_map {
                    if let Some(v) = cols.get(*i) {
                        let canon = CF_FIELDS
                            .iter()
                            .find(|(k, _)| k == key)
                            .map(|(_, syns)| syns[0])
                            .unwrap_or(key);
                        obj.insert(canon.to_string(), v.clone());
                    }
                }
                // Additional gate: the resolved IP must not contain spaces
                // or brackets. f422 doesn't validate shape, so without
                // this an nginx line with the same column count as the
                // header would still slip through.
                let ip_ok = obj
                    .get(CF_FIELDS[0].1[0])
                    .map(|s| !s.contains(' ') && !s.contains('[') && !s.is_empty())
                    .unwrap_or(false);
                if ip_ok {
                    if let Some(e) = f422(&obj) {
                        events.push(e);
                        parsed += 1;
                        let seen = if was_syslog {
                            t101::Syslog
                        } else {
                            t101::CloudflareCsv
                        };
                        bump_format(seen, &mut format);
                        continue;
                    }
                }
            }
            // Fall through to other parsers — a non-CSV line in a CSV
            // file is mixed-format, not malformed.
        }

        // Attempt 2: JSON-shaped. Three sub-parsers in order:
        //   1. OTEL  — own shape markers (`timeUnixNano`, attributes)
        //   2. ELK / Logstash / Splunk-JSON — `@timestamp`, `clientip`,
        //      `_raw` markers; either grok-parsed fields or `message`
        //      unwrap routed through the text parser
        //   3. CF JSONL — flat object with `ClientIP` etc.
        let trimmed = line.trim_start();
        if trimmed.starts_with('{') {
            if let Some(e) = f425(trimmed) {
                events.push(e);
                parsed += 1;
                let seen = if was_syslog || was_splunk_kv {
                    if was_splunk_kv {
                        t101::Splunk
                    } else {
                        t101::Syslog
                    }
                } else {
                    t101::Otel
                };
                bump_format(seen, &mut format);
                continue;
            }
            if let Some((e, detected_inner)) = f429(trimmed) {
                events.push(e);
                parsed += 1;
                let seen = if was_syslog {
                    t101::Syslog
                } else if was_splunk_kv {
                    t101::Splunk
                } else {
                    detected_inner
                };
                bump_format(seen, &mut format);
                continue;
            }
            if let Some(map) = crate::json_lite::f300(trimmed) {
                if let Some(e) = f422(&map) {
                    events.push(e);
                    parsed += 1;
                    let seen = if was_syslog {
                        t101::Syslog
                    } else if was_splunk_kv {
                        t101::Splunk
                    } else {
                        t101::CloudflareJsonl
                    };
                    bump_format(seen, &mut format);
                    continue;
                }
            }
            // JSON-shaped but unparseable → genuine skip, no text fallback.
            json_malformed += 1;
            skipped += 1;
            continue;
        }

        // Attempt 3: wbl-native or nginx/apache combined.
        if let Some(e) = f424(&line) {
            let detected = if was_syslog {
                t101::Syslog
            } else if was_splunk_kv {
                t101::Splunk
            } else if f411().is_match(&line) {
                t101::WblNative
            } else {
                t101::Combined
            };
            bump_format(detected, &mut format);
            events.push(e);
            parsed += 1;
        } else if let Some(e) = w3c_idx.as_ref().and_then(|idx| f434(&line, idx)) {
            let seen = if was_syslog {
                t101::Syslog
            } else if was_splunk_kv {
                t101::Splunk
            } else {
                t101::W3c
            };
            bump_format(seen, &mut format);
            events.push(e);
            parsed += 1;
        } else if let Some(e) = f432(&line) {
            let seen = if was_syslog {
                t101::Syslog
            } else if was_splunk_kv {
                t101::Splunk
            } else {
                t101::HaProxy
            };
            bump_format(seen, &mut format);
            events.push(e);
            parsed += 1;
        } else {
            skipped += 1;
        }
    }

    // Raw fallback: if no structured parser matched anything, regex-scan
    // the entire text for IPv4 addresses. Covers ACAS/Nessus output, email
    // headers, config dumps, and any other unstructured input that contains
    // IP addresses but no recognised log format.
    if parsed == 0 && json_malformed == 0 {
        let raw_events = f435(text);
        if !raw_events.is_empty() {
            parsed = raw_events.len();
            format = t101::Raw;
            events = raw_events;
        }
    }

    t103 {
        events,
        stats: t102 {
            parsed,
            skipped,
            format: format.name().to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wbl_native() {
        let line = r#"2026-01-15T18:42:11.123Z INFO whobelooking::visit visit ip=1.2.3.4 cc=US method=GET path=/foo ua="Mozilla/5.0" ref="-""#;
        let r = f400(line);
        assert_eq!(r.stats.parsed, 1);
        assert_eq!(r.events[0].ip, "1.2.3.4");
        assert_eq!(r.events[0].path, "/foo");
        assert_eq!(r.events[0].cc, "US");
    }

    #[test]
    fn parses_combined() {
        let line = r#"1.2.3.4 - - [15/Jan/2026:18:42:11 +0000] "GET /foo HTTP/1.1" 200 1234 "-" "Mozilla/5.0""#;
        let r = f400(line);
        assert_eq!(r.stats.parsed, 1);
        assert_eq!(r.events[0].ip, "1.2.3.4");
        assert_eq!(r.events[0].path, "/foo");
        assert!(r.events[0].ts > 0);
    }

    #[test]
    fn parses_cf_jsonl() {
        let line = r#"{"ClientIP":"1.2.3.4","ClientRequestPath":"/foo","ClientRequestMethod":"GET","ClientCountry":"us","EdgeStartTimestamp":"2026-01-15T18:42:11Z","ClientRequestUserAgent":"Mozilla/5.0"}"#;
        let r = f400(line);
        assert_eq!(r.stats.parsed, 1);
        assert_eq!(r.events[0].ip, "1.2.3.4");
        assert_eq!(r.events[0].cc, "us");
    }

    #[test]
    fn parses_cf_csv() {
        let csv = "ClientIP,ClientRequestPath,ClientRequestMethod,ClientCountry\n1.2.3.4,/foo,GET,us\n5.6.7.8,/bar,POST,gb";
        let r = f400(csv);
        assert_eq!(r.stats.parsed, 2);
        assert_eq!(r.events[0].ip, "1.2.3.4");
        assert_eq!(r.events[1].cc, "gb");
    }

    #[test]
    fn skips_garbage() {
        let r = f400("not a log line\n");
        assert_eq!(r.stats.parsed, 0);
        assert_eq!(r.stats.skipped, 1);
    }
}
