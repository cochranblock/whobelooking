// Unlicense — public domain — whobelooking.org
//! Tiny JSON scanner for *flat string-keyed objects with scalar values*.
//!
//! The crate only consumes two JSON shapes:
//!   1. Cloudflare Logpush JSONL — one flat object per line, fields we want
//!      are all string or number primitives (`ClientIP`, paths, UAs, etc).
//!   2. The enrichment overlay JS hands back to WASM — `{ "1.2.3.4":
//!      { "rdns": "...", "org": "...", "org_country": "..." }, … }`.
//!
//! That's it. Dropping `serde_json` saves ~30 KB of WASM, which is the
//! single biggest win we can get without rewriting the regex engine.
//! Anything more nuanced (arrays, deep nesting, escapes beyond `\"` `\\`
//! `\n` `\t` `\r`) is intentionally not supported — feed it the two shapes
//! above and nothing else.

use std::collections::BTreeMap;

/// f300 = scan_flat_object — parse a `{"a":"b","c":42,…}` blob into a flat
/// string→string map. Returns `None` on anything we don't understand;
/// callers must fall back to "skip this line". Thin wrapper around the
/// byte-index variant `f306` so `f304` (nested-object map) can reuse the
/// same walker without slicing-and-reparsing the inner object.
pub fn f300(src: &str) -> Option<BTreeMap<String, String>> {
    f306_at(src.as_bytes(), 0).map(|(m, _)| m)
}

/// f306 = scan_flat_object_at — same as `f300` but starts at a caller-supplied
/// byte index in an existing buffer and returns `(map, end_index)`. Lives at
/// this layer because the slice-then-`from_utf8`-then-`f300` chain used to
/// be a silent data-loss surface: if the byte walker ever returned a length
/// that landed mid-codepoint, `from_utf8` would fail and the whole
/// enrichment overlay would silently drop. Working directly on the
/// underlying `&[u8]` removes that surface entirely.
fn f306_at(bytes: &[u8], start: usize) -> Option<(BTreeMap<String, String>, usize)> {
    let mut i = f303_skip_ws(bytes, start)?;
    if bytes.get(i)? != &b'{' {
        return None;
    }
    i += 1;
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    loop {
        i = f303_skip_ws(bytes, i)?;
        if bytes.get(i)? == &b'}' {
            return Some((out, i + 1));
        }
        let (key, ni) = f301_read_string(bytes, i)?;
        i = f303_skip_ws(bytes, ni)?;
        if bytes.get(i)? != &b':' {
            return None;
        }
        i = f303_skip_ws(bytes, i + 1)?;
        let (val, ni) = f302_read_scalar(bytes, i)?;
        out.insert(key, val);
        i = f303_skip_ws(bytes, ni)?;
        match bytes.get(i)? {
            b',' => {
                i += 1;
            }
            b'}' => {
                return Some((out, i + 1));
            }
            _ => return None,
        }
    }
}

/// f304 = scan_enrichment_map — parse `{"ip": {"rdns":..., "org":..., "org_country":...}, ...}`
/// into a per-IP `BTreeMap`. Nested-object parsing delegates to `f306` on
/// the same byte buffer, so there's no slice-and-reparse and no
/// `from_utf8` round-trip that could fail on a malformed boundary.
///
/// Gated to wasm32 + tests: only the WASM bindings call this in production
/// (the native build has no enrichment-overlay path), but unit tests on
/// the native side need access to verify the round-trip.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn f304(src: &str) -> Option<BTreeMap<String, BTreeMap<String, String>>> {
    let bytes = src.as_bytes();
    let mut i = f303_skip_ws(bytes, 0)?;
    if bytes.get(i)? != &b'{' {
        return None;
    }
    i += 1;
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    loop {
        i = f303_skip_ws(bytes, i)?;
        if bytes.get(i)? == &b'}' {
            return Some(out);
        }
        let (key, ni) = f301_read_string(bytes, i)?;
        i = f303_skip_ws(bytes, ni)?;
        if bytes.get(i)? != &b':' {
            return None;
        }
        i = f303_skip_ws(bytes, i + 1)?;
        let (inner_map, ni) = f306_at(bytes, i)?;
        out.insert(key, inner_map);
        i = f303_skip_ws(bytes, ni)?;
        match bytes.get(i)? {
            b',' => {
                i += 1;
            }
            b'}' => {
                return Some(out);
            }
            _ => return None,
        }
    }
}

/// f301 = read_string — JSON string starting at `bytes[start]`. Handles only
/// the escapes JS exporters actually emit: `\"`, `\\`, `\n`, `\t`, `\r`,
/// `\/`, and `\uXXXX`. Anything else falls back to copying the byte through.
fn f301_read_string(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    if bytes.get(start)? != &b'"' {
        return None;
    }
    // Accumulate raw bytes; non-ASCII content is multi-byte UTF-8 sequences
    // that must survive verbatim into the output. Decoding byte-by-byte as
    // `as char` would silently re-interpret each byte as a Latin-1
    // codepoint and corrupt anything above U+007F.
    let mut buf: Vec<u8> = Vec::with_capacity(32);
    let mut i = start + 1;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' {
            let s = String::from_utf8(buf).ok()?;
            return Some((s, i + 1));
        }
        if c == b'\\' {
            i += 1;
            match *bytes.get(i)? {
                b'"' => buf.push(b'"'),
                b'\\' => buf.push(b'\\'),
                b'/' => buf.push(b'/'),
                b'n' => buf.push(b'\n'),
                b't' => buf.push(b'\t'),
                b'r' => buf.push(b'\r'),
                b'b' => buf.push(0x08),
                b'f' => buf.push(0x0c),
                b'u' => {
                    let hex = bytes.get(i + 1..i + 5)?;
                    let cp = u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
                    if let Some(ch) = char::from_u32(cp) {
                        let mut tmp = [0u8; 4];
                        buf.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                    }
                    i += 4;
                }
                _ => return None,
            }
            i += 1;
            continue;
        }
        buf.push(c);
        i += 1;
    }
    None
}

/// f302 = read_scalar — JSON string, number, bool, or null at `bytes[start]`.
/// All shapes coerce to `String` for the flat-object API (null → "").
fn f302_read_scalar(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let c = *bytes.get(start)?;
    if c == b'"' {
        return f301_read_string(bytes, start);
    }
    // Skip nested objects/arrays — caller only uses flat scalars; treat
    // these as empty so we don't choke on extra CF fields.
    if c == b'{' || c == b'[' {
        let pair = if c == b'{' {
            (b'{', b'}')
        } else {
            (b'[', b']')
        };
        let mut depth = 0i32;
        let mut in_str = false;
        let mut escape = false;
        let mut i = start;
        while i < bytes.len() {
            let b = bytes[i];
            if in_str {
                if escape {
                    escape = false;
                } else if b == b'\\' {
                    escape = true;
                } else if b == b'"' {
                    in_str = false;
                }
                i += 1;
                continue;
            }
            if b == b'"' {
                in_str = true;
            } else if b == pair.0 {
                depth += 1;
            } else if b == pair.1 {
                depth -= 1;
                if depth == 0 {
                    return Some((String::new(), i + 1));
                }
            }
            i += 1;
        }
        return None;
    }
    // Number / bool / null — read until the next struct delimiter.
    let mut end = start;
    while end < bytes.len() {
        let b = bytes[end];
        if b == b','
            || b == b'}'
            || b == b']'
            || b == b' '
            || b == b'\n'
            || b == b'\t'
            || b == b'\r'
        {
            break;
        }
        end += 1;
    }
    let s = std::str::from_utf8(&bytes[start..end]).ok()?;
    if s == "null" {
        Some((String::new(), end))
    } else {
        Some((s.to_string(), end))
    }
}

/// f303 = skip_ws — advance past `' '`, `'\t'`, `'\n'`, `'\r'`. Returns the
/// new index. None only if input was truncated (input is empty / `start ==
/// len`).
fn f303_skip_ws(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            _ => return Some(i),
        }
    }
    Some(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flat_strings() {
        let s = r#"{"ip":"1.2.3.4","ua":"Mozilla","cc":"US"}"#;
        let m = f300(s).unwrap();
        assert_eq!(m["ip"], "1.2.3.4");
        assert_eq!(m["ua"], "Mozilla");
        assert_eq!(m["cc"], "US");
    }

    #[test]
    fn coerces_numbers_to_string() {
        let s = r#"{"port":8080,"latency":12.5}"#;
        let m = f300(s).unwrap();
        assert_eq!(m["port"], "8080");
        assert_eq!(m["latency"], "12.5");
    }

    #[test]
    fn handles_escapes() {
        let s = r#"{"path":"/x\"y","ua":"foo\nbar"}"#;
        let m = f300(s).unwrap();
        assert_eq!(m["path"], "/x\"y");
        assert_eq!(m["ua"], "foo\nbar");
    }

    #[test]
    fn skips_unknown_objects() {
        let s = r#"{"ip":"1.2.3.4","extra":{"nested":"yes"},"ua":"x"}"#;
        let m = f300(s).unwrap();
        assert_eq!(m["ip"], "1.2.3.4");
        assert_eq!(m["ua"], "x");
        assert_eq!(m.get("extra").map(String::as_str), Some(""));
    }

    #[test]
    fn enrichment_map_roundtrip() {
        let s = r#"{
            "1.2.3.4": {"rdns": "a.example", "org": "Example Inc", "org_country": "US"},
            "5.6.7.8": {"rdns": "b.example"}
        }"#;
        let m = f304(s).unwrap();
        assert_eq!(m["1.2.3.4"]["rdns"], "a.example");
        assert_eq!(m["1.2.3.4"]["org"], "Example Inc");
        assert_eq!(m["5.6.7.8"]["rdns"], "b.example");
    }

    // The `from_utf8` round-trip we used to do was the surface flagged as
    // a silent data-loss risk. Non-ASCII content inside the *inner* object
    // is the exact shape that would have tripped it. The new f304/f306
    // share a byte buffer instead of slicing-and-reparsing, so this case
    // round-trips byte-for-byte without going through `from_utf8`.
    #[test]
    fn enrichment_map_inner_utf8() {
        let s = r#"{"1.2.3.4":{"org":"Café Networks AG","org_country":"DE"}}"#;
        let m = f304(s).unwrap();
        assert_eq!(m["1.2.3.4"]["org"], "Café Networks AG");
        assert_eq!(m["1.2.3.4"]["org_country"], "DE");
    }

    // Inner object with a backslash-escaped quote: previously the slice
    // walker could mis-skip and the inner from_utf8 would silently reject.
    #[test]
    fn enrichment_map_inner_escaped_quote() {
        let s = r#"{"1.2.3.4":{"org":"O\"Brien Networks"}}"#;
        let m = f304(s).unwrap();
        assert_eq!(m["1.2.3.4"]["org"], "O\"Brien Networks");
    }

    #[test]
    fn handles_null() {
        let s = r#"{"x":null,"y":"v"}"#;
        let m = f300(s).unwrap();
        assert_eq!(m["x"], "");
        assert_eq!(m["y"], "v");
    }
}
