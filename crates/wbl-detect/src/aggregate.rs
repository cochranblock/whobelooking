// Unlicense — public domain — whobelooking.org
//! Per-IP rollup + IP-level classification.
//!
//! Takes the flat `Vec<t100>` from `parse` and folds it into one record
//! per source IP — hit count, top paths, top UAs, first/last seen,
//! enrichment slots (rDNS, org, org country). Then assigns each IP one of
//! four classes (threat / institutional / organic / bot) using the same
//! rules the `/try` page used to apply in JS.

use crate::parse::t100;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// t104 = IpClass
pub enum t104 {
    Threat,
    Institutional,
    Organic,
    Bot,
}

impl t104 {
    pub fn name(self) -> &'static str {
        match self {
            t104::Threat => "threat",
            t104::Institutional => "institutional",
            t104::Organic => "organic",
            t104::Bot => "bot",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
/// t105 = IpRecord
pub struct t105 {
    pub hits: u32,
    pub paths: BTreeMap<String, u32>,
    pub user_agents: BTreeMap<String, u32>,
    pub countries: BTreeMap<String, u32>,
    pub methods: BTreeMap<String, u32>,
    pub first_unix: i64,
    pub last_unix: i64,
    pub class: Option<t104>,
    pub rdns: Option<String>,
    pub org: Option<String>,
    pub org_country: Option<String>,
    /// Earliest unix timestamp this IP has ever been seen across all reports.
    pub history_first_unix: Option<i64>,
    /// Total number of reports this IP has appeared in (before this one).
    pub history_total_reports: Option<u32>,
    /// Cumulative hit count across all prior reports.
    pub history_total_hits: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
/// t106 = DayStat
pub struct t106 {
    pub hits: u32,
    pub unique_ips: u32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
/// t107 = AggregatedReport
pub struct t107 {
    pub total_events: usize,
    pub distinct_paths: usize,
    pub ips: BTreeMap<String, t105>,
    pub days: BTreeMap<i64, t106>,
    pub class_counts: BTreeMap<String, u32>,
}

/// Attack-path needles that mark an IP as `threat`. Matched
/// case-insensitively against the lowercased path. Mirrors the JS
/// `ATTACK_PATHS` list in the old `/try` rendering, expanded slightly
/// for parity with `classify.rs`'s `CredHunt` + `Exploit` + `WpProbe`
/// + `LlmProbe` buckets.
const ATTACK_PATHS: &[&str] = &[
    ".env",
    ".git/",
    ".aws/",
    ".ssh",
    ".npmrc",
    ".boto",
    ".pgpass",
    ".pypirc",
    ".dockerconfigjson",
    "credentials",
    "id_rsa",
    "config.php",
    "shell.php",
    "phpmyadmin",
    "adminer",
    "/manager/html",
    "/admin/serverconfig",
    "/actuator/env",
    "wp-admin",
    "wp-login",
    "wlwmanifest",
    "xmlrpc",
    "/v1/completions",
    "/v1/embeddings",
    "/v1/models",
    "/v1/chat",
    ".ds_store",
    "secrets",
    "/cgi-bin/",
    "/3.php",
];

/// User-agent substrings that mark a request as a bot. Lowercased before match.
const BOT_HINTS: &[&str] = &[
    "bot",
    "crawl",
    "spider",
    "slurp",
    "scrap",
    "headless",
    "wget",
    "curl/",
    "python-requests",
    "go-http-client",
    "java/",
    "okhttp",
];

/// Real-browser substrings. Lowercased before match.
const BROWSER_HINTS: &[&str] = &["mozilla", "safari", "chrome", "firefox", "edg/"];

/// f404 = classify_ip
pub fn f404(rec: &t105) -> t104 {
    // 1. Threat: any attack-path probe seen
    for p in rec.paths.keys() {
        let pl = p.to_ascii_lowercase();
        if ATTACK_PATHS.iter().any(|a| pl.contains(a)) {
            return t104::Threat;
        }
    }
    // 2. Bot: every UA looks botty (at least one UA known)
    let uas: Vec<String> = rec
        .user_agents
        .keys()
        .map(|u| u.to_ascii_lowercase())
        .collect();
    if !uas.is_empty() && uas.iter().all(|u| BOT_HINTS.iter().any(|h| u.contains(h))) {
        return t104::Bot;
    }
    // 3. Institutional: low-volume + has a real-browser UA
    let has_browser_ua = uas
        .iter()
        .any(|u| BROWSER_HINTS.iter().any(|h| u.contains(h)));
    if rec.hits <= 30 && has_browser_ua {
        return t104::Institutional;
    }
    t104::Organic
}

/// f401 = aggregate
pub fn f401(events: &[t100]) -> t107 {
    let mut report = t107::default();
    let mut distinct_paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut day_ips: BTreeMap<i64, std::collections::BTreeSet<String>> = BTreeMap::new();

    for e in events {
        report.total_events += 1;
        distinct_paths.insert(e.path.clone());
        let rec = report.ips.entry(e.ip.clone()).or_default();
        rec.hits += 1;
        *rec.paths.entry(e.path.clone()).or_insert(0) += 1;
        if !e.ua.is_empty() {
            *rec.user_agents.entry(e.ua.clone()).or_insert(0) += 1;
        }
        if !e.cc.is_empty() {
            *rec.countries.entry(e.cc.clone()).or_insert(0) += 1;
        }
        *rec.methods.entry(e.method.clone()).or_insert(0) += 1;
        if rec.first_unix == 0 || (e.ts > 0 && e.ts < rec.first_unix) {
            rec.first_unix = e.ts;
        }
        if e.ts > rec.last_unix {
            rec.last_unix = e.ts;
        }

        if e.ts > 0 {
            let day = e.ts / 86400;
            day_ips.entry(day).or_default().insert(e.ip.clone());
            let d = report.days.entry(day).or_default();
            d.hits += 1;
        }
    }

    for (day, ips) in &day_ips {
        if let Some(d) = report.days.get_mut(day) {
            d.unique_ips = ips.len() as u32;
        }
    }

    // Classify after the full rollup is in hand.
    for (_ip, rec) in report.ips.iter_mut() {
        let c = f404(rec);
        rec.class = Some(c);
        *report.class_counts.entry(c.name().to_string()).or_insert(0) += 1;
    }

    report.distinct_paths = distinct_paths.len();
    report
}

/// Enrichment overlay passed in from the caller (JS does the actual DoH +
/// RDAP fetches in the browser; native callers can pass an empty map).
#[derive(Debug, Default, Deserialize)]
/// t108 = IpEnrichment
pub struct t108 {
    pub rdns: Option<String>,
    pub org: Option<String>,
    pub org_country: Option<String>,
    pub history_first_unix: Option<i64>,
    pub history_total_reports: Option<u32>,
    pub history_total_hits: Option<u32>,
}

/// f402 = apply_enrichment.
///
/// Splice rDNS/org/country into existing IpRecords for every IP found in
/// `enrich`. Empty strings in the overlay are treated as "no value, keep
/// what's already there" so a JS layer that only resolved rDNS for an IP
/// can still call `f402` without wiping a previously-known
/// org name.
///
/// After the splice every record is re-run through `f404` and the
/// `class_counts` map is rebuilt from scratch. Today `f404` only
/// reads `rec.paths` and `rec.user_agents`, so the re-classify is inert
/// for current inputs — but the hook is wired so a future rule (eg.
/// "rec.org matches a known enterprise → bump organic → institutional")
/// drops in without callers also having to remember to re-classify.
pub fn f402(report: &mut t107, enrich: &BTreeMap<String, t108>) {
    for (ip, e) in enrich {
        if let Some(rec) = report.ips.get_mut(ip) {
            if let Some(r) = &e.rdns {
                if !r.is_empty() {
                    rec.rdns = Some(r.clone());
                }
            }
            if let Some(o) = &e.org {
                if !o.is_empty() {
                    rec.org = Some(o.clone());
                }
            }
            if let Some(c) = &e.org_country {
                if !c.is_empty() {
                    rec.org_country = Some(c.clone());
                }
            }
            if e.history_first_unix.is_some() {
                rec.history_first_unix = e.history_first_unix;
                rec.history_total_reports = e.history_total_reports;
                rec.history_total_hits = e.history_total_hits;
            }
        }
    }
    // Re-classify + rebuild counts. The order matters: we must call
    // `f404` against the post-enrichment record, then count.
    report.class_counts.clear();
    for rec in report.ips.values_mut() {
        let c = f404(rec);
        rec.class = Some(c);
        *report.class_counts.entry(c.name().to_string()).or_insert(0) += 1;
    }
}

/// f403 = ips_needing_enrichment.
///
/// Return the list of IPs the browser should run DoH PTR + RDAP for. Skips
/// IPs that are already enriched. Limited to IPv4 in v0 — IPv6 reverse-zone
/// PTR is its own beast and we don't want it blocking the report.
pub fn f403(report: &t107) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (ip, rec) in &report.ips {
        if rec.rdns.is_some() && rec.org.is_some() {
            continue;
        }
        if f430(ip) {
            out.push(ip.clone());
        }
    }
    out
}

fn f430(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::t100;

    fn ev(ip: &str, path: &str, ua: &str) -> t100 {
        t100 {
            ts: 1_700_000_000,
            ip: ip.into(),
            cc: "".into(),
            method: "GET".into(),
            path: path.into(),
            ua: ua.into(),
            referrer: "".into(),
        }
    }

    #[test]
    fn threat_wins_over_browser() {
        let events = vec![
            ev("1.1.1.1", "/.env", "Mozilla/5.0"),
            ev("1.1.1.1", "/", "Mozilla/5.0"),
        ];
        let r = f401(&events);
        assert_eq!(r.ips["1.1.1.1"].class, Some(t104::Threat));
    }

    #[test]
    fn bot_only_when_all_uas_bot() {
        let events = vec![ev("2.2.2.2", "/", "Googlebot/2.1")];
        let r = f401(&events);
        assert_eq!(r.ips["2.2.2.2"].class, Some(t104::Bot));
    }

    #[test]
    fn institutional_under_30_hits() {
        let events = vec![ev("3.3.3.3", "/about", "Mozilla/5.0 Chrome")];
        let r = f401(&events);
        assert_eq!(r.ips["3.3.3.3"].class, Some(t104::Institutional));
    }

    #[test]
    fn ips_needing_enrichment_skips_filled() {
        let events = vec![
            ev("4.4.4.4", "/", "Mozilla/5.0"),
            ev("5.5.5.5", "/", "Mozilla/5.0"),
        ];
        let mut r = f401(&events);
        r.ips.get_mut("4.4.4.4").unwrap().rdns = Some("a.example".into());
        r.ips.get_mut("4.4.4.4").unwrap().org = Some("Example".into());
        let need = f403(&r);
        assert_eq!(need, vec!["5.5.5.5".to_string()]);
    }
}
