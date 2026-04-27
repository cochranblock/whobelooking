// All Rights Reserved — The Cochran Block, LLC
#![forbid(unsafe_code)]
// Contributors: GotEmCoach, KOVA, Claude Opus 4.6
//! whobelooking library — pure logic exposed for the main binary and the
//! test binary. Sled I/O and source pullers stay in src/main.rs; everything
//! here is deterministic, no I/O, safe to test in isolation.

pub mod ctos {
    use serde::{Deserialize, Serialize};
    use std::collections::{HashMap, HashSet};

    // =========================================================================
    // Types
    // =========================================================================

    /// One raw observation of a CTO in a public source. May be partial.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct CtoMention {
        pub source: String,        // hn | yc | github | reddit | podcasts
        pub source_url: String,    // URL where this observation came from
        pub name: String,          // scraped name ("" if not observed)
        pub company: String,       // scraped company ("" if not observed)
        pub handle: String,        // platform handle ("" if none)
        pub context: String,       // short snippet for review
        pub company_url: String,   // observed company URL ("" if none)
        pub scraped_email: String, // observed email ("" if none)
        pub fetched_at: u64,
    }

    /// Cross-verified CTO — same name + company in 2+ distinct sources.
    #[derive(Debug, Clone)]
    pub struct VerifiedCto {
        pub name: String,
        pub company: String,
        pub sources: Vec<(String, String)>,       // (source, url)
        pub company_urls: Vec<String>,            // observed company URLs
        pub direct_emails: Vec<(String, String)>, // (email, source_url)
    }

    // =========================================================================
    // Timestamps
    // =========================================================================

    pub fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Cheap ISO date — civil-calendar reconstruction from epoch days.
    pub fn today_iso() -> String {
        let secs = now_secs() as i64;
        let days = secs / 86400;
        let y = (10000 * days + 14780) / 3652425;
        let doy = days - (365 * y + y / 4 - y / 100 + y / 400);
        let y = if doy < 0 { y - 1 } else { y };
        let doy = if doy < 0 {
            days - (365 * y + y / 4 - y / 100 + y / 400)
        } else {
            doy
        };
        let mi = (100 * doy + 52) / 3060;
        let month = mi + 3 - 12 * (mi / 10);
        let year = y + mi / 10;
        let day = doy - (mi * 306 + 5) / 10 + 1;
        format!("{:04}-{:02}-{:02}", year, month, day)
    }

    // =========================================================================
    // Normalization
    // =========================================================================

    pub fn norm(s: &str) -> String {
        s.to_lowercase()
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == ' ')
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn norm_company(s: &str) -> String {
        let mut n = norm(s.trim_start_matches('@'));
        // Loop until stable — "Beta Co AI" → strip " ai" → strip " co" → "beta"
        loop {
            let before = n.len();
            for suffix in [
                " inc", " llc", " ltd", " corp", " gmbh", " co", " company", " io", " ai",
            ] {
                if n.ends_with(suffix) {
                    n.truncate(n.len() - suffix.len());
                    n = n.trim().to_string();
                }
            }
            if n.len() == before {
                break;
            }
        }
        n
    }

    pub fn truncate(s: &str, max: usize) -> String {
        if s.chars().count() <= max {
            s.to_string()
        } else {
            s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
        }
    }

    pub fn slugify(s: &str) -> String {
        s.to_lowercase()
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '-' })
            .collect::<String>()
            .split('-')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("-")
    }

    // =========================================================================
    // CTO mention extraction from free text
    // =========================================================================

    /// Find "CTO of X" / "CTO at X" patterns in text and capture candidate
    /// name + company. A mention with an empty name still gets emitted but
    /// won't cross-verify (verify() drops partial mentions).
    pub fn extract_cto_from_text(text: &str, source: &str, url: &str) -> Vec<CtoMention> {
        let mut out = Vec::new();
        let markers: &[&str] = &["CTO of ", "CTO at ", "CTO @ ", "cto of ", "cto at "];
        for marker in markers {
            let mut start = 0;
            while let Some(pos) = text[start..].find(marker) {
                let abs = start + pos;
                let tail = &text[abs + marker.len()..];
                let company_raw: String = tail
                    .chars()
                    .take(80)
                    .take_while(|c| {
                        *c != '.'
                            && *c != ','
                            && *c != ';'
                            && *c != '\n'
                            && *c != '—'
                            && *c != '('
                            && *c != ')'
                            && *c != '|'
                            && *c != '!'
                            && *c != '?'
                    })
                    .collect();
                let company_words: Vec<&str> = company_raw.split_whitespace().take(3).collect();
                // Trim trailing common verbs/conjunctions that leak into
                // company names ("Acme Labs and" → "Acme Labs")
                let mut trimmed: Vec<&str> = company_words;
                while let Some(last) = trimmed.last() {
                    if is_company_stop_word(last) {
                        trimmed.pop();
                    } else {
                        break;
                    }
                }
                let company = trimmed.join(" ").trim().to_string();
                if company.len() < 2 || company.len() > 60 {
                    start = abs + marker.len();
                    continue;
                }
                let name = extract_name_before(&text[..abs]).unwrap_or_default();
                let ctx_start = abs.saturating_sub(60);
                let ctx_end = (abs + marker.len() + company.len() + 20).min(text.len());
                let context = text[ctx_start..ctx_end].replace('\n', " ");
                out.push(CtoMention {
                    source: source.to_string(),
                    source_url: url.to_string(),
                    name,
                    company,
                    handle: String::new(),
                    context: truncate(&context, 200),
                    company_url: String::new(),
                    scraped_email: String::new(),
                    fetched_at: now_secs(),
                });
                start = abs + marker.len();
            }
        }
        out
    }

    fn extract_name_before(text: &str) -> Option<String> {
        let words: Vec<&str> = text.split_whitespace().collect();
        let n = words.len();
        let from = n.saturating_sub(20);
        let window = &words[from..n];
        for i in (0..window.len().saturating_sub(1)).rev() {
            let a = strip_edge_punct(window[i]);
            let b = strip_edge_punct(window[i + 1]);
            if is_cap_name(a) && is_cap_name(b) && !is_noise_word(a) && !is_noise_word(b) {
                return Some(format!("{} {}", a, b));
            }
        }
        None
    }

    fn strip_edge_punct(s: &str) -> &str {
        s.trim_matches(|c: char| !c.is_alphabetic())
    }

    fn is_cap_name(s: &str) -> bool {
        if s.len() < 2 || s.len() > 20 {
            return false;
        }
        let mut cs = s.chars();
        let first = match cs.next() {
            Some(c) => c,
            None => return false,
        };
        if !first.is_uppercase() {
            return false;
        }
        cs.all(|c| c.is_alphabetic())
    }

    fn is_company_stop_word(s: &str) -> bool {
        let lower: String = s.to_lowercase();
        matches!(
            lower.as_str(),
            "and"
                | "she"
                | "he"
                | "they"
                | "who"
                | "which"
                | "where"
                | "that"
                | "this"
                | "explained"
                | "said"
                | "told"
                | "announced"
                | "spoke"
                | "described"
                | "launched"
                | "built"
                | "reported"
                | "joined"
                | "left"
                | "while"
                | "because"
                | "since"
                | "when"
                | "presented"
                | "is"
                | "was"
                | "has"
                | "had"
                | "will"
                | "the"
                | "to"
                | "for"
                | "with"
                | "on"
                | "in"
                | "a"
                | "an"
        )
    }

    fn is_noise_word(s: &str) -> bool {
        matches!(
            s,
            "The"
                | "Our"
                | "My"
                | "His"
                | "Her"
                | "Their"
                | "CTO"
                | "A"
                | "An"
                | "I"
                | "We"
                | "Is"
                | "As"
                | "Co"
                | "Ex"
                | "Former"
                | "New"
                | "Hi"
                | "Hello"
                | "Hey"
                | "This"
                | "That"
                | "Hiring"
                | "Founder"
                | "Chief"
                | "Technology"
                | "Officer"
                | "Engineering"
                | "Engineer"
                | "Senior"
                | "Lead"
                | "Ask"
                | "Show"
                | "Tell"
                | "YC"
                | "Startup"
        )
    }

    // =========================================================================
    // Email extraction
    // =========================================================================

    /// Extract the first non-placeholder email from free text.
    /// Skips example@, noreply@, test@, sentry@, wordpress@, localhost.
    /// Returns (email, byte_offset_of_start).
    pub fn extract_first_email(text: &str) -> Option<(String, usize)> {
        let chars: Vec<char> = text.chars().collect();
        let n = chars.len();
        for i in 0..n {
            if chars[i] != '@' {
                continue;
            }
            let mut l = i;
            while l > 0 && is_local_char(chars[l - 1]) {
                l -= 1;
            }
            let mut r = i + 1;
            while r < n && is_domain_char(chars[r]) {
                r += 1;
            }
            if l >= i || r <= i + 2 {
                continue;
            }
            let domain: String = chars[i + 1..r].iter().collect();
            if !domain.contains('.') || domain.ends_with('.') || domain.starts_with('.') {
                continue;
            }
            let email: String = chars[l..r].iter().collect();
            let lower = email.to_lowercase();
            if is_placeholder_email(&lower) {
                continue;
            }
            return Some((email, l));
        }
        None
    }

    fn is_placeholder_email(lower: &str) -> bool {
        lower.contains("example")
            || lower.contains("noreply")
            || lower.contains("no-reply")
            || lower.starts_with("sentry@")
            || lower.starts_with("wordpress@")
            || lower.starts_with("test@")
            || lower.contains("@sentry.io")
            || lower.contains("@localhost")
    }

    fn is_local_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-')
    }
    fn is_domain_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '-')
    }

    // =========================================================================
    // Cross-verification
    // =========================================================================

    /// Group mentions by normalized (name, company). Keep only groups with
    /// 2+ distinct sources. Partial mentions (empty name or company) are
    /// silently dropped — they can never verify on their own.
    pub fn verify(mentions: &[CtoMention]) -> Vec<VerifiedCto> {
        let mut groups: HashMap<(String, String), Vec<&CtoMention>> = HashMap::new();
        for m in mentions {
            if m.name.is_empty() || m.company.is_empty() {
                continue;
            }
            let key = (norm(&m.name), norm_company(&m.company));
            if key.0.is_empty() || key.1.is_empty() {
                continue;
            }
            groups.entry(key).or_default().push(m);
        }
        let mut out = Vec::new();
        for ((_nk, _ck), ms) in groups {
            let distinct: HashSet<&str> = ms.iter().map(|m| m.source.as_str()).collect();
            if distinct.len() < 2 {
                continue;
            }
            let name = ms
                .iter()
                .map(|m| m.name.clone())
                .max_by_key(|s| s.len())
                .unwrap_or_default();
            let company = ms
                .iter()
                .map(|m| m.company.clone())
                .max_by_key(|s| s.len())
                .unwrap_or_default();
            let sources: Vec<(String, String)> = ms
                .iter()
                .map(|m| (m.source.clone(), m.source_url.clone()))
                .collect();
            let company_urls: Vec<String> = ms
                .iter()
                .filter_map(|m| {
                    if m.company_url.is_empty() {
                        None
                    } else {
                        Some(m.company_url.clone())
                    }
                })
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            let direct_emails: Vec<(String, String)> = ms
                .iter()
                .filter_map(|m| {
                    if m.scraped_email.is_empty() {
                        None
                    } else {
                        Some((m.scraped_email.clone(), m.source_url.clone()))
                    }
                })
                .collect();
            out.push(VerifiedCto {
                name,
                company,
                sources,
                company_urls,
                direct_emails,
            });
        }
        out.sort_by(|a, b| b.sources.len().cmp(&a.sources.len()));
        out
    }
}

/// Queue types — deterministic, no I/O, safe to test in isolation.
pub mod queue_types {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum JobStatus {
        Paid,
        Pending,
        InProgress,
        Complete,
        Delivered,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum Tier {
        Starter,
        Growth,
        Scale,
        Custom,
    }

    impl Tier {
        pub fn estimated_hours(&self) -> f32 {
            match self {
                Tier::Starter => 1.5,
                Tier::Growth => 3.0,
                Tier::Scale => 6.0,
                Tier::Custom => 8.0,
            }
        }

        pub fn price_cents(&self) -> u32 {
            match self {
                Tier::Starter => 15000,
                Tier::Growth => 35000,
                Tier::Scale => 75000,
                Tier::Custom => 150000,
            }
        }

        pub fn label(&self) -> &'static str {
            match self {
                Tier::Starter => "Starter (<500 IPs)",
                Tier::Growth => "Growth (500-2K IPs)",
                Tier::Scale => "Scale (2K-10K IPs)",
                Tier::Custom => "Custom (10K+ IPs)",
            }
        }
    }

    pub const HOURS_PER_WEEK: f32 = 12.0;

    pub fn has_capacity(committed_hours: f32, tier: &Tier) -> bool {
        committed_hours + tier.estimated_hours() <= HOURS_PER_WEEK
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum SourceType {
        Cloudflare { zone: String, token: String },
        AccessLog,
        Csv,
        Json,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Job {
        pub id: String,
        pub customer_email: String,
        pub source_type: SourceType,
        pub tier: Tier,
        pub status: JobStatus,
        pub estimated_hours: f32,
        pub created_at: u64,
        pub started_at: Option<u64>,
        pub completed_at: Option<u64>,
        pub report_path: Option<String>,
        pub notes: Option<String>,
    }
}

#[path = "crypto.rs"]
pub mod crypto;

#[path = "orders.rs"]
pub mod orders;

/// CIDR membership test for IPv4 and IPv6 prefixes.  No allocation, no
/// dependencies — used by the RDAP cache to coalesce per-/24 lookups.
pub mod cidr {
    /// Parse `"a.b.c.d/N"` or `"prefix/N"` (IPv6) and return `(prefix_bytes, prefix_len)`.
    /// IPv4 prefixes return 4 bytes; IPv6 returns 16 bytes.
    pub fn parse(cidr: &str) -> Option<(Vec<u8>, u8)> {
        let (addr, len) = cidr.split_once('/')?;
        let len: u8 = len.parse().ok()?;
        if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
            if len > 32 {
                return None;
            }
            return Some((v4.octets().to_vec(), len));
        }
        if let Ok(v6) = addr.parse::<std::net::Ipv6Addr>() {
            if len > 128 {
                return None;
            }
            return Some((v6.octets().to_vec(), len));
        }
        None
    }

    /// Does `ip` fall inside `cidr`?  Returns false on any parse failure or
    /// family mismatch (v4 IP vs v6 CIDR or vice versa).
    pub fn contains(cidr: &str, ip: &str) -> bool {
        let Some((prefix, len)) = parse(cidr) else {
            return false;
        };
        let ip_bytes: Vec<u8> = if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
            v4.octets().to_vec()
        } else if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
            v6.octets().to_vec()
        } else {
            return false;
        };
        if ip_bytes.len() != prefix.len() {
            return false;
        }
        let full_bytes = (len / 8) as usize;
        let tail_bits = (len % 8) as usize;
        if ip_bytes[..full_bytes] != prefix[..full_bytes] {
            return false;
        }
        if tail_bits == 0 {
            return true;
        }
        let mask: u8 = 0xFFu8 << (8 - tail_bits);
        (ip_bytes[full_bytes] & mask) == (prefix[full_bytes] & mask)
    }
}

/// IP redaction + project-level operator ignore-list.
/// Pure functions — safe to call from test binary.
pub mod redact {
    /// Operator IP prefixes to drop entirely from any visitor report.
    /// Mirrors `feedback_ignore_list_operator_ip.md` in this project's memory.
    pub const OPERATOR_IPV4_PREFIXES: &[&str] = &["173.69.182."];
    pub const OPERATOR_IPV6_PREFIXES: &[&str] = &[];

    pub fn is_operator(ip: &str) -> bool {
        if ip.contains(':') {
            OPERATOR_IPV6_PREFIXES.iter().any(|p| ip.starts_with(p))
        } else {
            OPERATOR_IPV4_PREFIXES.iter().any(|p| ip.starts_with(p))
        }
    }

    /// IPv4 → first two octets + ".x.x"; IPv6 → first two hextets + "::x:x".
    /// Anything that doesn't parse as either is returned unchanged.
    pub fn redact(ip: &str) -> String {
        if let Some((a, rest)) = ip.split_once('.') {
            if let Some((b, _)) = rest.split_once('.') {
                if a.parse::<u8>().is_ok() && b.parse::<u8>().is_ok() {
                    return format!("{}.{}.x.x", a, b);
                }
            }
        }
        if ip.contains(':') {
            // Walk from the left, take up to 2 leading hextets, stop at `::`.
            let mut leading: Vec<&str> = Vec::new();
            for part in ip.split(':') {
                if part.is_empty() {
                    break;
                }
                leading.push(part);
                if leading.len() == 2 {
                    break;
                }
            }
            if !leading.is_empty() {
                return format!("{}::x:x", leading.join(":"));
            }
        }
        ip.to_string()
    }

    /// Pure threat classification — derived from the union of paths + user agents
    /// observed for one IP. Returns `&'static str` so callers can stash it in a struct.
    ///
    /// Order matters: most-specific threat tier first
    /// (CRED_HUNT > EXPLOIT > WP_PROBE > LLM_PROBE > CRAWLER > BUYER > BROWSER).
    ///
    /// Path matching is **token-aware**: we split each URL on `/` and `?` so a
    /// segment like `.env` matches `/foo/.env` but not `/wp-environment/`.
    /// Substring fragments (e.g. `wp-admin`, `wlwmanifest`, `xmrlpc`) still
    /// match across a segment so we catch obfuscated probes.
    pub fn classify(paths: &[&str], user_agents: &[&str]) -> &'static str {
        // Pre-tokenize once. Lowercased segments split on `/` `?` `;` `&` `=`.
        let segments: Vec<String> = paths
            .iter()
            .flat_map(|p| {
                p.split(['/', '?', ';', '&', '='])
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .collect();
        let seg_refs: Vec<&str> = segments.iter().map(String::as_str).collect();
        let pl = paths.join(" ").to_ascii_lowercase();
        let ul = user_agents.join(" ").to_ascii_lowercase();

        // Whole-segment exact matches catch credential filenames without
        // false-positiving paths that merely contain the token.
        const CRED_SEGMENTS: &[&str] = &[
            ".env",
            ".env.staging",
            ".env.production",
            ".env.local",
            ".env.live",
            ".env.old",
            ".env.bak",
            ".env.sample",
            ".npmrc",
            ".boto",
            ".pgpass",
            ".pypirc",
            ".aws",
            "credentials",
            "id_rsa",
            "id_ed25519",
            ".dockerconfigjson",
            "wp-config.php",
            ".env_sample",
            ".git-credentials",
            ".docker",
            "config.json",
        ];
        // Path-substring matches for paths that legitimately contain these.
        const CRED_SUBSTRINGS: &[&str] = &[".git/", ".ssh/", "/.cursor"];
        if seg_refs.iter().any(|s| CRED_SEGMENTS.contains(s))
            || CRED_SUBSTRINGS.iter().any(|s| pl.contains(s))
        {
            return "CRED_HUNT";
        }

        const EXPLOIT_SEGMENTS: &[&str] = &["phpmyadmin", "adminer", "shell.php", "config.php"];
        const EXPLOIT_SUBSTRINGS: &[&str] = &[
            "/cgi-bin/",
            "/manager/html",
            "/admin/serverconfig",
            "/actuator/env",
            "/swagger",
        ];
        if seg_refs.iter().any(|s| EXPLOIT_SEGMENTS.contains(s))
            || EXPLOIT_SUBSTRINGS.iter().any(|s| pl.contains(s))
        {
            return "EXPLOIT";
        }

        const WP_SUBSTRINGS: &[&str] = &[
            "wp-admin",
            "wp-login",
            "wp-includes",
            "wlwmanifest",
            "xmlrpc",
            "wordpress",
            "xmrlpc",
        ];
        const WP_SEGMENTS: &[&str] = &["3.php"];
        if WP_SUBSTRINGS.iter().any(|s| pl.contains(s))
            || seg_refs.iter().any(|s| WP_SEGMENTS.contains(s))
        {
            return "WP_PROBE";
        }

        if pl.contains("/v1/completions")
            || pl.contains("/v1/embeddings")
            || pl.contains("/v1/models")
            || pl.contains("/v1/chat")
        {
            return "LLM_PROBE";
        }
        if ul.contains("googlebot")
            || ul.contains("bingbot")
            || ul.contains("gptbot")
            || ul.contains("chatgpt")
            || ul.contains("anthropic")
            || ul.contains("applebot")
            || ul.contains("bytespider")
            || ul.contains("yandexbot")
            || ul.contains("duckduck")
            || ul.contains("linkedinbot")
            || ul.contains("ccbot")
            || ul.contains("facebookexternalhit")
            || ul.contains("crawl")
            || ul.contains(" bot")
            || ul.contains("spider")
        {
            return "CRAWLER";
        }
        // Buyer = visited a marketing/conversion page. Match whole-segment so
        // `/booklet` does not register as `/book`, `/aboutwordpress` not as `/about`.
        const BUYER_SEGMENTS: &[&str] = &[
            "order", "contact", "pricing", "about", "products", "services", "checkout", "govdocs",
            "sbir", "dcaa", "vre", "book", "booking", "intake",
        ];
        if seg_refs.iter().any(|s| BUYER_SEGMENTS.contains(s)) {
            return "BUYER";
        }
        "BROWSER"
    }

    /// Redact every IPv4/IPv6 literal embedded in free-form text.
    pub fn redact_text(s: &str) -> String {
        // Patterns are compile-time literals and unit-tested.  `expect` documents
        // intent: if these ever fail we want a hard, immediate panic — never
        // silent under-redaction.
        let v4 = regex_lite::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
            .expect("v4 redaction regex must compile");
        let v6 =
            regex_lite::Regex::new(r"\b[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F:]+)?\b")
                .expect("v6 redaction regex must compile");
        let s = v4
            .replace_all(s, |c: &regex_lite::Captures| redact(&c[0]))
            .into_owned();
        v6.replace_all(&s, |c: &regex_lite::Captures| redact(&c[0]))
            .into_owned()
    }
}
