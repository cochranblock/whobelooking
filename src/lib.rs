// Unlicense — cochranblock.org
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
            .unwrap()
            .as_secs()
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
            for suffix in [" inc", " llc", " ltd", " corp", " gmbh", " co", " company", " io", " ai"] {
                if n.ends_with(suffix) {
                    n.truncate(n.len() - suffix.len());
                    n = n.trim().to_string();
                }
            }
            if n.len() == before { break; }
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
                        *c != '.' && *c != ',' && *c != ';' && *c != '\n'
                            && *c != '—' && *c != '(' && *c != ')' && *c != '|'
                            && *c != '!' && *c != '?'
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
            "and" | "she" | "he" | "they" | "who" | "which" | "where" | "that"
            | "this" | "explained" | "said" | "told" | "announced" | "spoke"
            | "described" | "launched" | "built" | "reported" | "joined" | "left"
            | "while" | "because" | "since" | "when" | "presented" | "is" | "was"
            | "has" | "had" | "will" | "the" | "to" | "for" | "with" | "on"
            | "in" | "a" | "an"
        )
    }

    fn is_noise_word(s: &str) -> bool {
        matches!(
            s,
            "The" | "Our" | "My" | "His" | "Her" | "Their" | "CTO" | "A" | "An"
            | "I" | "We" | "Is" | "As" | "Co" | "Ex" | "Former" | "New" | "Hi"
            | "Hello" | "Hey" | "This" | "That" | "Hiring" | "Founder" | "Chief"
            | "Technology" | "Officer" | "Engineering" | "Engineer" | "Senior"
            | "Lead" | "Ask" | "Show" | "Tell" | "YC" | "Startup"
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
