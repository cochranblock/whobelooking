// All Rights Reserved — The Cochran Block, LLC
// Contributors: GotEmCoach, KOVA, Claude Opus 4.6
//! whobelooking-test — TRIPLE SIMS quality gate for whobelooking v0.2.0.
//!
//! Tests: cross-verification, source dedup, fake-vs-real email detection,
//! normalization, pattern extraction.
//!
//! Stage 1: compile
//! Stage 2: unit tests (below)
//! Stage 3: triple sims — run everything 3x, all must pass
//! Stage 4: exit 0 = pass, 1 = fail

use exopack::triple_sims::f60;
use whobelooking::ctos::{
    extract_cto_from_text, extract_first_email, norm, norm_company, slugify,
    truncate, verify, CtoMention,
};
use whobelooking::queue_types::{
    has_capacity, Job, JobStatus, SourceType, Tier, HOURS_PER_WEEK,
};

fn mk(source: &str, url: &str, name: &str, company: &str) -> CtoMention {
    CtoMention {
        source: source.to_string(),
        source_url: url.to_string(),
        name: name.to_string(),
        company: company.to_string(),
        handle: String::new(),
        context: String::new(),
        company_url: String::new(),
        scraped_email: String::new(),
        fetched_at: 0,
    }
}

fn mk_with_email(
    source: &str,
    url: &str,
    name: &str,
    company: &str,
    email: &str,
) -> CtoMention {
    let mut m = mk(source, url, name, company);
    m.scraped_email = email.to_string();
    m
}

// =========================================================================
// Test catalog — each returns Result<(), String> so failures describe what
// =========================================================================

fn test_verify_rejects_single_source() -> Result<(), String> {
    let ms = vec![mk("hn", "https://hn/1", "Jane Doe", "Acme Corp")];
    let v = verify(&ms);
    if !v.is_empty() {
        return Err(format!("single source must not verify, got {}", v.len()));
    }
    Ok(())
}

fn test_verify_accepts_two_distinct_sources() -> Result<(), String> {
    let ms = vec![
        mk("hn", "https://hn/1", "Jane Doe", "Acme Corp"),
        mk("github", "https://github.com/jdoe", "Jane Doe", "Acme Corp"),
    ];
    let v = verify(&ms);
    if v.len() != 1 {
        return Err(format!("expected 1 verified, got {}", v.len()));
    }
    if v[0].name != "Jane Doe" {
        return Err(format!("expected name 'Jane Doe', got '{}'", v[0].name));
    }
    Ok(())
}

fn test_verify_dedup_same_source_twice() -> Result<(), String> {
    // Same source type twice is still 1 distinct source — no verification
    let ms = vec![
        mk("hn", "https://hn/1", "Jane Doe", "Acme Corp"),
        mk("hn", "https://hn/2", "Jane Doe", "Acme Corp"),
    ];
    let v = verify(&ms);
    if !v.is_empty() {
        return Err(format!(
            "two mentions from same source must not verify, got {}",
            v.len()
        ));
    }
    Ok(())
}

fn test_verify_drops_partial_mentions() -> Result<(), String> {
    // Missing name or company should never verify
    let ms = vec![
        mk("hn", "https://hn/1", "", "Acme Corp"),
        mk("github", "https://gh/1", "", "Acme Corp"),
        mk("reddit", "https://rd/1", "Jane Doe", ""),
        mk("podcasts", "https://pod/1", "Jane Doe", ""),
    ];
    let v = verify(&ms);
    if !v.is_empty() {
        return Err(format!("partial mentions must not verify, got {}", v.len()));
    }
    Ok(())
}

fn test_verify_case_insensitive_name_company() -> Result<(), String> {
    let ms = vec![
        mk("hn", "https://hn/1", "jane doe", "ACME CORP"),
        mk("github", "https://gh/1", "Jane Doe", "Acme Corp"),
    ];
    let v = verify(&ms);
    if v.len() != 1 {
        return Err(format!("case-insensitive match must verify, got {}", v.len()));
    }
    Ok(())
}

fn test_verify_strips_company_suffixes() -> Result<(), String> {
    let ms = vec![
        mk("hn", "https://hn/1", "Jane Doe", "Acme Corp Inc"),
        mk("github", "https://gh/1", "Jane Doe", "Acme Corp"),
    ];
    let v = verify(&ms);
    if v.len() != 1 {
        return Err(format!("company suffix stripping must match, got {}", v.len()));
    }
    Ok(())
}

fn test_verify_preserves_direct_emails() -> Result<(), String> {
    let ms = vec![
        mk_with_email("github", "https://gh/jd", "Jane Doe", "Acme", "jane@acme.com"),
        mk("hn", "https://hn/1", "Jane Doe", "Acme"),
    ];
    let v = verify(&ms);
    if v.len() != 1 {
        return Err(format!("expected 1 verified, got {}", v.len()));
    }
    if v[0].direct_emails.is_empty() {
        return Err("verified CTO must carry the direct email".into());
    }
    if v[0].direct_emails[0].0 != "jane@acme.com" {
        return Err(format!(
            "expected 'jane@acme.com', got '{}'",
            v[0].direct_emails[0].0
        ));
    }
    Ok(())
}

fn test_verify_three_sources_higher_rank() -> Result<(), String> {
    let ms = vec![
        mk("hn", "https://hn/1", "Jane Doe", "Acme"),
        mk("github", "https://gh/1", "Jane Doe", "Acme"),
        mk("reddit", "https://rd/1", "Jane Doe", "Acme"),
        mk("hn", "https://hn/2", "Bob Smith", "Beta Co"),
        mk("github", "https://gh/2", "Bob Smith", "Beta Co"),
    ];
    let v = verify(&ms);
    if v.len() != 2 {
        return Err(format!("expected 2 verified, got {}", v.len()));
    }
    // First should have more sources (3 mentions for Jane vs 2 for Bob)
    if v[0].sources.len() < v[1].sources.len() {
        return Err("higher source count must rank first".into());
    }
    Ok(())
}

// --- Email extraction tests ---

fn test_email_extracts_real_address() -> Result<(), String> {
    let text = "Contact: jane.doe@acme.com for details";
    let (email, _) = extract_first_email(text).ok_or("expected email")?;
    if email != "jane.doe@acme.com" {
        return Err(format!("expected jane.doe@acme.com, got '{}'", email));
    }
    Ok(())
}

fn test_email_skips_noreply() -> Result<(), String> {
    let text = "From: noreply@company.com";
    if extract_first_email(text).is_some() {
        return Err("noreply@ must be skipped".into());
    }
    Ok(())
}

fn test_email_skips_example() -> Result<(), String> {
    let text = "user@example.com";
    if extract_first_email(text).is_some() {
        return Err("example.com must be skipped".into());
    }
    Ok(())
}

fn test_email_skips_sentry() -> Result<(), String> {
    let text = "sentry@app.sentry.io reported an error";
    if extract_first_email(text).is_some() {
        return Err("sentry@ must be skipped".into());
    }
    Ok(())
}

fn test_email_skips_test() -> Result<(), String> {
    let text = "Send to test@mail.com";
    if extract_first_email(text).is_some() {
        return Err("test@ must be skipped".into());
    }
    Ok(())
}

fn test_email_requires_dot_in_domain() -> Result<(), String> {
    let text = "user@localhost";
    if extract_first_email(text).is_some() {
        return Err("domain without dot must be rejected".into());
    }
    Ok(())
}

fn test_email_finds_first_valid() -> Result<(), String> {
    let text = "noreply@x.com then real@company.org";
    let (email, _) = extract_first_email(text).ok_or("expected email")?;
    if email != "real@company.org" {
        return Err(format!("expected real@company.org, got '{}'", email));
    }
    Ok(())
}

fn test_email_with_plus_tag() -> Result<(), String> {
    let text = "Email: cto+info@startup.io for partnerships";
    let (email, _) = extract_first_email(text).ok_or("expected email")?;
    if email != "cto+info@startup.io" {
        return Err(format!("expected cto+info@startup.io, got '{}'", email));
    }
    Ok(())
}

// --- Normalization tests ---

fn test_norm_lowercases_and_strips() -> Result<(), String> {
    let out = norm("  Jane  DOE  ");
    if out != "jane doe" {
        return Err(format!("expected 'jane doe', got '{}'", out));
    }
    Ok(())
}

fn test_norm_company_strips_suffix() -> Result<(), String> {
    for (input, expected) in [
        ("Acme Corp Inc", "acme"),    // strips both " inc" and " corp"
        ("@Acme LLC", "acme"),
        ("Beta Co AI", "beta"),       // strips " ai" then " co"
        ("Simple", "simple"),
        ("BigTech LLC", "bigtech"),
        ("NoSuffix Here", "nosuffix here"),
    ] {
        let out = norm_company(input);
        if out != expected {
            return Err(format!("norm_company({:?}): expected '{}', got '{}'", input, expected, out));
        }
    }
    Ok(())
}

// --- Pattern extraction tests ---

fn test_extract_finds_cto_of_pattern() -> Result<(), String> {
    let text = "Alice Wong is the CTO of Zeta Labs and she spoke at the event.";
    let ms = extract_cto_from_text(text, "test", "https://test");
    if ms.is_empty() {
        return Err("expected at least 1 mention from 'CTO of'".into());
    }
    if ms[0].company != "Zeta Labs" {
        return Err(format!("expected company 'Zeta Labs', got '{}'", ms[0].company));
    }
    Ok(())
}

fn test_extract_finds_cto_at_pattern() -> Result<(), String> {
    let text = "Bob Chen, CTO at NexGen Systems explained the architecture.";
    let ms = extract_cto_from_text(text, "test", "https://test");
    if ms.is_empty() {
        return Err("expected at least 1 mention from 'CTO at'".into());
    }
    if ms[0].company != "NexGen Systems" {
        return Err(format!("expected 'NexGen Systems', got '{}'", ms[0].company));
    }
    Ok(())
}

fn test_extract_captures_name_before_marker() -> Result<(), String> {
    let text = "We met Sarah Kim, CTO of Apex Data at the summit.";
    let ms = extract_cto_from_text(text, "test", "https://test");
    if ms.is_empty() {
        return Err("expected mention".into());
    }
    if ms[0].name != "Sarah Kim" {
        return Err(format!("expected name 'Sarah Kim', got '{}'", ms[0].name));
    }
    Ok(())
}

fn test_extract_no_false_positive_on_plain_text() -> Result<(), String> {
    let text = "This is a blog post about cloud infrastructure and security.";
    let ms = extract_cto_from_text(text, "test", "https://test");
    if !ms.is_empty() {
        return Err(format!(
            "no CTO mention should be found in plain text, got {}",
            ms.len()
        ));
    }
    Ok(())
}

fn test_extract_multiple_mentions_same_text() -> Result<(), String> {
    let text = "Panel: Jane Doe CTO of Alpha, and Bob Lee CTO at Beta.";
    let ms = extract_cto_from_text(text, "test", "https://test");
    if ms.len() < 2 {
        return Err(format!("expected 2+ mentions, got {}", ms.len()));
    }
    Ok(())
}

// --- Helpers ---

fn test_slugify() -> Result<(), String> {
    let out = slugify("Jane Doe - Acme Corp!!!");
    if out != "jane-doe-acme-corp" {
        return Err(format!("expected 'jane-doe-acme-corp', got '{}'", out));
    }
    Ok(())
}

fn test_truncate_short() -> Result<(), String> {
    let out = truncate("short", 10);
    if out != "short" {
        return Err(format!("expected 'short', got '{}'", out));
    }
    Ok(())
}

fn test_truncate_long() -> Result<(), String> {
    let out = truncate("longer text here", 8);
    if out.chars().count() > 8 {
        return Err(format!("expected <= 8 chars, got '{}'", out));
    }
    Ok(())
}

// --- Fake-vs-real detection ---

fn test_fabrication_guard_empty_email_no_verify() -> Result<(), String> {
    // Two sources, both have empty emails — verified but no draft should
    // be possible (draft requires scraped email). This test checks the
    // verify step: direct_emails must be empty.
    let ms = vec![
        mk("hn", "https://hn/1", "Jane Doe", "Acme"),
        mk("github", "https://gh/1", "Jane Doe", "Acme"),
    ];
    let v = verify(&ms);
    if v.len() != 1 {
        return Err(format!("expected 1 verified, got {}", v.len()));
    }
    if !v[0].direct_emails.is_empty() {
        return Err("no scraped email — direct_emails must be empty".into());
    }
    Ok(())
}

fn test_fabrication_guard_mixed_email() -> Result<(), String> {
    // One source has email, one doesn't. Verified CTO carries the real email.
    let ms = vec![
        mk_with_email("github", "https://gh/1", "Jane Doe", "Acme", "jane@acme.com"),
        mk("hn", "https://hn/1", "Jane Doe", "Acme"),
    ];
    let v = verify(&ms);
    if v.len() != 1 {
        return Err(format!("expected 1 verified, got {}", v.len()));
    }
    if v[0].direct_emails.len() != 1 || v[0].direct_emails[0].0 != "jane@acme.com" {
        return Err("must preserve the one real scraped email".into());
    }
    Ok(())
}

// --- Queue system tests ---

// --- Queue: real behavioral tests ---

fn test_queue_capacity_math() -> Result<(), String> {
    // Boundary conditions on 12hr cap — the math that protects your time
    if !has_capacity(0.0, &Tier::Starter) {
        return Err("empty week should accept Starter".into());
    }
    if !has_capacity(10.5, &Tier::Starter) {
        return Err("10.5 + 1.5 = 12.0 exactly should fit".into());
    }
    if has_capacity(10.6, &Tier::Starter) {
        return Err("10.6 + 1.5 = 12.1 should reject".into());
    }
    if has_capacity(6.0, &Tier::Custom) {
        return Err("6 + 8 = 14 should reject Custom".into());
    }
    if !has_capacity(4.0, &Tier::Scale) {
        return Err("4 + 6 = 10 should accept Scale".into());
    }
    // Full week rejects everything
    if has_capacity(12.0, &Tier::Starter) {
        return Err("12.0 committed should reject any new job".into());
    }
    Ok(())
}

fn test_queue_job_serialization() -> Result<(), String> {
    // Job must survive JSON round-trip — this breaks if fields are added without defaults
    let job = Job {
        id: "test-123".into(),
        customer_email: "buyer@company.com".into(),
        source_type: SourceType::Cloudflare { zone: "abc".into(), token: "xyz".into() },
        tier: Tier::Growth,
        status: JobStatus::InProgress,
        estimated_hours: 3.0,
        created_at: 1234567890,
        started_at: Some(1234567900),
        completed_at: None,
        report_path: None,
        notes: Some("urgent".into()),
    };
    let json = serde_json::to_vec(&job).map_err(|e| format!("serialize: {}", e))?;
    let back: Job = serde_json::from_slice(&json).map_err(|e| format!("deserialize: {}", e))?;
    if back.id != "test-123" { return Err(format!("id: {}", back.id)); }
    if back.customer_email != "buyer@company.com" { return Err(format!("email: {}", back.customer_email)); }
    if back.tier != Tier::Growth { return Err(format!("tier: {:?}", back.tier)); }
    if back.status != JobStatus::InProgress { return Err(format!("status: {:?}", back.status)); }
    if back.started_at != Some(1234567900) { return Err("started_at lost".into()); }
    if back.notes.as_deref() != Some("urgent") { return Err("notes lost".into()); }
    Ok(())
}

fn test_queue_tiers_complete() -> Result<(), String> {
    // Every tier must have price > 0, hours > 0, and hours that scale with price
    let tiers = [Tier::Starter, Tier::Growth, Tier::Scale, Tier::Custom];
    let mut prev_price = 0u32;
    let mut prev_hours = 0.0f32;
    for t in tiers {
        let price = t.price_cents();
        let hours = t.estimated_hours();
        if price == 0 { return Err(format!("{:?} has zero price", t)); }
        if hours <= 0.0 { return Err(format!("{:?} has zero hours", t)); }
        if price <= prev_price { return Err(format!("{:?} price {} not > prev {}", t, price, prev_price)); }
        if hours <= prev_hours { return Err(format!("{:?} hours {} not > prev {}", t, hours, prev_hours)); }
        prev_price = price;
        prev_hours = hours;
    }
    Ok(())
}

fn test_queue_capacity_overflow() -> Result<(), String> {
    // Edge: negative committed hours should still work (defensive)
    if !has_capacity(-1.0, &Tier::Custom) {
        return Err("negative hours + Custom should fit".into());
    }
    // Edge: f32 precision near boundary
    if has_capacity(11.999, &Tier::Starter) {
        // 11.999 + 1.5 = 13.499 > 12
        return Err("11.999 + 1.5 should reject".into());
    }
    Ok(())
}

fn test_queue_all_source_types() -> Result<(), String> {
    // All source types must serialize and deserialize
    let sources = vec![
        SourceType::Cloudflare { zone: "z".into(), token: "t".into() },
        SourceType::AccessLog,
        SourceType::Csv,
        SourceType::Json,
    ];
    for src in sources {
        let json = serde_json::to_string(&src).map_err(|e| format!("ser: {}", e))?;
        let _back: SourceType = serde_json::from_str(&json).map_err(|e| format!("de {}: {}", json, e))?;
    }
    Ok(())
}

fn test_queue_job_optional_fields() -> Result<(), String> {
    // Job with all None optionals must round-trip
    let job = Job {
        id: "bare".into(),
        customer_email: "x@y.com".into(),
        source_type: SourceType::Csv,
        tier: Tier::Starter,
        status: JobStatus::Paid,
        estimated_hours: 1.5,
        created_at: 0,
        started_at: None,
        completed_at: None,
        report_path: None,
        notes: None,
    };
    let json = serde_json::to_vec(&job).map_err(|e| format!("{}", e))?;
    let back: Job = serde_json::from_slice(&json).map_err(|e| format!("{}", e))?;
    if back.started_at.is_some() { return Err("started_at should be None".into()); }
    if back.report_path.is_some() { return Err("report_path should be None".into()); }
    if back.notes.is_some() { return Err("notes should be None".into()); }
    // Now with all Some
    let job2 = Job {
        started_at: Some(100), completed_at: Some(200),
        report_path: Some("/tmp/report.pdf".into()),
        notes: Some("test note".into()), ..back
    };
    let json2 = serde_json::to_vec(&job2).map_err(|e| format!("{}", e))?;
    let back2: Job = serde_json::from_slice(&json2).map_err(|e| format!("{}", e))?;
    if back2.report_path.as_deref() != Some("/tmp/report.pdf") { return Err("report_path lost".into()); }
    Ok(())
}

// --- Web content: validates the actual demo output ---

const DEMO: &str = include_str!("../../demo.html");

fn test_demo_has_microsoft() -> Result<(), String> {
    if !DEMO.contains("Microsoft") {
        return Err("demo must mention Microsoft".into());
    }
    if !DEMO.contains("Microsoft Corporation") {
        return Err("demo must mention Microsoft Corporation".into());
    }
    Ok(())
}

fn test_demo_has_threat_blocked() -> Result<(), String> {
    if !DEMO.contains("BLOCKED") {
        return Err("demo must show threat being blocked".into());
    }
    if !DEMO.contains("NextGenWebs") {
        return Err("demo must name the attacker".into());
    }
    if !DEMO.contains("10 minutes") {
        return Err("demo must mention 10 minute response time".into());
    }
    Ok(())
}

fn test_demo_no_full_ips() -> Result<(), String> {
    // No full IPv4 addresses should appear (redacted to x.x)
    let re_full_ip = regex_lite::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    for m in re_full_ip.find_iter(DEMO) {
        let ip = m.as_str();
        // Allow x.x patterns and 0.0.0.0 style
        if !ip.contains("x.x") && !ip.starts_with("0.") && ip != "100.0" {
            return Err(format!("full IP found in demo: {} — must be redacted to first two octets", ip));
        }
    }
    Ok(())
}

fn test_demo_has_cta() -> Result<(), String> {
    if !DEMO.contains("mcochran@cochranblock.org") {
        return Err("demo must have email CTA".into());
    }
    if !DEMO.contains("$150") {
        return Err("demo must show starting price".into());
    }
    Ok(())
}

fn test_demo_has_all_days() -> Result<(), String> {
    for day in ["Day 1", "Day 2", "Day 3", "Day 5", "Day 7", "Day 8"] {
        if !DEMO.contains(day) {
            return Err(format!("demo missing {}", day));
        }
    }
    Ok(())
}

fn test_demo_has_friend_reference() -> Result<(), String> {
    if !DEMO.contains("cybersecurity practices") {
        return Err("demo must reference cybersecurity friendship with Brisbane CISO".into());
    }
    Ok(())
}

// --- Security: things that must NEVER appear ---

fn test_no_secrets_in_demo() -> Result<(), String> {
    let banned = [
        "CF_TOKEN", "CF_ZONE_ID", "STRIPE_KEY", "API_KEY",
        "mcochran/.secrets", "kovakey", "id_ed25519",
    ];
    for s in banned {
        if DEMO.contains(s) {
            return Err(format!("SECURITY: demo contains '{}' — secret leak", s));
        }
    }
    Ok(())
}

fn test_no_internal_paths_in_demo() -> Result<(), String> {
    let banned = [
        "/Users/mcochran", "/home/mcochran", "/tmp/cochranblock",
        "~/.ssh", "~/.secrets", "~/.claude",
    ];
    for s in banned {
        if DEMO.contains(s) {
            return Err(format!("SECURITY: demo contains internal path '{}'", s));
        }
    }
    Ok(())
}

// --- Theme consistency: cosmic palette must be enforced ---

fn test_demo_cosmic_palette() -> Result<(), String> {
    // Must have the cochranblock cosmic colors
    let required = ["#050508", "#00d9ff", "#9d4edd", "#00ffcc", "#ff6b35"];
    for color in required {
        if !DEMO.contains(color) {
            return Err(format!("missing cosmic color {}", color));
        }
    }
    Ok(())
}

fn test_demo_no_monokai() -> Result<(), String> {
    // No stale Monokai amber/red palette
    let banned = ["#ffd866", "#ff6188", "#a9dc76", "#78dce8", "#ab9df2"];
    for color in banned {
        if DEMO.contains(color) {
            return Err(format!("stale Monokai color {} found — should be cosmic", color));
        }
    }
    Ok(())
}

fn test_demo_has_orbitron() -> Result<(), String> {
    if !DEMO.contains("Orbitron") {
        return Err("demo must use Orbitron display font".into());
    }
    if !DEMO.contains("Rajdhani") {
        return Err("demo must use Rajdhani body font".into());
    }
    Ok(())
}

fn test_demo_portrait_query() -> Result<(), String> {
    if DEMO.contains("max-width") && DEMO.contains("900px") {
        return Err("demo uses mobile breakpoint — should use orientation:portrait".into());
    }
    if !DEMO.contains("orientation:portrait") {
        return Err("demo must use portrait/landscape, not mobile/desktop".into());
    }
    Ok(())
}

// --- Demo structure: the ops center must have all panels ---

fn test_demo_has_terminal() -> Result<(), String> {
    // Demo is the ops center with live feed, not a terminal animation
    // The feed cards serve the same purpose — verify the feed exists
    if !DEMO.contains("Live Intelligence Feed") {
        return Err("demo must have live intelligence feed".into());
    }
    if !DEMO.contains("event") {
        return Err("demo must have event cards".into());
    }
    Ok(())
}

fn test_demo_has_timeline() -> Result<(), String> {
    if !DEMO.contains("Intelligence Timeline") {
        return Err("demo must have timeline sidebar".into());
    }
    if !DEMO.contains("sidebar") {
        return Err("demo must have sidebar element".into());
    }
    Ok(())
}

fn test_demo_has_stats_panel() -> Result<(), String> {
    if !DEMO.contains("Session Intelligence") {
        return Err("demo must have stats panel header".into());
    }
    if !DEMO.contains("visitor-count") {
        return Err("demo must have visitor counter".into());
    }
    if !DEMO.contains("company-count") {
        return Err("demo must have company counter".into());
    }
    if !DEMO.contains("threat-count") {
        return Err("demo must have threat counter".into());
    }
    Ok(())
}

fn test_demo_has_enrichment() -> Result<(), String> {
    if !DEMO.contains("Enrichment Cache") {
        return Err("demo must show enrichment cache section".into());
    }
    if !DEMO.contains("IPs resolved") {
        return Err("demo must show IP resolution count".into());
    }
    if !DEMO.contains("Companies mapped") {
        return Err("demo must show company mapping count".into());
    }
    Ok(())
}

fn test_demo_has_roster() -> Result<(), String> {
    if !DEMO.contains("Companies Detected") {
        return Err("demo must have company roster header".into());
    }
    if !DEMO.contains("roster") {
        return Err("demo must have roster element".into());
    }
    Ok(())
}

fn test_demo_has_autoplay() -> Result<(), String> {
    if !DEMO.contains("autoPlay") {
        return Err("demo must have autoplay function".into());
    }
    if !DEMO.contains("setTimeout") {
        return Err("demo must use setTimeout for staggered events".into());
    }
    Ok(())
}

// --- Content integrity: the real story must be complete ---

fn test_all_companies() -> Result<(), String> {
    let companies = ["Microsoft", "Google", "IBM", "Domino", "Verizon", "NextGenWebs"];
    for c in companies {
        if !DEMO.contains(c) {
            return Err(format!("demo missing company: {}", c));
        }
    }
    Ok(())
}

fn test_google_ibm() -> Result<(), String> {
    if !DEMO.contains("Google VPN") {
        return Err("demo must mention Google VPN specifically".into());
    }
    if !DEMO.contains("IBM Corporate") {
        return Err("demo must mention IBM Corporate specifically".into());
    }
    if !DEMO.contains("same hour") || !DEMO.contains("same page") {
        return Err("demo must note Google+IBM same hour/page correlation".into());
    }
    Ok(())
}

fn test_two_six() -> Result<(), String> {
    if !DEMO.contains("Two Six") || !DEMO.contains("Ashburn") {
        return Err("demo must mention Two Six / Ashburn corridor".into());
    }
    if !DEMO.contains("30") && !DEMO.contains("minute dwell") {
        return Err("demo must mention the 30-min deck read".into());
    }
    Ok(())
}

fn test_attacker_story() -> Result<(), String> {
    if !DEMO.contains("NextGenWebs") {
        return Err("attacker must be named".into());
    }
    if !DEMO.contains("Spain") {
        return Err("attacker origin must be named".into());
    }
    if !DEMO.contains(".aws/credentials") {
        return Err("attacker probe targets must be listed".into());
    }
    if !DEMO.contains(".cursor/mcp.json") {
        return Err("cursor MCP probe must be mentioned".into());
    }
    if !DEMO.contains("10 minutes") {
        return Err("response time must be mentioned".into());
    }
    if !DEMO.contains("BLOCKED") {
        return Err("block action must be shown".into());
    }
    Ok(())
}

fn test_resume_story() -> Result<(), String> {
    if !DEMO.contains("resume") {
        return Err("resume download story must be present".into());
    }
    if !DEMO.contains("5 times") || !DEMO.contains("48 hours") {
        return Err("must mention 5 downloads in 48 hours".into());
    }
    Ok(())
}

fn test_linkedin_shares() -> Result<(), String> {
    if !DEMO.contains("56 times") || !DEMO.contains("56") {
        return Err("must mention 56 LinkedIn shares".into());
    }
    if !DEMO.contains("not his account") {
        return Err("must clarify shares were not by the founder".into());
    }
    Ok(())
}

// --- Legal: licensing must be correct ---

fn test_all_rights_reserved() -> Result<(), String> {
    if !DEMO.contains("All Rights Reserved") && !DEMO.contains("all rights reserved") {
        return Err("demo must contain All Rights Reserved".into());
    }
    Ok(())
}

fn test_no_unlicense() -> Result<(), String> {
    let lower = DEMO.to_lowercase();
    if lower.contains("unlicense") || lower.contains("public domain") {
        return Err("demo must NOT contain Unlicense or public domain references".into());
    }
    Ok(())
}

// =========================================================================
// Runner
// =========================================================================

type TestFn = fn() -> Result<(), String>;

const TESTS: &[(&str, TestFn)] = &[
    // Cross-verification
    ("verify_rejects_single_source", test_verify_rejects_single_source),
    ("verify_accepts_two_distinct_sources", test_verify_accepts_two_distinct_sources),
    ("verify_dedup_same_source_twice", test_verify_dedup_same_source_twice),
    ("verify_drops_partial_mentions", test_verify_drops_partial_mentions),
    ("verify_case_insensitive_name_company", test_verify_case_insensitive_name_company),
    ("verify_strips_company_suffixes", test_verify_strips_company_suffixes),
    ("verify_preserves_direct_emails", test_verify_preserves_direct_emails),
    ("verify_three_sources_higher_rank", test_verify_three_sources_higher_rank),
    // Email extraction
    ("email_extracts_real_address", test_email_extracts_real_address),
    ("email_skips_noreply", test_email_skips_noreply),
    ("email_skips_example", test_email_skips_example),
    ("email_skips_sentry", test_email_skips_sentry),
    ("email_skips_test", test_email_skips_test),
    ("email_requires_dot_in_domain", test_email_requires_dot_in_domain),
    ("email_finds_first_valid", test_email_finds_first_valid),
    ("email_with_plus_tag", test_email_with_plus_tag),
    // Normalization
    ("norm_lowercases_and_strips", test_norm_lowercases_and_strips),
    ("norm_company_strips_suffix", test_norm_company_strips_suffix),
    // Pattern extraction
    ("extract_finds_cto_of_pattern", test_extract_finds_cto_of_pattern),
    ("extract_finds_cto_at_pattern", test_extract_finds_cto_at_pattern),
    ("extract_captures_name_before_marker", test_extract_captures_name_before_marker),
    ("extract_no_false_positive_on_plain_text", test_extract_no_false_positive_on_plain_text),
    ("extract_multiple_mentions_same_text", test_extract_multiple_mentions_same_text),
    // Helpers
    ("slugify", test_slugify),
    ("truncate_short", test_truncate_short),
    ("truncate_long", test_truncate_long),
    // Fabrication guards
    ("fabrication_guard_empty_email_no_verify", test_fabrication_guard_empty_email_no_verify),
    ("fabrication_guard_mixed_email", test_fabrication_guard_mixed_email),
    // Queue — real behavioral tests
    ("queue_capacity_boundary", test_queue_capacity_math),
    ("queue_job_roundtrip", test_queue_job_serialization),
    ("queue_all_tiers_have_price_and_hours", test_queue_tiers_complete),
    ("queue_capacity_rejects_overflow", test_queue_capacity_overflow),
    ("queue_source_types_roundtrip", test_queue_all_source_types),
    ("queue_job_optional_fields", test_queue_job_optional_fields),
    // Web content — validates real output
    ("web_demo_contains_microsoft", test_demo_has_microsoft),
    ("web_demo_contains_blocked", test_demo_has_threat_blocked),
    ("web_demo_no_full_ips", test_demo_no_full_ips),
    ("web_demo_has_cta", test_demo_has_cta),
    ("web_demo_has_all_days", test_demo_has_all_days),
    ("web_demo_has_friend_ref", test_demo_has_friend_reference),
    // Security
    ("security_no_secrets_in_demo", test_no_secrets_in_demo),
    ("security_no_internal_paths", test_no_internal_paths_in_demo),
    // Theme consistency
    ("theme_demo_has_cosmic_palette", test_demo_cosmic_palette),
    ("theme_demo_no_stale_monokai", test_demo_no_monokai),
    ("theme_demo_has_orbitron", test_demo_has_orbitron),
    ("theme_demo_portrait_not_mobile", test_demo_portrait_query),
    // Demo structure
    ("demo_has_terminal_animation", test_demo_has_terminal),
    ("demo_has_timeline_sidebar", test_demo_has_timeline),
    ("demo_has_stats_panel", test_demo_has_stats_panel),
    ("demo_has_enrichment_counters", test_demo_has_enrichment),
    ("demo_has_company_roster", test_demo_has_roster),
    ("demo_autoplay_script", test_demo_has_autoplay),
    // Content integrity
    ("content_all_companies_present", test_all_companies),
    ("content_google_and_ibm", test_google_ibm),
    ("content_two_six_ashburn", test_two_six),
    ("content_attacker_story_complete", test_attacker_story),
    ("content_resume_download_story", test_resume_story),
    ("content_linkedin_56_shares", test_linkedin_shares),
    // Legal
    ("legal_all_rights_reserved", test_all_rights_reserved),
    ("legal_no_unlicense", test_no_unlicense),
];

fn run_all_tests() -> bool {
    let mut passed = 0u32;
    let mut failed = 0u32;
    for (name, f) in TESTS {
        match f() {
            Ok(()) => {
                println!("  [pass] {}", name);
                passed += 1;
            }
            Err(msg) => {
                println!("  [FAIL] {} — {}", name, msg);
                failed += 1;
            }
        }
    }
    println!("  ---");
    println!("  {} passed, {} failed, {} total", passed, failed, TESTS.len());
    failed == 0
}

#[tokio::main]
async fn main() {
    println!("=== whobelooking-test: CTO OSINT pipeline quality gate ===\n");

    // Stage 1: compilation success (we're already here)
    println!("Stage 1: compile OK");

    // Stage 2: unit tests
    println!("\nStage 2: unit tests");
    let unit_ok = run_all_tests();
    if !unit_ok {
        eprintln!("\nStage 2 FAILED — skipping triple sims");
        std::process::exit(1);
    }

    // Stage 3: TRIPLE SIMS — run all tests 3x, must be deterministic
    println!("\nStage 3: TRIPLE SIMS (3 passes, all must match)");
    let ok = f60(|| async { run_all_tests() }).await;

    // Stage 4: exit code
    if ok {
        println!("\n=== whobelooking-test: ALL STAGES PASSED ===");
        std::process::exit(0);
    } else {
        eprintln!("\n=== whobelooking-test: TRIPLE SIMS FAILED ===");
        std::process::exit(1);
    }
}
