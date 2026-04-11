// Unlicense — cochranblock.org
// Contributors: GotEmCoach, KOVA, Claude Opus 4.6
//! whobelooking-test — TRIPLE SIMS quality gate for the CTO OSINT pipeline.
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
