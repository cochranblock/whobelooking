// Unlicense — cochranblock.org
// Contributors: GotEmCoach, KOVA, Claude Opus 4.6
//! whobelooking — Two modes:
//! 1. Visitor ID: Cloudflare → rDNS → /24 neighbor scan → company ID.
//! 2. Contract Scout: SAM.gov + USASpending + SBIR load-balanced queries → sled cache → report.
//! One binary. Zero cloud.

use clap::Parser;

#[derive(Parser)]
#[command(name = "whobelooking", about = "Who's looking at your site? CF → rDNS → company ID.")]
enum Cmd {
    /// Scout federal contract opportunities across SAM.gov, USASpending, SBIR
    Scout {
        /// NAICS codes to search (comma-separated)
        #[arg(short, long, default_value = "541511,541512,541519,518210")]
        naics: String,
        /// Keyword filter
        #[arg(short, long)]
        keyword: Option<String>,
        /// SAM.gov API key (optional — skips SAM.gov if absent)
        #[arg(long, env = "SAM_GOV_API")]
        sam_key: Option<String>,
        /// Max award amount for USASpending filter
        #[arg(long, default_value = "500000")]
        max_amount: u64,
        /// Min award amount
        #[arg(long, default_value = "25000")]
        min_amount: u64,
    },
    /// Browse a URL with headless Chrome — screenshot + extract text
    #[cfg(feature = "browser")]
    Browse {
        /// URL to browse
        url: String,
        /// Output directory for screenshots
        #[arg(short, long, default_value = ".")]
        out: String,
        /// Wait seconds for page render (JS/WASM)
        #[arg(short, long, default_value = "3")]
        wait: u64,
        /// Extract page text (strip HTML, print to stdout)
        #[arg(long, default_value = "true")]
        extract: bool,
    },
    /// Batch browse — read URLs from file, one Chrome instance, screenshot + text for each
    #[cfg(feature = "browser")]
    Scrape {
        /// File with one URL per line
        #[arg(short, long, default_value = "/tmp/sam_unique_urls.txt")]
        file: String,
        /// Output directory
        #[arg(short, long, default_value = "sam_opps")]
        out: String,
        /// Wait seconds per page
        #[arg(short, long, default_value = "6")]
        wait: u64,
    },
    /// Pull US visitor IPs from Cloudflare GraphQL for a given date
    Pull {
        /// Date (YYYY-MM-DD), default today
        #[arg(short, long)]
        date: Option<String>,
        /// Cloudflare zone ID
        #[arg(short, long, env = "CF_ZONE_ID")]
        zone: String,
        /// Cloudflare API token
        #[arg(short, long, env = "CF_TOKEN")]
        token: String,
        /// Country filter (default US)
        #[arg(short, long, default_value = "US")]
        country: String,
        /// Min hits to include
        #[arg(short, long, default_value = "2")]
        min_hits: u32,
    },
    /// Reverse DNS lookup on a list of IPs (or stdin)
    Rdns {
        /// IPs to look up (or reads stdin)
        ips: Vec<String>,
    },
    /// Scan /24 neighbors of an IP for PTR records that reveal company names
    Neighbors {
        /// IP to scan neighbors of
        ip: String,
        /// Skip generic ISP hostnames
        #[arg(long, default_value = "true")]
        skip_isp: bool,
    },
    /// Full pipeline: pull → rdns → neighbor scan → report
    Report {
        /// Date (YYYY-MM-DD), default today
        #[arg(short, long)]
        date: Option<String>,
        /// Cloudflare zone ID
        #[arg(short, long, env = "CF_ZONE_ID")]
        zone: String,
        /// Cloudflare API token
        #[arg(short, long, env = "CF_TOKEN")]
        token: String,
        /// Country filter (default US)
        #[arg(short, long, default_value = "US")]
        country: String,
        /// Min hits to include
        #[arg(short, long, default_value = "2")]
        min_hits: u32,
        /// Scan /24 neighbors for company PTR records
        #[arg(long, default_value = "true")]
        scan_neighbors: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cmd = Cmd::parse();
    match cmd {
        Cmd::Scout { naics, keyword, sam_key, max_amount, min_amount } => {
            let codes: Vec<&str> = naics.split(',').map(|s| s.trim()).collect();
            scout::run(&codes, keyword.as_deref(), sam_key.as_deref(), min_amount, max_amount).await?;
        }
        #[cfg(feature = "browser")]
        Cmd::Browse { url, out, wait, extract } => {
            browse::run(&url, &out, wait, extract).await?;
        }
        #[cfg(feature = "browser")]
        Cmd::Scrape { file, out, wait } => {
            browse::scrape(&file, &out, wait).await?;
        }
        Cmd::Pull { date, zone, token, country, min_hits } => {
            let visitors = cf::pull(&zone, &token, date.as_deref(), &country, min_hits).await?;
            for v in &visitors {
                println!("{:<6} {}", v.hits, v.ip);
            }
            eprintln!("{} IPs pulled", visitors.len());
        }
        Cmd::Rdns { ips } => {
            let results = dns::rdns_batch(&ips).await;
            for (ip, rdns) in &results {
                println!("{:<42} {}", ip, rdns.as_deref().unwrap_or("-"));
            }
        }
        Cmd::Neighbors { ip, skip_isp } => {
            let results = dns::scan_neighbors(&ip, skip_isp).await?;
            for (neighbor_ip, hostname) in &results {
                println!("  {}  ->  {}", neighbor_ip, hostname);
            }
            if results.is_empty() {
                eprintln!("no company PTR records found in /24");
            }
        }
        Cmd::Report { date, zone, token, country, min_hits, scan_neighbors } => {
            report::run(&zone, &token, date.as_deref(), &country, min_hits, scan_neighbors).await?;
        }
    }
    Ok(())
}

mod scout {
    use serde::{Deserialize, Serialize};

    // === Common Open Opportunity Schema ===
    // 4 record types, each with fields that match their source data cleanly.
    // Stored in separate sled trees so queries don't mix concerns.

    /// Biddable opportunities — things you can respond to TODAY
    /// Sources: SAM.gov, Grants.gov, SBIR.gov
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct Bid {
        pub source: String,        // sam.gov | grants | sbir
        pub id: String,            // noticeId | oppNumber | solicitationId
        pub title: String,
        pub description: String,
        pub agency: String,
        pub naics: String,         // NAICS code or "grant" / "sbir"
        pub set_aside: String,     // SBA, SDVOSBC, 8A, etc. or ""
        pub posted: String,        // YYYY-MM-DD
        pub deadline: String,      // YYYY-MM-DD or ""
        pub url: String,
    }

    /// Past awards — who won what, competitive intel
    /// Sources: USASpending, SAM.gov Contract Awards
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct Award {
        pub source: String,        // usaspending | awards
        pub id: String,            // Award ID | contractId
        pub winner: String,        // company name
        pub description: String,
        pub amount: f64,
        pub agency: String,
        pub naics: String,
        pub date: String,          // award/start date
        pub url: String,
    }

    /// Early pipeline signals — RFIs, proposed rules, policy changes
    /// Sources: Federal Register, Regulations.gov
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct Signal {
        pub source: String,        // fedreg | regs
        pub id: String,            // document_number | documentId
        pub title: String,
        pub description: String,
        pub agency: String,
        pub doc_type: String,      // NOTICE | Rule | Proposed Rule
        pub date: String,
        pub url: String,
    }

    /// Labor rate benchmarks — what the market charges
    /// Source: CALC+
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct Rate {
        pub id: String,
        pub labor_category: String,
        pub vendor: String,
        pub sin: String,           // GSA SIN
        pub price: f64,            // ceiling rate $/hr
        pub education: String,
        pub experience: String,
    }

    /// Unified report container
    pub struct ScoutReport {
        pub bids: Vec<Bid>,
        pub awards: Vec<Award>,
        pub signals: Vec<Signal>,
        pub rates: Vec<Rate>,
        pub new_count: u32,
    }

    fn open_db() -> sled::Db {
        let dir = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join("whobelooking");
        sled::open(dir).expect("open sled db")
    }

    fn compress(data: &[u8]) -> Vec<u8> {
        zstd::encode_all(data, 3).unwrap_or_else(|_| data.to_vec())
    }

    fn decompress(data: &[u8]) -> Vec<u8> {
        zstd::decode_all(data).unwrap_or_else(|_| data.to_vec())
    }

    fn cache_bid(db: &sled::Db, b: &Bid) -> bool {
        let key = format!("bid:{}:{}", b.source, b.id);
        let val = compress(&serde_json::to_vec(b).unwrap());
        db.insert(&key, val).unwrap().is_none()
    }
    fn cache_award(db: &sled::Db, a: &Award) -> bool {
        let key = format!("award:{}:{}", a.source, a.id);
        let val = compress(&serde_json::to_vec(a).unwrap());
        db.insert(&key, val).unwrap().is_none()
    }
    fn cache_signal(db: &sled::Db, s: &Signal) -> bool {
        let key = format!("signal:{}:{}", s.source, s.id);
        let val = compress(&serde_json::to_vec(s).unwrap());
        db.insert(&key, val).unwrap().is_none()
    }
    fn cache_rate(db: &sled::Db, r: &Rate) -> bool {
        let key = format!("rate:{}", r.id);
        let val = compress(&serde_json::to_vec(r).unwrap());
        db.insert(&key, val).unwrap().is_none()
    }

    fn strip_html(s: &str) -> String {
        s.chars().fold((String::new(), false), |(mut out, in_tag), c| {
            match c {
                '<' => (out, true),
                '>' => (out, false),
                _ if !in_tag => { out.push(c); (out, false) }
                _ => (out, true)
            }
        }).0
    }

    /// Fetch full description text from a URL, return as string
    async fn enrich(client: &reqwest::Client, url: &str) -> String {
        if url.is_empty() || !url.starts_with("http") { return String::new(); }
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.get(url).send()
        ).await {
            Ok(Ok(resp)) => resp.text().await.unwrap_or_default(),
            _ => String::new(),
        }
    }

    /// Enrich a batch of bids — fetch full descriptions in parallel, cap concurrency
    async fn enrich_bids(bids: &mut [Bid], db: &sled::Db) {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();

        for b in bids.iter_mut() {
            // Skip if already enriched (description > 200 chars = probably full text)
            if b.description.len() > 200 { continue; }

            // Check sled for cached enrichment
            let ekey = format!("enriched:{}:{}", b.source, b.id);
            if let Some(cached) = db.get(&ekey).unwrap() {
                let text = String::from_utf8_lossy(&decompress(&cached)).to_string();
                if !text.is_empty() { b.description = text; continue; }
            }

            // SAM.gov: description field is a URL to full solicitation text
            if b.description.starts_with("http") {
                let full = enrich(&client, &b.description).await;
                if !full.is_empty() {
                    let clean = strip_html(&full);
                    let trimmed = if clean.len() > 2000 { clean[..2000].to_string() } else { clean };
                    let _ = db.insert(&ekey, compress(trimmed.as_bytes()));
                    b.description = trimmed;
                }
            }

            // Grants.gov: fetch full synopsis via fetchOpportunity (no auth)
            if b.source == "grants" && !b.id.is_empty() {
                let body = serde_json::json!({"oppId": b.id});
                let resp = client
                    .post("https://api.grants.gov/v1/api/fetchOpportunity")
                    .json(&body)
                    .send()
                    .await;
                if let Ok(resp) = resp {
                    if let Ok(val) = resp.json::<serde_json::Value>().await {
                        // data.synopsis.synopsisDesc has the full text
                        let desc = val["data"]["synopsis"]["synopsisDesc"]
                            .as_str()
                            .or_else(|| val["data"]["description"].as_str())
                            .unwrap_or("");
                        if !desc.is_empty() {
                            let clean = strip_html(desc);
                            let trimmed = if clean.len() > 2000 { clean[..2000].to_string() } else { clean };
                            let _ = db.insert(&ekey, compress(trimmed.as_bytes()));
                            b.description = trimmed;
                        }
                    }
                }
            }
        }
    }

    pub async fn run(naics: &[&str], keyword: Option<&str>, sam_key: Option<&str>, min_amount: u64, max_amount: u64) -> anyhow::Result<()> {
        let db = open_db();
        let mut rpt = ScoutReport { bids: vec![], awards: vec![], signals: vec![], rates: vec![], new_count: 0 };

        // === BIDS (things you can respond to) ===

        // SAM.gov Opportunities
        if let Some(key) = sam_key {
            eprintln!("[sam.gov] querying...");
            match sam::query(key, naics, keyword).await {
                Ok(bids) => {
                    eprintln!("[sam.gov] {} bids", bids.len());
                    for b in bids { if cache_bid(&db, &b) { rpt.new_count += 1; } rpt.bids.push(b); }
                }
                Err(e) => eprintln!("[sam.gov] error: {}", e),
            }
        } else {
            eprintln!("[sam.gov] skipped (no SAM_GOV_API)");
        }

        // Grants.gov
        let gr_kw = keyword.unwrap_or("cybersecurity");
        eprintln!("[grants] querying...");
        match grants::query(gr_kw).await {
            Ok(bids) => {
                eprintln!("[grants] {} bids", bids.len());
                for b in bids { if cache_bid(&db, &b) { rpt.new_count += 1; } rpt.bids.push(b); }
            }
            Err(e) => eprintln!("[grants] error: {}", e),
        }

        // SBIR.gov
        eprintln!("[sbir] querying...");
        match sbir::query(keyword.unwrap_or("cyber")).await {
            Ok(bids) => {
                eprintln!("[sbir] {} bids", bids.len());
                for b in bids { if cache_bid(&db, &b) { rpt.new_count += 1; } rpt.bids.push(b); }
            }
            Err(e) => eprintln!("[sbir] error: {}", e),
        }

        // === ENRICH BIDS — fetch full descriptions, compress, cache ===
        if !rpt.bids.is_empty() {
            eprintln!("[enrich] fetching full descriptions for {} bids...", rpt.bids.len());
            enrich_bids(&mut rpt.bids, &db).await;
            eprintln!("[enrich] done");
        }

        // === AWARDS (competitive intel) ===

        eprintln!("[usaspending] querying...");
        match usaspending::query(naics, min_amount, max_amount).await {
            Ok(awards) => {
                eprintln!("[usaspending] {} awards", awards.len());
                for a in awards { if cache_award(&db, &a) { rpt.new_count += 1; } rpt.awards.push(a); }
            }
            Err(e) => eprintln!("[usaspending] error: {}", e),
        }

        if let Some(key) = sam_key {
            eprintln!("[awards] querying...");
            match contract_awards::query(key, naics).await {
                Ok(awards) => {
                    eprintln!("[awards] {} awards", awards.len());
                    for a in awards { if cache_award(&db, &a) { rpt.new_count += 1; } rpt.awards.push(a); }
                }
                Err(e) => eprintln!("[awards] error: {}", e),
            }
        }

        // === SIGNALS (early pipeline) ===

        let sig_kw = keyword.unwrap_or("cybersecurity+software");
        eprintln!("[fedreg] querying...");
        match fedreg::query(sig_kw).await {
            Ok(sigs) => {
                eprintln!("[fedreg] {} signals", sigs.len());
                for s in sigs { if cache_signal(&db, &s) { rpt.new_count += 1; } rpt.signals.push(s); }
            }
            Err(e) => eprintln!("[fedreg] error: {}", e),
        }

        let reg_kw = keyword.unwrap_or("cybersecurity");
        eprintln!("[regs] querying...");
        match regulations::query(reg_kw).await {
            Ok(sigs) => {
                eprintln!("[regs] {} signals", sigs.len());
                for s in sigs { if cache_signal(&db, &s) { rpt.new_count += 1; } rpt.signals.push(s); }
            }
            Err(e) => eprintln!("[regs] error: {}", e),
        }

        // === RATES (pricing intel) ===

        let calc_kw = keyword.unwrap_or("software engineer");
        eprintln!("[calc] querying...");
        match calc::query(calc_kw).await {
            Ok(rates) => {
                eprintln!("[calc] {} rates", rates.len());
                for r in rates { if cache_rate(&db, &r) { rpt.new_count += 1; } rpt.rates.push(r); }
            }
            Err(e) => eprintln!("[calc] error: {}", e),
        }

        // === REPORT (gamified) ===

        let total = rpt.bids.len() + rpt.awards.len() + rpt.signals.len() + rpt.rates.len();

        // Score bids by match quality
        let match_keywords = ["cyber", "software", "rust", "edge", "ai", "cloud", "zero trust",
            "sbir", "single binary", "open source", "secure", "memory safe", "veteran"];

        fn score_bid(b: &Bid, keywords: &[&str]) -> u32 {
            let text = format!("{} {} {}", b.title, b.description, b.agency).to_lowercase();
            let mut s = 0u32;
            for kw in keywords { if text.contains(kw) { s += 10; } }
            if !b.set_aside.is_empty() { s += 15; }
            if b.set_aside.contains("SDVOSB") { s += 25; }
            if b.deadline.is_empty() || b.deadline.contains("rolling") { s += 5; }
            // Agency boost — orgs you've worked with or align to
            let good_agencies = ["darpa", "nsf", "navy", "air force", "army", "dhs", "cisa",
                "cyber", "dod", "defense", "veterans", "nist", "nasa"];
            for ga in good_agencies { if text.contains(ga) { s += 8; } }
            // NAICS boost — your codes
            let your_naics = ["541511", "541512", "541519", "518210", "541690"];
            if your_naics.iter().any(|n| b.naics.contains(n)) { s += 20; }
            // Title keyword boost — things you actually build
            let hot = ["software", "web", "application", "platform", "data", "api",
                "infrastructure", "system design", "custom", "development", "modernization"];
            for h in hot { if text.contains(h) { s += 5; } }
            s
        }

        fn score_icon(score: u32) -> &'static str {
            if score >= 50 { "[!!!]" }      // perfect match — drop everything
            else if score >= 30 { "[!! ]" }  // strong match — bid this week
            else if score >= 15 { "[!  ]" }  // worth a look
            else { "[   ]" }                 // low match
        }

        // Sort bids by score descending
        let mut scored_bids: Vec<(u32, &Bid)> = rpt.bids.iter().map(|b| (score_bid(b, &match_keywords), b)).collect();
        scored_bids.sort_by(|a, b| b.0.cmp(&a.0));

        println!("\n  LOOT TABLE — OPEN BIDS ({} found)", rpt.bids.len());
        println!("  {:<6} {:<10} {:<12} {:<48} {}", "Match", "Source", "Deadline", "Title", "Agency");
        println!("  {}", "-".repeat(115));
        for (score, b) in &scored_bids {
            let dl = if b.deadline.is_empty() { "rolling" } else { &b.deadline[..10.min(b.deadline.len())] };
            let title = if b.title.len() > 46 { &b.title[..46] } else { &b.title };
            println!("  {:<6} {:<10} {:<12} {:<48} {}", score_icon(*score), b.source, dl, title, b.agency);
        }

        // Awards — sorted by amount, show your weight class
        let mut sorted_awards = rpt.awards.clone();
        sorted_awards.sort_by(|a, b| b.amount.partial_cmp(&a.amount).unwrap_or(std::cmp::Ordering::Equal));

        println!("\n  SCOREBOARD — WHO'S WINNING ({} awards)", sorted_awards.len());
        println!("  {:<12} {:<12} {:<38} {}", "Amount", "NAICS", "Winner", "Agency");
        println!("  {}", "-".repeat(105));
        let mut your_range = 0u32;
        for a in &sorted_awards {
            let tier = if a.amount < 50000.0 { ">" } // micro — easy entry
                else if a.amount < 150000.0 { ">>" } // your sweet spot
                else if a.amount < 300000.0 { ">>>" }
                else { ">>>>" };
            if a.amount >= 25000.0 && a.amount <= 250000.0 { your_range += 1; }
            let winner = if a.winner.len() > 36 { &a.winner[..36] } else { &a.winner };
            let agency = if a.agency.len() > 30 { &a.agency[..30] } else { &a.agency };
            println!("  {:<2} ${:<10.0} {:<12} {:<38} {}", tier, a.amount, a.naics, winner, agency);
        }
        println!("  {} awards in your range ($25K-$250K)", your_range);

        // Pipeline — signals sorted by date
        println!("\n  RADAR — PIPELINE SIGNALS ({} detected)", rpt.signals.len());
        println!("  {:<8} {:<12} {:<58} {}", "Source", "Date", "Title", "Agency");
        println!("  {}", "-".repeat(105));
        for s in rpt.signals.iter().take(30) {
            let title = if s.title.len() > 56 { &s.title[..56] } else { &s.title };
            let date = if s.date.len() >= 10 { &s.date[..10] } else { &s.date };
            println!("  {:<8} {:<12} {:<58} {}", s.source, date, title, s.agency);
        }
        if rpt.signals.len() > 30 {
            println!("  ... +{} more", rpt.signals.len() - 30);
        }

        // Rates — your pricing intel
        println!("\n  MARKET RATES — WHAT THEY CHARGE ({} benchmarks)", rpt.rates.len());
        println!("  {:<10} {:<38} {}", "$/hr", "Labor Category", "Vendor");
        println!("  {}", "-".repeat(75));
        for r in &rpt.rates {
            let cat = if r.labor_category.len() > 36 { &r.labor_category[..36] } else { &r.labor_category };
            let vendor = if r.vendor.len() > 28 { &r.vendor[..28] } else { &r.vendor };
            println!("  ${:<9.2} {:<38} {}", r.price, cat, vendor);
        }

        // Summary
        let top_matches = scored_bids.iter().filter(|(s, _)| *s >= 30).count();
        println!("\n  === SCOUT SUMMARY ===");
        println!("  {} total records | {} new | {} cached", total, rpt.new_count, db.len());
        println!("  {} open bids | {} strong matches [!!+]", rpt.bids.len(), top_matches);
        println!("  {} competitors tracked | {} in your range", rpt.awards.len(), your_range);
        println!("  {} pipeline signals | {} rate benchmarks", rpt.signals.len(), rpt.rates.len());
        if top_matches > 0 {
            println!("\n  [!!!] = perfect match, bid NOW");
            println!("  [!! ] = strong match, bid this week");
            println!("  [!  ] = worth a look");
        }

        db.flush()?;
        Ok(())
    }

    /// Max records per source before stopping pagination
    const PAGE_CAP: usize = 200;

    mod usaspending {
        use super::{Award, PAGE_CAP};

        /// USASpending API — no auth, no rate limit
        /// Pagination: page param (1-indexed), limit per page, has_next_page in response
        pub async fn query(naics: &[&str], min_amount: u64, max_amount: u64) -> anyhow::Result<Vec<Award>> {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let naics_arr: Vec<String> = naics.iter().map(|s| s.to_string()).collect();
            let mut all = Vec::new();
            let mut page = 1u32;
            let page_size = 100;

            loop {
                let body = serde_json::json!({
                    "filters": {
                        "naics_codes": naics_arr,
                        "award_type_codes": ["A", "B", "C", "D"],
                        "time_period": [{"start_date": "2025-10-01", "end_date": "2026-12-31"}],
                        "award_amounts": [{"lower_bound": min_amount, "upper_bound": max_amount}]
                    },
                    "fields": ["Award ID", "Recipient Name", "Award Amount", "Description", "Start Date", "Awarding Agency"],
                    "limit": page_size,
                    "page": page,
                    "sort": "Start Date",
                    "order": "desc"
                });

                let resp: serde_json::Value = client
                    .post("https://api.usaspending.gov/api/v2/search/spending_by_award/")
                    .json(&body)
                    .send()
                    .await?
                    .json()
                    .await?;

                let results = resp["results"].as_array();
                let count = results.map(|a| a.len()).unwrap_or(0);
                let has_next = resp["page_metadata"]["hasNext"].as_bool().unwrap_or(false);

                if let Some(arr) = results {
                    for r in arr {
                        all.push(Award {
                            source: "usaspending".into(),
                            id: r["Award ID"].as_str().unwrap_or("").into(),
                            winner: r["Recipient Name"].as_str().unwrap_or("").into(),
                            description: r["Description"].as_str().unwrap_or("").into(),
                            amount: r["Award Amount"].as_f64().unwrap_or(0.0),
                            agency: r["Awarding Agency"].as_str().unwrap_or("").into(),
                            naics: "mixed".into(),
                            date: r["Start Date"].as_str().unwrap_or("").into(),
                            url: format!("https://www.usaspending.gov/award/{}", r["generated_internal_id"].as_str().unwrap_or("")),
                        });
                    }
                }

                page += 1;
                if count == 0 || !has_next || all.len() >= PAGE_CAP { break; }
            }
            Ok(all)
        }
    }

    mod sam {
        use super::Bid;

        pub async fn query(api_key: &str, naics: &[&str], keyword: Option<&str>) -> anyhow::Result<Vec<Bid>> {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let _naics_set: std::collections::HashSet<&str> = naics.iter().copied().collect();
            // Query each NAICS code separately, paginate until exhausted or 200 per code
            // Rate limit guard: skip codes fetched in last 24h (sled key: "sam_last:{code}")
            let mut all_opps = Vec::new();
            let page_size = 100;
            let db = super::open_db();
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            for code in naics {
                let cache_key = format!("sam_last:{}", code);
                if let Some(ts_bytes) = db.get(&cache_key).unwrap() {
                    let ts = u64::from_le_bytes(ts_bytes.as_ref().try_into().unwrap_or([0;8]));
                    if now - ts < 86400 {
                        eprintln!("[sam.gov] {} cached (<24h), skipping API call", code);
                        continue;
                    }
                }
                let mut offset = 0u32;
                loop {
                    let mut url = format!(
                        "https://api.sam.gov/opportunities/v2/search?api_key={}&limit={}&offset={}&postedFrom=01/01/2026&postedTo=12/31/2026&ncode={}",
                        api_key, page_size, offset, code
                    );
                    if let Some(kw) = keyword {
                        url.push_str(&format!("&q={}", kw));
                    }

                    let resp: serde_json::Value = client
                        .get(&url)
                        .send()
                        .await?
                        .json()
                        .await?;

                    let total = resp["totalRecords"].as_u64().unwrap_or(0);
                    let arr = resp["opportunitiesData"].as_array();
                    let page_count = arr.map(|a| a.len()).unwrap_or(0);

                    if let Some(arr) = arr {
                        for r in arr {
                            let set_aside_val = r["typeOfSetAsideDescription"].as_str()
                                .or_else(|| r["typeOfSetAside"].as_str())
                                .unwrap_or("");
                            all_opps.push(Bid {
                                source: "sam.gov".into(),
                                id: r["noticeId"].as_str().unwrap_or("").into(),
                                title: r["title"].as_str().unwrap_or("").into(),
                                description: r["description"].as_str().unwrap_or("").into(),
                                agency: r["fullParentPathName"].as_str().unwrap_or("").into(),
                                naics: r["naicsCode"].as_str().unwrap_or("").into(),
                                set_aside: set_aside_val.into(),
                                posted: r["postedDate"].as_str().unwrap_or("").into(),
                                deadline: r["responseDeadLine"].as_str().unwrap_or("").into(),
                                url: format!("https://sam.gov/opp/{}/view", r["noticeId"].as_str().unwrap_or("")),
                            });
                        }
                    }

                    offset += page_count as u32;
                    // One page per code — conserve rate limit, enrich via OSINT instead
                    if page_count == 0 || offset >= 100 || offset as u64 >= total {
                        break;
                    }
                }
                // Stamp this NAICS as fetched
                let _ = db.insert(&cache_key, &now.to_le_bytes());
                let _ = db.flush();
            }

            Ok(all_opps)
        }
    }

    mod sbir {
        use super::Bid;

        pub async fn query(keyword: &str) -> anyhow::Result<Vec<Bid>> {
            let client = reqwest::Client::new();
            let url = format!(
                "https://api.sbir.gov/solicitation?keyword={}&open=true&rows=25",
                keyword
            );

            let resp = client.get(&url).send().await?.text().await?;

            // SBIR API may return empty or HTML when under maintenance
            let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap_or(serde_json::Value::Array(vec![]));

            let results = parsed.as_array().map(|arr| {
                arr.iter().map(|r| Bid {
                    source: "sbir".into(),
                    id: r["solicitationId"].as_str().unwrap_or("").into(),
                    title: r["solicitationTitle"].as_str().unwrap_or("").into(),
                    description: r["sbpiAbstract"].as_str().unwrap_or("").into(),
                    agency: r["agency"].as_str().unwrap_or("").into(),
                    naics: "SBIR".into(),
                    set_aside: String::new(),
                    posted: r["openDate"].as_str().unwrap_or("").into(),
                    deadline: r["closeDate"].as_str().unwrap_or("").into(),
                    url: format!("https://www.sbir.gov/node/{}", r["solicitationId"].as_str().unwrap_or("")),
                }).collect()
            }).unwrap_or_default();

            Ok(results)
        }
    }

    mod fedreg {
        use super::{Signal, PAGE_CAP};

        /// Federal Register API v1 — no auth, no rate limit
        /// Pagination: per_page (max 1000), page param
        pub async fn query(keyword: &str) -> anyhow::Result<Vec<Signal>> {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let mut all = Vec::new();
            let mut page = 1u32;
            let per_page = 100;

            loop {
                let url = format!(
                    "https://www.federalregister.gov/api/v1/documents.json?conditions%5Bterm%5D={}&conditions%5Btype%5D%5B%5D=NOTICE&per_page={}&page={}&order=newest",
                    keyword, per_page, page
                );

                let resp: serde_json::Value = client.get(&url).send().await?.json().await?;
                let total = resp["count"].as_u64().unwrap_or(0);
                let results = resp["results"].as_array();
                let count = results.map(|a| a.len()).unwrap_or(0);

                if let Some(arr) = results {
                    for r in arr {
                        let agency = r["agencies"].as_array()
                            .and_then(|a| a.first())
                            .and_then(|a| a["name"].as_str())
                            .unwrap_or("");
                        all.push(Signal {
                            source: "fedreg".into(),
                            id: r["document_number"].as_str().unwrap_or("").into(),
                            title: r["title"].as_str().unwrap_or("").into(),
                            description: r["abstract"].as_str().unwrap_or("").into(),
                            agency: agency.into(),
                            doc_type: r["type"].as_str().unwrap_or("NOTICE").into(),
                            date: r["publication_date"].as_str().unwrap_or("").into(),
                            url: r["html_url"].as_str().unwrap_or("").into(),
                        });
                    }
                }

                page += 1;
                if count == 0 || all.len() >= PAGE_CAP || all.len() as u64 >= total { break; }
            }
            Ok(all)
        }
    }

    mod grants {
        use super::{Bid, PAGE_CAP};

        /// Grants.gov API v1 — no auth, POST to /v1/api/search2
        /// Pagination: startRecordNum in body, hitCount in response
        pub async fn query(keyword: &str) -> anyhow::Result<Vec<Bid>> {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let mut all = Vec::new();
            let mut start = 0u32;
            let rows = 100;

            loop {
                let body = serde_json::json!({
                    "keyword": keyword,
                    "oppStatuses": "posted",
                    "rows": rows,
                    "startRecordNum": start
                });

                let resp: serde_json::Value = client
                    .post("https://api.grants.gov/v1/api/search2")
                    .json(&body)
                    .send()
                    .await?
                    .json()
                    .await?;

                let hit_count = resp["data"]["hitCount"].as_u64().unwrap_or(0);
                let hits = resp["data"]["oppHits"].as_array();
                let count = hits.map(|a| a.len()).unwrap_or(0);

                if let Some(arr) = hits {
                    for r in arr {
                        all.push(Bid {
                            source: "grants".into(),
                            id: r["number"].as_str().unwrap_or("").into(),
                            title: r["title"].as_str().unwrap_or("").into(),
                            description: r["docType"].as_str().unwrap_or("").into(),
                            agency: r["agency"].as_str().unwrap_or("").into(),
                            naics: "grant".into(),
                            set_aside: String::new(),
                            posted: r["openDate"].as_str().unwrap_or("").into(),
                            deadline: r["closeDate"].as_str().unwrap_or("").into(),
                            url: format!("https://www.grants.gov/search-results-detail/{}", r["id"].as_str().unwrap_or("")),
                        });
                    }
                }

                start += count as u32;
                if count == 0 || all.len() >= PAGE_CAP || start as u64 >= hit_count { break; }
            }
            Ok(all)
        }
    }

    mod contract_awards {
        use super::Award;

        /// SAM.gov Contract Awards API v1 — same API key as opportunities
        /// Endpoint: https://api.sam.gov/contract-awards/v1/search
        /// Params: naicsCode (~ separated), dollarsObligated (range), dateSigned (range), limit, offset
        /// Rate limit: shares daily budget with opportunities API
        pub async fn query(api_key: &str, naics: &[&str]) -> anyhow::Result<Vec<Award>> {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let naics_param = naics.join("~");
            let url = format!(
                "https://api.sam.gov/contract-awards/v1/search?api_key={}&naicsCode={}&dollarsObligated=[25000.0,500000.0]&dateSigned=[01/01/2025,04/08/2026]&limit=25",
                api_key, naics_param
            );

            let resp: serde_json::Value = client.get(&url).send().await?.json().await?;

            let results = resp["awardSummary"].as_array().map(|arr| {
                arr.iter().map(|r| {
                    let core = &r["coreData"];
                    let awardee = &r["awardeeData"];
                    Award {
                        source: "awards".into(),
                        id: core["contractId"].as_str().unwrap_or("").into(),
                        winner: awardee["awardeeLegalBusinessName"].as_str().unwrap_or("").into(),
                        description: core["descriptionOfContractRequirement"].as_str().unwrap_or("").into(),
                        amount: core["dollarsObligated"].as_f64().unwrap_or(0.0),
                        agency: core["fundingAgencyName"].as_str().unwrap_or("").into(),
                        naics: core["naicsCode"].as_str().unwrap_or("").into(),
                        date: core["dateSigned"].as_str().unwrap_or("").into(),
                        url: "https://sam.gov/search?keywords=contract+awards".into(),
                    }
                }).collect()
            }).unwrap_or_default();

            Ok(results)
        }
    }

    mod regulations {
        use super::{Signal, PAGE_CAP};

        /// Regulations.gov API v4 — DEMO_KEY for testing, get real key from api.data.gov
        /// Pagination: page[size] max 250, page[number]
        pub async fn query(keyword: &str) -> anyhow::Result<Vec<Signal>> {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let mut all = Vec::new();
            let mut page = 1u32;
            let page_size = 100;

            loop {
                let url = format!(
                    "https://api.regulations.gov/v4/documents?filter[searchTerm]={}&page[size]={}&page[number]={}&sort=-postedDate",
                    keyword, page_size, page
                );

                let resp: serde_json::Value = client
                    .get(&url)
                    .header("X-Api-Key", "DEMO_KEY")
                    .send()
                    .await?
                    .json()
                    .await?;

                let data = resp["data"].as_array();
                let count = data.map(|a| a.len()).unwrap_or(0);
                let total = resp["meta"]["totalElements"].as_u64().unwrap_or(0);

                if let Some(arr) = data {
                    for r in arr {
                        let attrs = &r["attributes"];
                        all.push(Signal {
                            source: "regs".into(),
                            id: attrs["documentId"].as_str().unwrap_or("").into(),
                            title: attrs["title"].as_str().unwrap_or("").into(),
                            description: String::new(),
                            agency: attrs["agencyId"].as_str().unwrap_or("").into(),
                            doc_type: attrs["documentType"].as_str().unwrap_or("").into(),
                            date: attrs["postedDate"].as_str().unwrap_or("").into(),
                            url: format!("https://www.regulations.gov/document/{}", attrs["documentId"].as_str().unwrap_or("")),
                        });
                    }
                }

                page += 1;
                if count == 0 || all.len() >= PAGE_CAP || all.len() as u64 >= total { break; }
            }
            Ok(all)
        }
    }

    mod calc {
        use super::Rate;

        /// GSA CALC+ Labor Rates API v3 — no auth required
        /// Endpoint: https://api.gsa.gov/acquisition/calc/v3/api/ceilingrates/
        /// Params: keyword (min 2 chars), page, page_size
        /// Returns labor categories with ceiling rates from GSA schedules
        pub async fn query(keyword: &str) -> anyhow::Result<Vec<Rate>> {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let url = format!(
                "https://api.gsa.gov/acquisition/calc/v3/api/ceilingrates/?keyword={}&page=1&page_size=25",
                keyword
            );

            let resp: serde_json::Value = client.get(&url).send().await?.json().await?;

            let results = resp["hits"]["hits"].as_array().map(|arr| {
                arr.iter().map(|r| {
                    let s = &r["_source"];
                    Rate {
                        id: r["_id"].as_str().unwrap_or("").into(),
                        labor_category: s["labor_category"].as_str().unwrap_or("").into(),
                        vendor: s["vendor_name"].as_str().unwrap_or("").into(),
                        sin: s["sin"].as_str().unwrap_or("").into(),
                        price: s["current_price"].as_f64().unwrap_or(0.0),
                        education: s["education_level"].as_str().unwrap_or("").into(),
                        experience: s["min_years_experience"].as_str().unwrap_or("").into(),
                    }
                }).collect()
            }).unwrap_or_default();

            Ok(results)
        }
    }
}

mod cf {
    use serde::Deserialize;

    pub struct Visitor {
        pub ip: String,
        pub hits: u32,
    }

    #[derive(Deserialize)]
    struct GqlResponse {
        data: Option<GqlData>,
        errors: Option<Vec<GqlError>>,
    }
    #[derive(Deserialize)]
    struct GqlData {
        viewer: GqlViewer,
    }
    #[derive(Deserialize)]
    struct GqlViewer {
        zones: Vec<GqlZone>,
    }
    #[derive(Deserialize)]
    struct GqlZone {
        #[serde(rename = "httpRequestsAdaptiveGroups")]
        groups: Vec<GqlGroup>,
    }
    #[derive(Deserialize)]
    struct GqlGroup {
        count: u32,
        dimensions: GqlDimensions,
    }
    #[derive(Deserialize)]
    struct GqlDimensions {
        #[serde(rename = "clientIP")]
        client_ip: String,
    }
    #[derive(Deserialize)]
    struct GqlError {
        message: String,
    }

    pub async fn pull(zone: &str, token: &str, date: Option<&str>, country: &str, min_hits: u32) -> anyhow::Result<Vec<Visitor>> {
        let date = date.map(|d| d.to_string()).unwrap_or_else(|| {
            chrono_free_today()
        });

        let query = format!(
            r#"{{ viewer {{ zones(filter: {{zoneTag: "{}"}}) {{ httpRequestsAdaptiveGroups(limit: 200, filter: {{date: "{}", clientCountryName: "{}"}}, orderBy: [count_DESC]) {{ count dimensions {{ clientIP }} }} }} }} }}"#,
            zone, date, country
        );

        let client = reqwest::Client::new();
        let resp: GqlResponse = client
            .post("https://api.cloudflare.com/client/v4/graphql")
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({ "query": query }))
            .send()
            .await?
            .json()
            .await?;

        if let Some(errors) = resp.errors {
            if !errors.is_empty() {
                anyhow::bail!("CF API error: {}", errors[0].message);
            }
        }

        let data = resp.data.ok_or_else(|| anyhow::anyhow!("no data in response"))?;
        let zone = data.viewer.zones.into_iter().next().ok_or_else(|| anyhow::anyhow!("no zone data"))?;

        Ok(zone.groups
            .into_iter()
            .filter(|g| g.count >= min_hits)
            .map(|g| Visitor { ip: g.dimensions.client_ip, hits: g.count })
            .collect())
    }

    fn chrono_free_today() -> String {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let days = (secs / 86400) as i64;
        let y = (10000 * days + 14780) / 3652425;
        let doy = days - (365 * y + y / 4 - y / 100 + y / 400);
        let y = if doy < 0 { y - 1 } else { y };
        let doy = if doy < 0 { days - (365 * y + y / 4 - y / 100 + y / 400) } else { doy };
        let mi = (100 * doy + 52) / 3060;
        let month = mi + 3 - 12 * (mi / 10);
        let year = y + mi / 10;
        let day = doy - (mi * 306 + 5) / 10 + 1;
        format!("{:04}-{:02}-{:02}", year, month, day)
    }
}

mod dns {
    use hickory_resolver::TokioResolver;
    use hickory_resolver::lookup::ReverseLookup;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;

    const ISP_PATTERNS: &[&str] = &[
        "spectrum", "comcast", "verizon", "sbcglobal", "att.net", "cox",
        "cable", "pool-", "dsl", "dhcp", "static-", "cpe.", "res.",
        "biz.", "biz6.", "inf6.", "lightspeed", "hsd1.", "socal.",
        "nycmny", "rr.com", "charter.com", "alticeusa",
    ];

    fn make_resolver() -> TokioResolver {
        TokioResolver::builder_tokio()
            .unwrap_or_else(|_| TokioResolver::builder_with_config(Default::default(), Default::default()))
            .build()
    }

    fn hostname_from_lookup(lookup: ReverseLookup) -> Option<String> {
        lookup.iter().next().map(|n| n.to_string().trim_end_matches('.').to_string())
    }

    pub async fn rdns_batch(ips: &[String]) -> Vec<(String, Option<String>)> {
        let resolver = make_resolver();
        let mut results = Vec::new();
        for ip in ips {
            let addr = match IpAddr::from_str(ip) {
                Ok(a) => a,
                Err(_) => { results.push((ip.clone(), None)); continue; }
            };
            let rdns = tokio::time::timeout(Duration::from_secs(3), resolver.reverse_lookup(addr))
                .await
                .ok()
                .and_then(|r| r.ok())
                .and_then(hostname_from_lookup);
            results.push((ip.clone(), rdns));
        }
        results
    }

    pub async fn scan_neighbors(ip: &str, skip_isp: bool) -> anyhow::Result<Vec<(String, String)>> {
        let addr: IpAddr = ip.parse()?;
        let base = match addr {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!("{}.{}.{}", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(_) => anyhow::bail!("/24 scan only works on IPv4"),
        };

        let resolver = make_resolver();
        let mut results = Vec::new();

        for i in 1..=254u8 {
            let neighbor = format!("{}.{}", base, i);
            let neighbor_addr: IpAddr = neighbor.parse()?;
            let rdns = tokio::time::timeout(Duration::from_secs(2), resolver.reverse_lookup(neighbor_addr))
                .await
                .ok()
                .and_then(|r| r.ok())
                .and_then(hostname_from_lookup);

            if let Some(hostname) = rdns {
                let lower = hostname.to_lowercase();
                if skip_isp && ISP_PATTERNS.iter().any(|p| lower.contains(p)) {
                    continue;
                }
                // Skip generic reverse-DNS delegation entries
                if hostname.contains("in-addr.arpa") {
                    continue;
                }
                results.push((neighbor, hostname));
            }
        }
        Ok(results)
    }
}

mod report {
    use super::cf;
    use super::dns;

    pub async fn run(zone: &str, token: &str, date: Option<&str>, country: &str, min_hits: u32, scan_neighbors: bool) -> anyhow::Result<()> {
        eprintln!("pulling visitors from Cloudflare...");
        let visitors = cf::pull(zone, token, date, country, min_hits).await?;
        eprintln!("{} IPs above {} hits", visitors.len(), min_hits);

        let ips: Vec<String> = visitors.iter().map(|v| v.ip.clone()).collect();
        eprintln!("running rDNS on {} IPs...", ips.len());
        let rdns_results = dns::rdns_batch(&ips).await;

        println!("{:<6} {:<42} {:<55} {}", "Hits", "IP", "rDNS", "Neighbors");
        println!("{}", "=".repeat(130));

        for (v, (_ip, rdns)) in visitors.iter().zip(rdns_results.iter()) {
            let rdns_str = rdns.as_deref().unwrap_or("-");

            let mut neighbor_str = String::new();
            if scan_neighbors && rdns.is_none() {
                // Only scan /24 for IPv4 with no rDNS (most likely to reveal company)
                if !v.ip.contains(':') {
                    if let Ok(neighbors) = dns::scan_neighbors(&v.ip, true).await {
                        if !neighbors.is_empty() {
                            let names: Vec<&str> = neighbors.iter().map(|(_, h)| h.as_str()).take(3).collect();
                            neighbor_str = names.join(", ");
                        }
                    }
                }
            }

            println!("{:<6} {:<42} {:<55} {}", v.hits, v.ip, rdns_str, neighbor_str);
        }

        Ok(())
    }
}

#[cfg(feature = "browser")]
mod browse {
    use std::path::Path;
    use std::time::Duration;

    async fn browser_config() -> Result<chromiumoxide::BrowserConfig, String> {
        let builder = chromiumoxide::BrowserConfig::builder();
        match builder.build() {
            Ok(c) => return Ok(c),
            Err(e) if e.contains("Could not auto detect") => {}
            Err(e) => return Err(format!("browser config: {}", e)),
        }
        let dir = dirs::cache_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("chromiumoxide");
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {}", e))?;
        let fetcher = chromiumoxide::fetcher::BrowserFetcher::new(
            chromiumoxide::fetcher::BrowserFetcherOptions::builder()
                .with_path(&dir)
                .build()
                .map_err(|e| format!("fetcher opts: {}", e))?,
        );
        let info = fetcher.fetch().await.map_err(|e| format!("fetcher: {}", e))?;
        chromiumoxide::BrowserConfig::builder()
            .chrome_executable(info.executable_path)
            .build()
            .map_err(|e| format!("browser config: {}", e))
    }

    pub async fn run(url: &str, out_dir: &str, wait: u64, extract: bool) -> anyhow::Result<()> {
        let out = Path::new(out_dir);
        std::fs::create_dir_all(out)?;

        eprintln!("[browse] launching headless chrome...");
        let config = browser_config().await.map_err(|e| anyhow::anyhow!(e))?;
        let (browser, mut handler) = chromiumoxide::Browser::launch(config)
            .await
            .map_err(|e| anyhow::anyhow!("launch: {}", e))?;

        let handle = tokio::spawn(async move {
            while futures::StreamExt::next(&mut handler).await.is_some() {}
        });

        let page = browser.new_page("about:blank").await
            .map_err(|e| anyhow::anyhow!("new_page: {}", e))?;

        eprintln!("[browse] navigating to {}...", url);
        let _ = page.goto(url).await.map_err(|e| anyhow::anyhow!("goto: {}", e))?;
        tokio::time::sleep(Duration::from_secs(wait)).await;

        // Screenshot
        let slug: String = url.chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .take(60)
            .collect();
        let screenshot_path = out.join(format!("{}.png", slug));

        use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
        use chromiumoxide::page::ScreenshotParams;
        page.save_screenshot(
            ScreenshotParams::builder()
                .format(CaptureScreenshotFormat::Png)
                .full_page(true)
                .build(),
            &screenshot_path,
        ).await.map_err(|e| anyhow::anyhow!("screenshot: {}", e))?;
        eprintln!("[browse] screenshot saved: {}", screenshot_path.display());

        // Extract text — use innerText for clean rendered content (no CSS/JS noise)
        if extract {
            let text = page.evaluate("document.body.innerText").await
                .map_err(|e| anyhow::anyhow!("evaluate: {}", e))?
                .into_value::<String>()
                .unwrap_or_default();
            println!("{}", text);
        }

        let _ = browser.close().await;
        handle.abort();
        Ok(())
    }

    /// Batch scrape — one Chrome instance, 3 concurrent tabs, skip cached
    pub async fn scrape(url_file: &str, out_dir: &str, wait: u64) -> anyhow::Result<()> {
        let out = std::path::Path::new(out_dir);
        std::fs::create_dir_all(out)?;

        let urls: Vec<String> = std::fs::read_to_string(url_file)?
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();

        let total = urls.len();
        eprintln!("[scrape] {} URLs to process", total);

        // Skip already scraped
        let mut todo: Vec<String> = Vec::new();
        for url in &urls {
            let slug = url_to_slug(url);
            if out.join(format!("{}.txt", slug)).exists() {
                continue;
            }
            todo.push(url.clone());
        }
        eprintln!("[scrape] {} cached, {} remaining", total - todo.len(), todo.len());
        if todo.is_empty() { return Ok(()); }

        eprintln!("[scrape] launching headless chrome...");
        let config = browser_config().await.map_err(|e| anyhow::anyhow!(e))?;
        let (browser, mut handler) = chromiumoxide::Browser::launch(config)
            .await
            .map_err(|e| anyhow::anyhow!("launch: {}", e))?;

        let handle = tokio::spawn(async move {
            while futures::StreamExt::next(&mut handler).await.is_some() {}
        });

        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1)); // 1 tab — Chrome crashes with concurrent tabs
        let browser = std::sync::Arc::new(browser);
        let out = std::sync::Arc::new(out.to_path_buf());
        let done = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let remaining = todo.len();

        let mut handles = Vec::new();
        for url in todo {
            let sem = sem.clone();
            let browser = browser.clone();
            let out = out.clone();
            let done = done.clone();
            let h = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let slug = url_to_slug(&url);
                let txt_path = out.join(format!("{}.txt", slug));
                let png_path = out.join(format!("{}.png", slug));

                match scrape_one(&browser, &url, &png_path, &txt_path, wait).await {
                    Ok(()) => {}
                    Err(e) => eprintln!("[scrape] {}: {}", slug, e),
                }
                let n = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if n % 10 == 0 || n == remaining {
                    eprintln!("[scrape] {}/{}", n, remaining);
                }
            });
            handles.push(h);
        }

        for h in handles {
            let _ = h.await;
        }

        // Can't close Arc<Browser> directly — just abort the handler
        handle.abort();
        eprintln!("[scrape] done — {} files in {}", remaining, out.display());
        Ok(())
    }

    fn url_to_slug(url: &str) -> String {
        url.replace("https://sam.gov/opp/", "")
            .replace("/view", "")
            .replace("https://", "")
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' })
            .take(60)
            .collect()
    }

    async fn scrape_one(
        browser: &chromiumoxide::Browser,
        url: &str,
        png: &std::path::Path,
        txt: &std::path::Path,
        wait: u64,
    ) -> anyhow::Result<()> {
        let page = browser.new_page("about:blank").await
            .map_err(|e| anyhow::anyhow!("new_page: {}", e))?;
        let _ = page.goto(url).await.map_err(|e| anyhow::anyhow!("goto: {}", e))?;
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;

        // Screenshot
        use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
        use chromiumoxide::page::ScreenshotParams;
        let _ = page.save_screenshot(
            ScreenshotParams::builder()
                .format(CaptureScreenshotFormat::Png)
                .full_page(true)
                .build(),
            png,
        ).await;

        // Extract text — innerText gives clean rendered content
        if let Ok(val) = page.evaluate("document.body.innerText").await {
            let text = val.into_value::<String>().unwrap_or_default();
            let _ = std::fs::write(txt, &text);
        }

        let _ = page.close().await;
        Ok(())
    }
}
