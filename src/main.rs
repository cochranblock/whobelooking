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

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct Opportunity {
        pub source: String,
        pub id: String,
        pub title: String,
        pub description: String,
        pub amount: Option<f64>,
        pub agency: String,
        pub date: String,
        pub naics: String,
        pub url: String,
    }

    fn open_db() -> sled::Db {
        let dir = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join("whobelooking");
        sled::open(dir).expect("open sled db")
    }

    fn cache_put(db: &sled::Db, opp: &Opportunity) -> bool {
        let key = format!("{}:{}", opp.source, opp.id);
        let is_new = db.insert(&key, serde_json::to_vec(opp).unwrap()).unwrap().is_none();
        is_new
    }

    pub async fn run(naics: &[&str], keyword: Option<&str>, sam_key: Option<&str>, min_amount: u64, max_amount: u64) -> anyhow::Result<()> {
        let db = open_db();
        let mut all: Vec<Opportunity> = Vec::new();
        let mut new_count = 0u32;

        // --- USASpending (no auth, always available) ---
        eprintln!("[usaspending] querying...");
        match usaspending::query(naics, min_amount, max_amount).await {
            Ok(opps) => {
                eprintln!("[usaspending] {} results", opps.len());
                for o in opps {
                    if cache_put(&db, &o) { new_count += 1; }
                    all.push(o);
                }
            }
            Err(e) => eprintln!("[usaspending] error: {}", e),
        }

        // --- SAM.gov (needs API key) ---
        if let Some(key) = sam_key {
            eprintln!("[sam.gov] querying...");
            match sam::query(key, naics, keyword).await {
                Ok(opps) => {
                    eprintln!("[sam.gov] {} results", opps.len());
                    for o in opps {
                        if cache_put(&db, &o) { new_count += 1; }
                        all.push(o);
                    }
                }
                Err(e) => eprintln!("[sam.gov] error: {}", e),
            }
        } else {
            eprintln!("[sam.gov] skipped (no SAM_GOV_API)");
        }

        // --- SBIR.gov (no auth) ---
        eprintln!("[sbir] querying...");
        match sbir::query(keyword.unwrap_or("cyber")).await {
            Ok(opps) => {
                eprintln!("[sbir] {} results", opps.len());
                for o in opps {
                    if cache_put(&db, &o) { new_count += 1; }
                    all.push(o);
                }
            }
            Err(e) => eprintln!("[sbir] error: {}", e),
        }

        // --- Report ---
        let kw = keyword.unwrap_or("");
        let filtered: Vec<&Opportunity> = if kw.is_empty() {
            all.iter().collect()
        } else {
            let kw_lower = kw.to_lowercase();
            all.iter().filter(|o| {
                o.title.to_lowercase().contains(&kw_lower) ||
                o.description.to_lowercase().contains(&kw_lower)
            }).collect()
        };

        println!("\n{:<12} {:<12} {:<10} {:<50} {}", "Source", "Amount", "NAICS", "Title", "Agency");
        println!("{}", "=".repeat(120));
        for o in &filtered {
            let amt = o.amount.map(|a| format!("${:.0}", a)).unwrap_or_else(|| "-".into());
            let title = if o.title.len() > 48 { &o.title[..48] } else { &o.title };
            println!("{:<12} {:<12} {:<10} {:<50} {}", o.source, amt, o.naics, title, o.agency);
        }
        println!("\n{} total | {} new | {} cached", all.len(), new_count, db.len());
        db.flush()?;
        Ok(())
    }

    mod usaspending {
        use super::Opportunity;

        pub async fn query(naics: &[&str], min_amount: u64, max_amount: u64) -> anyhow::Result<Vec<Opportunity>> {
            let client = reqwest::Client::new();
            let naics_arr: Vec<String> = naics.iter().map(|s| s.to_string()).collect();
            let body = serde_json::json!({
                "filters": {
                    "naics_codes": naics_arr,
                    "award_type_codes": ["A", "B", "C", "D"],
                    "time_period": [{
                        "start_date": "2025-10-01",
                        "end_date": "2026-12-31"
                    }],
                    "award_amounts": [{
                        "lower_bound": min_amount,
                        "upper_bound": max_amount
                    }]
                },
                "fields": ["Award ID", "Recipient Name", "Award Amount", "Description", "Start Date", "Awarding Agency"],
                "limit": 25,
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

            let results = resp["results"].as_array().map(|arr| {
                arr.iter().map(|r| Opportunity {
                    source: "usaspending".into(),
                    id: r["Award ID"].as_str().unwrap_or("").into(),
                    title: r["Recipient Name"].as_str().unwrap_or("").into(),
                    description: r["Description"].as_str().unwrap_or("").into(),
                    amount: r["Award Amount"].as_f64(),
                    agency: r["Awarding Agency"].as_str().unwrap_or("").into(),
                    date: r["Start Date"].as_str().unwrap_or("").into(),
                    naics: "mixed".into(),
                    url: format!("https://www.usaspending.gov/award/{}", r["generated_internal_id"].as_str().unwrap_or("")),
                }).collect()
            }).unwrap_or_default();

            Ok(results)
        }
    }

    mod sam {
        use super::Opportunity;

        pub async fn query(api_key: &str, naics: &[&str], keyword: Option<&str>) -> anyhow::Result<Vec<Opportunity>> {
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
                            all_opps.push(Opportunity {
                                source: "sam.gov".into(),
                                id: r["noticeId"].as_str().unwrap_or("").into(),
                                title: r["title"].as_str().unwrap_or("").into(),
                                description: r["description"].as_str().unwrap_or("").into(),
                                amount: None,
                                agency: r["fullParentPathName"].as_str().unwrap_or("").into(),
                                date: r["postedDate"].as_str().unwrap_or("").into(),
                                naics: r["naicsCode"].as_str().unwrap_or("").into(),
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
        use super::Opportunity;

        pub async fn query(keyword: &str) -> anyhow::Result<Vec<Opportunity>> {
            let client = reqwest::Client::new();
            let url = format!(
                "https://api.sbir.gov/solicitation?keyword={}&open=true&rows=25",
                keyword
            );

            let resp = client.get(&url).send().await?.text().await?;

            // SBIR API may return empty or HTML when under maintenance
            let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap_or(serde_json::Value::Array(vec![]));

            let results = parsed.as_array().map(|arr| {
                arr.iter().map(|r| Opportunity {
                    source: "sbir".into(),
                    id: r["solicitationId"].as_str().unwrap_or("").into(),
                    title: r["solicitationTitle"].as_str().unwrap_or("").into(),
                    description: r["sbpiAbstract"].as_str().unwrap_or("").into(),
                    amount: None,
                    agency: r["agency"].as_str().unwrap_or("").into(),
                    date: r["openDate"].as_str().unwrap_or("").into(),
                    naics: "SBIR".into(),
                    url: format!("https://www.sbir.gov/node/{}", r["solicitationId"].as_str().unwrap_or("")),
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
