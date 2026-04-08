// Unlicense — cochranblock.org
// Contributors: GotEmCoach, KOVA, Claude Opus 4.6
//! whobelooking — Cloudflare visitor → rDNS → /24 neighbor scan → company ID.
//! One binary. Zero cloud. Know who's looking at your site.

use clap::Parser;

#[derive(Parser)]
#[command(name = "whobelooking", about = "Who's looking at your site? CF → rDNS → company ID.")]
enum Cmd {
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
        let days = secs / 86400;
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
