// All Rights Reserved — The Cochran Block, LLC
// Contributors: GotEmCoach, KOVA, Claude Opus 4.6
//! whobelooking — Visitor intelligence platform.
//!
//! - Visitor ID: Cloudflare → rDNS → /24 neighbor scan → company ID.
//! - Contract Scout: SAM.gov + USASpending + SBIR load-balanced queries → sled cache → report.
//!
//! One binary. Zero cloud.

use clap::Parser;
#[cfg(feature = "browser")]
use clap::Subcommand;

use whobelooking::crypto;
use whobelooking::orders;
#[cfg(feature = "serve")]
mod ipc;
mod logs;
#[cfg(feature = "serve")]
mod otel;
mod queue;
#[cfg(feature = "serve")]
mod web;

// Gemini Man pattern — atomic binary replacement via PID lockfile.
// Only the `serve` arm uses these; gating keeps the default-features build
// warning-free without adding `#[allow(dead_code)]` everywhere.
#[cfg(feature = "serve")]
fn pid_path() -> std::path::PathBuf {
    let base = dirs::data_local_dir().unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
    let dir = base.join("whobelooking");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("pid")
}

#[cfg(feature = "serve")]
fn lockfile_path() -> std::path::PathBuf {
    let base = dirs::data_local_dir().unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
    let dir = base.join("whobelooking");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("pid.lock")
}

#[cfg(feature = "serve")]
fn read_old_pid() -> Option<u32> {
    std::fs::read_to_string(pid_path())
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

#[cfg(feature = "serve")]
fn write_pid() {
    let _ = std::fs::write(pid_path(), std::process::id().to_string());
}

/// Hold an exclusive `flock` on `pid.lock` for the lifetime of the returned
/// guard. Two `serve` processes starting concurrently can't both win — the
/// second `try_write_lock()` returns `WouldBlock`, and the loser exits
/// cleanly instead of corrupting the PID file mid-write.
///
/// Implemented over `fd-lock` so the syscall stays out of our `unsafe` budget.
#[cfg(feature = "serve")]
struct PidLock {
    // Guard must be declared first — Rust drops fields in forward declaration
    // order, so _guard (which calls flock LOCK_UN) must run before _file closes
    // the fd. If _file drops first the fd is invalid when the guard runs.
    _guard: Option<fd_lock::RwLockWriteGuard<'static, std::fs::File>>,
    _file: Box<fd_lock::RwLock<std::fs::File>>,
}

#[cfg(feature = "serve")]
fn acquire_pid_lock() -> std::io::Result<Option<PidLock>> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(lockfile_path())?;
    let mut lock = Box::new(fd_lock::RwLock::new(f));
    // Extend the lifetime of the guard to the heap-pinned RwLock's lifetime.
    // Safety justification: we keep the box alive in the same struct as the
    // guard, dropped guard-first, lock-second.  But this is `unsafe` and
    // we're in main.rs (not lib.rs which has #[forbid(unsafe_code)]).
    let lock_ptr: *mut fd_lock::RwLock<std::fs::File> = lock.as_mut();
    // SAFETY: the box is owned by `PidLock` alongside the guard; field-drop
    // order is guard-first then file, so the borrow remains valid until drop.
    let lock_ref: &'static mut fd_lock::RwLock<std::fs::File> = unsafe { &mut *lock_ptr };
    match lock_ref.try_write() {
        Ok(guard) => Ok(Some(PidLock {
            _file: lock,
            _guard: Some(guard),
        })),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(feature = "serve")]
fn kill_old(pid: u32) {
    #[cfg(unix)]
    {
        use std::process::Command;
        use std::time::{Duration, Instant};

        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .output();
        tracing::info!("sent SIGTERM to old PID {}", pid);

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let alive = Command::new("kill")
                .arg("-0")
                .arg(pid.to_string())
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !alive {
                tracing::info!("old PID {} exited cleanly", pid);
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(pid.to_string())
            .output();
        tracing::warn!("sent SIGKILL to old PID {} (didn't exit in 5s)", pid);
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[derive(Parser)]
#[command(
    name = "whobelooking",
    about = "Who's looking at your site? CF → rDNS → company ID."
)]
enum Cmd {
    /// Start the web server (whobelooking.org)
    #[cfg(feature = "serve")]
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "8082", env = "WBL_PORT")]
        port: u16,
    },
    /// List all jobs in the queue
    Queue,
    /// Pop the next pending job
    Pop,
    /// Show today's visits (or N days ago) — IP/path/count/timing.
    #[cfg(feature = "serve")]
    Visits {
        /// 0 = today, 1 = yesterday, etc.
        #[arg(short, long, default_value = "0")]
        days_ago: u64,
        /// Output format: text (grouped by IP, default) or json.
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    /// Probe whether the IPC socket is alive (returns server PID).
    #[cfg(feature = "serve")]
    Ping,
    /// Export the captured-paths corpus from the visits tree (input for the surface-scan WASM).
    #[cfg(feature = "serve")]
    Corpus {
        /// Output format: text (one path per line, default), json (with hit counts).
        #[arg(short, long, default_value = "text")]
        format: String,
        /// Output file. Defaults to stdout.
        #[arg(short, long)]
        output: Option<String>,
        /// Minimum hit count to include (filters one-off oddities).
        #[arg(long, default_value = "1")]
        min_hits: u64,
        /// Include only paths that look like attack/probe candidates (skip plain /, /robots.txt, /favicon.ico).
        #[arg(long)]
        attack_only: bool,
    },
    /// Atomic order queue — list, approve, reject, mark ready, audit.
    /// Replaces the old `mv pending/x approved/x` filesystem workflow.
    Order {
        #[command(subcommand)]
        op: OrderOp,
    },
    /// Mark a job as complete
    Done {
        /// Job ID
        id: String,
        /// Path to report file
        #[arg(short, long)]
        report: Option<String>,
    },
    /// Mark a job as delivered
    Deliver {
        /// Job ID
        id: String,
    },
    /// Decrypt a credential blob (from email) using your local key
    Decrypt {
        /// The base64 encrypted blob
        blob: String,
    },
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
    /// Benchmark a URL — render performance metrics via Chrome DevTools Protocol
    #[cfg(feature = "browser")]
    Perf {
        /// URL to benchmark
        url: String,
        /// Wait seconds for page render
        #[arg(short, long, default_value = "5")]
        wait: u64,
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
        /// Emulate mobile viewport (390x844 iPhone 14)
        #[arg(long)]
        mobile: bool,
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
    /// Render a URL or local HTML file to PDF via headless Chrome (CDP printToPDF)
    #[cfg(feature = "browser")]
    Pdf {
        /// URL (https://...) or path to local HTML file
        input: String,
        /// Output PDF path
        #[arg(short, long, default_value = "out.pdf")]
        out: String,
        /// Wait seconds for page render before printing
        #[arg(short, long, default_value = "2")]
        wait: u64,
        /// Landscape orientation
        #[arg(long)]
        landscape: bool,
        /// Print background colors/images
        #[arg(long, default_value = "true")]
        background: bool,
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
    /// RDAP whois lookup on a list of IPs (or stdin) — org / netname / country, with on-disk cache
    Rdap {
        /// IPs to look up (or reads stdin)
        ips: Vec<String>,
        /// Output as JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Parse base log files (`visit ip=…` lines), aggregate per-IP, classify, JSON to stdout
    ParseLogs {
        /// Log file paths (whobelooking-style `visit ip=…` lines)
        files: Vec<String>,
        /// Window in hours (relative to now); 0 = all
        #[arg(long, default_value = "48")]
        hours: u64,
    },
    /// Pull last N hours of CF GraphQL data for every zone the token can see (24h chunks)
    CfFleet {
        /// Cloudflare API token
        #[arg(short, long, env = "CF_TOKEN")]
        token: String,
        /// Window in hours
        #[arg(long, default_value = "48")]
        hours: u64,
        /// Output JSON path
        #[arg(short, long, default_value = "/tmp/wbl-cf-fleet.json")]
        out: String,
    },
    /// Enrich a list of IPs across all CF zones (httpRequestsAdaptiveGroups + firewallEventsAdaptive)
    CfEnrich {
        /// IPs to enrich (or reads stdin)
        ips: Vec<String>,
        /// Cloudflare API token
        #[arg(short, long, env = "CF_TOKEN")]
        token: String,
        /// Window in hours
        #[arg(long, default_value = "48")]
        hours: u64,
        /// Output JSON path
        #[arg(short, long, default_value = "/tmp/wbl-cf-enriched.json")]
        out: String,
    },
    /// Parse a log file and render a standalone HTML intelligence report (same pipeline as /try).
    Render {
        /// Path to a log file (any supported format: nginx, CF JSONL/CSV, W3C, HAProxy, syslog, …)
        file: String,
        /// Output path (default: <file>.html)
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Detect column types in a log/CSV file (uses the same WASM-shippable detector as `/detect`).
    Detect {
        /// Path to a log / CSV / TSV file
        file: String,
        /// Max rows to sample for column-type voting
        #[arg(long, default_value = "256")]
        max_rows: u32,
        /// Output as JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Full intel pipeline: parse base logs + CF enrich + rDNS + RDAP → redacted & unredacted HTML
    Intel {
        /// Directory containing base log files (whobelooking + ireducefraud + cochranblock + …)
        #[arg(long, default_value = "/tmp/wbl-baselogs")]
        baselogs_dir: String,
        /// Cloudflare API token
        #[arg(short, long, env = "CF_TOKEN")]
        token: String,
        /// Window in hours
        #[arg(long, default_value = "48")]
        hours: u64,
        /// Output directory for `intel.unredacted.html` and `intel.redacted.html`
        #[arg(short, long, default_value = "/tmp/wbl-intel")]
        out: String,
    },
    /// Automated diagnostic surface area scan — probe 140+ attack paths against a URL
    Scan {
        /// Target URL (e.g. https://example.com)
        url: String,
        /// Output as JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Scan /24 neighbors of an IP for PTR records that reveal company names
    Neighbors {
        /// IP to scan neighbors of
        ip: String,
        /// Skip generic ISP hostnames
        #[arg(long, default_value = "true")]
        skip_isp: bool,
    },
    /// Cross-verified CTO OSINT scout — pull, verify, draft
    #[cfg(feature = "browser")]
    Ctos {
        #[command(subcommand)]
        op: CtosOp,
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

#[derive(clap::Subcommand)]
enum OrderOp {
    /// List orders, newest first
    List {
        /// Filter by state: pending, approved, rejected, ready
        #[arg(long)]
        state: Option<String>,
    },
    /// Show one order plus its full audit history
    Show {
        /// Order id
        id: String,
    },
    /// Pending → Approved
    Approve {
        id: String,
        #[arg(long, default_value = "operator")]
        actor: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Pending|Approved|Ready → Rejected
    Reject {
        id: String,
        #[arg(long, default_value = "operator")]
        actor: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Approved → Ready (call after copying report.pdf into the blob dir)
    Ready {
        id: String,
        #[arg(long, default_value = "operator")]
        actor: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Tail the most-recent audit events (across all orders)
    Audit {
        /// Optional order id to filter to
        id: Option<String>,
        #[arg(long, default_value = "20")]
        limit: usize,
    },
}

#[cfg(feature = "browser")]
#[derive(Subcommand)]
enum CtosOp {
    /// Pull CTO mentions from HN, YC, GitHub, Reddit, podcasts
    Pull {
        /// Source filter: hn, yc, github, reddit, podcasts, all
        #[arg(short, long, default_value = "all")]
        source: String,
        /// Optional keyword override
        #[arg(short, long)]
        keyword: Option<String>,
    },
    /// Show CTOs seen in 2+ distinct sources (same name + company)
    Verified {
        /// Visit company URLs observed in mentions and extract real emails
        #[arg(long)]
        scrape_emails: bool,
    },
    /// Write markdown drafts for verified CTOs that have scraped emails.
    /// Skips any entry without a real scraped email — never derives.
    Draft {
        /// Output directory
        #[arg(short, long, default_value = "cto_drafts")]
        out: String,
    },
}

fn run_order_op(op: OrderOp) -> anyhow::Result<()> {
    use orders::{OrderState, Store};
    let store = Store::open()?;
    match op {
        OrderOp::List { state } => {
            let want = state
                .as_deref()
                .map(|s| match s.to_ascii_lowercase().as_str() {
                    "pending" => Some(OrderState::Pending),
                    "approved" => Some(OrderState::Approved),
                    "rejected" => Some(OrderState::Rejected),
                    "ready" => Some(OrderState::Ready),
                    _ => None,
                });
            let orders = store.list_all()?;
            let filtered: Vec<_> = match want {
                Some(Some(s)) => orders.into_iter().filter(|o| o.state == s).collect(),
                Some(None) => {
                    eprintln!("unknown state filter (use pending|approved|rejected|ready)");
                    return Ok(());
                }
                None => orders,
            };
            println!("STATE      ID                   TIER       CREATED                  EMAIL");
            for o in filtered {
                let short = &o.id[..o.id.len().min(20)];
                println!(
                    "{state:<10} {id:<20} {tier:<10} {created:<24} {email}",
                    state = o.state.name(),
                    id = short,
                    tier = o.tier,
                    created = o.created_at,
                    email = o.email
                );
            }
        }
        OrderOp::Show { id } => {
            let Some(order) = store.get(&id)? else {
                eprintln!("order not found: {}", id);
                std::process::exit(1);
            };
            println!("{:#?}", order);
            println!("\n--- audit ---");
            for ev in store.audit_for(&id)? {
                println!(
                    "  {:?} → {:?}  by {}  {}",
                    ev.from,
                    ev.to,
                    ev.actor,
                    ev.note.as_deref().unwrap_or("")
                );
            }
        }
        OrderOp::Approve { id, actor, note } => {
            let o = store.transition(&id, OrderState::Approved, &actor, note)?;
            println!("approved: {}  (Pending → {})", o.id, o.state.name());
        }
        OrderOp::Reject { id, actor, note } => {
            let o = store.transition(&id, OrderState::Rejected, &actor, note)?;
            println!("rejected: {}  ({})", o.id, o.state.name());
        }
        OrderOp::Ready { id, actor, note } => {
            // Sanity-check the report blob is in place before flipping state.
            let pdf = orders::blobs_dir(&id).join("report.pdf");
            if !pdf.exists() {
                anyhow::bail!(
                    "report.pdf not present at {} — copy it before marking ready",
                    pdf.display()
                );
            }
            let o = store.transition(&id, OrderState::Ready, &actor, note)?;
            println!(
                "ready: {}  ({})  pdf={}",
                o.id,
                o.state.name(),
                pdf.display()
            );
        }
        OrderOp::Audit { id, limit } => {
            let events = match id {
                Some(ref oid) => store.audit_for(oid)?,
                None => store.audit_tail(limit)?,
            };
            for ev in events {
                println!(
                    "  {}  {:>20}  {:?} → {:?}  by {}  {}",
                    ev.ts_nanos,
                    ev.order_id,
                    ev.from,
                    ev.to,
                    ev.actor,
                    ev.note.as_deref().unwrap_or("")
                );
            }
        }
    }
    Ok(())
}

/// If `ips` is empty, read whitespace-separated IPs from stdin. Otherwise return as-is.
fn read_ips_from_stdin_if_empty(ips: Vec<String>) -> Vec<String> {
    if !ips.is_empty() {
        return ips;
    }
    use std::io::Read;
    let mut buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut buf);
    buf.split_whitespace().map(|s| s.to_string()).collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Keep _log_guard alive for the process lifetime — drops flush the appender.
    let _log_guard = logs::init("whobelooking").ok();

    let cmd = Cmd::parse();
    match cmd {
        #[cfg(feature = "serve")]
        Cmd::Serve { port } => {
            // Gemini Man: snapshot current log, kill old process, take over.
            // Hold an exclusive flock on `pid.lock` across the snapshot/kill/write
            // window so two concurrent restarts can't race on the PID file. The
            // lock is released at the end of this block — if it lived for the
            // whole serve lifetime, the next deploy's new binary would see
            // WouldBlock and bail out before reaching kill_old().
            {
                let _pid_lock: Option<PidLock> = match acquire_pid_lock() {
                    Ok(Some(f)) => Some(f),
                    Ok(None) => {
                        eprintln!(
                            "another whobelooking serve is starting (pid.lock held); exiting"
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::warn!("could not acquire pid.lock: {} — proceeding anyway", e);
                        None
                    }
                };
                logs::snapshot_pre_restart("whobelooking");
                if let Some(old) = read_old_pid().filter(|&p| p != std::process::id()) {
                    kill_old(old);
                    // Old process serialized its counters to state.bin.zst on SIGTERM.
                    // Restore them so Prometheus totals are continuous across handoffs.
                    logs::load_state("whobelooking");
                }
                write_pid();
            }
            // IPC dispatcher — operator data over Unix socket. No HTTP /admin.
            ipc::spawn().await?;

            // OpenTelemetry — only emits if the `otel` feature is on AND
            // the operator has set `OTEL_EXPORTER_OTLP_ENDPOINT` (or
            // accepts the localhost:4317 default). Guard is held through
            // the serve lifetime so spans + metrics flush on shutdown.
            let _otel_guard = match otel::init("whobelooking") {
                Ok(g) => Some(g),
                Err(e) => {
                    tracing::warn!("otel init failed (continuing without): {}", e);
                    None
                }
            };

            let app = web::router::build();
            let addr = format!("0.0.0.0:{}", port);
            tracing::info!("whobelooking serving at http://{}", addr);
            let listener = tokio::net::TcpListener::bind(&addr).await?;

            let shutdown = async {
                #[cfg(unix)]
                {
                    let mut sigterm =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                            .expect("SIGTERM handler");
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {},
                        _ = sigterm.recv() => {},
                    }
                }
                #[cfg(not(unix))]
                tokio::signal::ctrl_c().await.ok();
                tracing::info!("shutting down — serializing state for handoff");
                // Save counters to bincode+zstd before exiting. The next process
                // (Gemini Man) will load this snapshot after kill_old() returns.
                logs::save_state("whobelooking");
            };
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await?;
        }
        Cmd::Queue => {
            // Try IPC first (server running) → fall back to direct sled (server down).
            #[cfg(feature = "serve")]
            let jobs: Vec<crate::queue::Job> = match ipc::call("queue", serde_json::json!({})).await
            {
                Ok(v) => serde_json::from_value(v).unwrap_or_default(),
                Err(_) => queue::list_jobs()?,
            };
            #[cfg(not(feature = "serve"))]
            let jobs = queue::list_jobs()?;
            if jobs.is_empty() {
                println!("queue empty");
            } else {
                for j in &jobs {
                    println!(
                        "{} {:?} {} {:.1}h {}",
                        j.id,
                        j.status,
                        j.customer_email,
                        j.estimated_hours,
                        j.tier.label()
                    );
                }
            }
            let hours = queue::hours_this_week();
            println!("\n{:.1} of 12 hours committed this week", hours);
        }
        Cmd::Pop => match queue::pop_job()? {
            Some(job) => {
                println!(
                    "popped: {} ({}) — {:?}",
                    job.id, job.customer_email, job.source_type
                );
                println!("tier: {} ({:.1}h)", job.tier.label(), job.estimated_hours);
            }
            None => println!("no pending jobs"),
        },
        #[cfg(feature = "serve")]
        Cmd::Ping => match ipc::call("ping", serde_json::json!({})).await {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v)?),
            Err(e) => anyhow::bail!("ipc unreachable: {}", e),
        },
        #[cfg(feature = "serve")]
        Cmd::Visits { days_ago, format } => {
            let val: serde_json::Value =
                match ipc::call("visits", serde_json::json!({"days_ago": days_ago})).await {
                    Ok(v) => v,
                    Err(_) => {
                        let today = web::visits::today();
                        let d = today.saturating_sub(days_ago);
                        let rows = web::visits::list_for_date(d);
                        serde_json::json!({
                            "date_days": d,
                            "today_minus": days_ago,
                            "rows": rows.iter().map(|(ip,p,c,f,l)|
                                serde_json::json!({"ip":ip,"path":p,"count":c,"first":f,"last":l})
                            ).collect::<Vec<_>>(),
                        })
                    }
                };

            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&val)?),
                _ => {
                    let rows = val
                        .get("rows")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let mut by_ip: std::collections::HashMap<String, Vec<(String, u64, u64, u64)>> =
                        std::collections::HashMap::new();
                    for r in &rows {
                        let ip = r["ip"].as_str().unwrap_or("").to_string();
                        let p = r["path"].as_str().unwrap_or("").to_string();
                        let c = r["count"].as_u64().unwrap_or(0);
                        let f = r["first"].as_u64().unwrap_or(0);
                        let l = r["last"].as_u64().unwrap_or(0);
                        by_ip.entry(ip).or_default().push((p, c, f, l));
                    }
                    let mut ranked: Vec<_> = by_ip
                        .into_iter()
                        .map(|(ip, mut paths)| {
                            paths.sort_by_key(|t| std::cmp::Reverse(t.1));
                            let total: u64 = paths.iter().map(|t| t.1).sum();
                            let first = paths.iter().map(|t| t.2).min().unwrap_or(0);
                            let last = paths.iter().map(|t| t.3).max().unwrap_or(0);
                            (ip, total, first, last, paths)
                        })
                        .collect();
                    ranked.sort_by_key(|r| std::cmp::Reverse(r.1));
                    println!(
                        "# whobelooking visits — today-{} — {} unique IPs",
                        days_ago,
                        ranked.len()
                    );
                    for (ip, total, first, last, paths) in &ranked {
                        let span = last.saturating_sub(*first);
                        println!(
                            "{:>5}  {}  span={}s  ({} paths)",
                            total,
                            ip,
                            span,
                            paths.len()
                        );
                        for (p, c, _, _) in paths.iter().take(8) {
                            println!("        {:>4}x  {}", c, p);
                        }
                    }
                }
            }
        }
        #[cfg(feature = "serve")]
        Cmd::Corpus {
            format,
            output,
            min_hits,
            attack_only,
        } => {
            // IPC first → fall back to direct sled if server isn't running.
            let corpus: Vec<(String, u64)> = match ipc::call(
                "corpus",
                serde_json::json!({"min_hits": min_hits, "attack_only": attack_only}),
            )
            .await
            {
                Ok(v) => serde_json::from_value(v).unwrap_or_default(),
                Err(_) => web::visits::corpus_paths(min_hits, attack_only),
            };

            let rendered = match format.as_str() {
                "json" => serde_json::to_string_pretty(&corpus)?,
                _ => corpus
                    .iter()
                    .map(|(p, _)| p.as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
            };
            match output {
                Some(path) => {
                    std::fs::write(&path, &rendered)?;
                    eprintln!("wrote {} paths to {}", corpus.len(), path);
                }
                None => println!("{}", rendered),
            }
        }
        Cmd::Order { op } => {
            run_order_op(op)?;
        }
        Cmd::Done { id, report } => {
            queue::complete_job(&id, report)?;
            println!("marked complete: {}", id);
        }
        Cmd::Deliver { id } => {
            queue::deliver_job(&id)?;
            println!("marked delivered: {}", id);
        }
        Cmd::Decrypt { blob } => {
            let passphrase =
                std::env::var("CRED_KEY").unwrap_or_else(|_| "whobelooking-default-key".into());
            let key = crypto::key_from_passphrase(&passphrase);
            match crypto::decrypt(&blob, &key) {
                Ok(plaintext) => println!("{}", plaintext),
                Err(e) => {
                    eprintln!("decryption failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Cmd::Scout {
            naics,
            keyword,
            sam_key,
            max_amount,
            min_amount,
        } => {
            let codes: Vec<&str> = naics.split(',').map(|s| s.trim()).collect();
            scout::run(
                &codes,
                keyword.as_deref(),
                sam_key.as_deref(),
                min_amount,
                max_amount,
            )
            .await?;
        }
        #[cfg(feature = "browser")]
        Cmd::Perf { url, wait } => {
            browse::perf(&url, wait).await?;
        }
        #[cfg(feature = "browser")]
        Cmd::Browse {
            url,
            out,
            wait,
            extract,
            mobile,
        } => {
            browse::run(&url, &out, wait, extract, mobile).await?;
        }
        #[cfg(feature = "browser")]
        Cmd::Scrape { file, out, wait } => {
            browse::scrape(&file, &out, wait).await?;
        }
        #[cfg(feature = "browser")]
        Cmd::Pdf {
            input,
            out,
            wait,
            landscape,
            background,
        } => {
            browse::pdf(&input, &out, wait, landscape, background).await?;
        }
        Cmd::Pull {
            date,
            zone,
            token,
            country,
            min_hits,
        } => {
            let visitors = cf::pull(&zone, &token, date.as_deref(), &country, min_hits).await?;
            for v in &visitors {
                println!("{:<6} {}", v.hits, v.ip);
            }
            eprintln!("{} IPs pulled", visitors.len());
        }
        Cmd::Rdns { ips } => {
            let ips = read_ips_from_stdin_if_empty(ips);
            let results = dns::rdns_batch(&ips).await;
            for (ip, rdns) in &results {
                println!("{:<42} {}", ip, rdns.as_deref().unwrap_or("-"));
            }
        }
        Cmd::Rdap { ips, json } => {
            let ips = read_ips_from_stdin_if_empty(ips);
            let results = rdap::lookup_batch(&ips).await;
            if json {
                let map: std::collections::BTreeMap<&str, &rdap::Info> = ips
                    .iter()
                    .zip(results.iter())
                    .map(|(i, r)| (i.as_str(), r))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&map)?);
            } else {
                for (ip, info) in ips.iter().zip(results.iter()) {
                    println!(
                        "{:<42} {:>3} {:<22} {}",
                        ip,
                        info.country.as_deref().unwrap_or("-"),
                        info.cidr.as_deref().unwrap_or("-"),
                        info.org
                            .as_deref()
                            .unwrap_or(info.name.as_deref().unwrap_or("-")),
                    );
                }
            }
        }
        Cmd::ParseLogs { files, hours } => {
            let agg = parse_logs::parse_files(&files, hours)?;
            println!("{}", serde_json::to_string_pretty(&agg)?);
            eprintln!("{} unique IPs across {} files", agg.len(), files.len());
        }
        Cmd::CfFleet { token, hours, out } => {
            let zones = cf::list_zones(&token).await?;
            eprintln!("{} zones found", zones.len());
            let groups = cf::pull_fleet(&token, &zones, hours).await?;
            std::fs::write(&out, serde_json::to_string_pretty(&groups)?)?;
            eprintln!("wrote {} ({} zone keys)", out, groups.len());
        }
        Cmd::CfEnrich {
            ips,
            token,
            hours,
            out,
        } => {
            let ips = read_ips_from_stdin_if_empty(ips);
            let zones = cf::list_zones(&token).await?;
            let enriched = cf::enrich_ips(&token, &zones, &ips, hours).await?;
            std::fs::write(&out, serde_json::to_string_pretty(&enriched)?)?;
            eprintln!(
                "enriched {} IPs across {} zones → {}",
                ips.len(),
                zones.len(),
                out
            );
        }
        Cmd::Detect {
            file,
            max_rows,
            json,
        } => {
            let text = std::fs::read_to_string(&file)?;
            let report = wbl_detect::detect_schema(&text, max_rows as usize);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "delim={:?}  rows_sampled={}  had_header={}",
                    report.delimiter, report.rows_sampled, report.had_header
                );
                for c in &report.columns {
                    let conf = (c.confidence * 100.0) as u32;
                    println!(
                        "  col {:>2}  {:<12}  {:>3}%  {}  {}",
                        c.index,
                        c.kind.name(),
                        conf,
                        c.header.as_deref().unwrap_or(""),
                        c.samples.first().map(String::as_str).unwrap_or(""),
                    );
                }
            }
        }
        Cmd::Render { file, out } => {
            let bytes = std::fs::read(&file)?;
            let parsed = match String::from_utf8(bytes.clone()) {
                Ok(text) => wbl_detect::f400(&text),
                Err(_) => wbl_detect::f454(&bytes),
            };
            let mut report = wbl_detect::f401(&parsed.events);
            let ips = wbl_detect::f403(&report);
            if !ips.is_empty() {
                eprintln!("resolving {} IP(s)...", ips.len());
                let rdns = dns::rdns_batch(&ips).await;
                let enrich: std::collections::BTreeMap<String, wbl_detect::t108> = rdns
                    .into_iter()
                    .filter_map(|(ip, name)| {
                        name.map(|r| {
                            (
                                ip,
                                wbl_detect::t108 {
                                    rdns: Some(r),
                                    ..Default::default()
                                },
                            )
                        })
                    })
                    .collect();
                wbl_detect::f402(&mut report, &enrich);
            }
            // Inject cross-report actor history from the local redb store.
            let history = actor_history::lookup(&ips);
            if !history.is_empty() {
                let hist_enrich: std::collections::BTreeMap<String, wbl_detect::t108> = history
                    .iter()
                    .map(|(ip, h)| {
                        (
                            ip.clone(),
                            wbl_detect::t108 {
                                history_first_unix: Some(h.first_seen),
                                history_total_reports: Some(h.total_reports),
                                history_total_hits: Some(h.total_hits),
                                ..Default::default()
                            },
                        )
                    })
                    .collect();
                wbl_detect::f402(&mut report, &hist_enrich);
            }
            let html = wbl_detect::f405(&report, &file);
            let dest = out.unwrap_or_else(|| format!("{}.html", file));
            std::fs::write(&dest, &html)?;
            println!("{}", dest);
            // Persist actor history so future reports can show the ↩ badge.
            actor_history::update(&report.ips);
        }
        Cmd::Intel {
            baselogs_dir,
            token,
            hours,
            out,
        } => {
            intel::run(&baselogs_dir, &token, hours, &out).await?;
        }
        Cmd::Scan { url, json } => {
            scan_cli::run(&url, json).await?;
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
        Cmd::Report {
            date,
            zone,
            token,
            country,
            min_hits,
            scan_neighbors,
        } => {
            report::run(
                &zone,
                &token,
                date.as_deref(),
                &country,
                min_hits,
                scan_neighbors,
            )
            .await?;
        }
        #[cfg(feature = "browser")]
        Cmd::Ctos { op } => {
            ctos::run(op).await?;
        }
    }
    Ok(())
}

mod scout {
    use redb::{Database, TableDefinition};
    use serde::{Deserialize, Serialize};

    const SCOUT_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("scout");

    fn db_get(db: &Database, key: &str) -> Option<Vec<u8>> {
        let txn = db.begin_read().ok()?;
        let tbl = txn.open_table(SCOUT_TABLE).ok()?;
        tbl.get(key.as_bytes()).ok()?.map(|g| g.value().to_vec())
    }

    fn db_insert_is_new(db: &Database, key: &str, val: &[u8]) -> bool {
        (|| -> anyhow::Result<bool> {
            let txn = db.begin_write()?;
            let is_new = {
                let mut tbl = txn.open_table(SCOUT_TABLE)?;
                tbl.insert(key.as_bytes(), val)?.is_none()
            };
            txn.commit()?;
            Ok(is_new)
        })()
        .unwrap_or(false)
    }

    fn db_put(db: &Database, key: &str, val: &[u8]) {
        let _ = (|| -> anyhow::Result<()> {
            let txn = db.begin_write()?;
            {
                let mut tbl = txn.open_table(SCOUT_TABLE)?;
                tbl.insert(key.as_bytes(), val)?;
            }
            txn.commit()?;
            Ok(())
        })();
    }

    // === Common Open Opportunity Schema ===
    // 4 record types, each with fields that match their source data cleanly.
    // Stored in a single redb table with key prefixes per record type.

    /// Biddable opportunities — things you can respond to TODAY
    /// Sources: SAM.gov, Grants.gov, SBIR.gov
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct Bid {
        pub source: String, // sam.gov | grants | sbir
        pub id: String,     // noticeId | oppNumber | solicitationId
        pub title: String,
        pub description: String,
        pub agency: String,
        pub naics: String,     // NAICS code or "grant" / "sbir"
        pub set_aside: String, // SBA, SDVOSBC, 8A, etc. or ""
        pub posted: String,    // YYYY-MM-DD
        pub deadline: String,  // YYYY-MM-DD or ""
        pub url: String,
    }

    /// Past awards — who won what, competitive intel
    /// Sources: USASpending, SAM.gov Contract Awards
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct Award {
        pub source: String, // usaspending | awards
        pub id: String,     // Award ID | contractId
        pub winner: String, // company name
        pub description: String,
        pub amount: f64,
        pub agency: String,
        pub naics: String,
        pub date: String, // award/start date
        pub url: String,
    }

    /// Early pipeline signals — RFIs, proposed rules, policy changes
    /// Sources: Federal Register, Regulations.gov
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct Signal {
        pub source: String, // fedreg | regs
        pub id: String,     // document_number | documentId
        pub title: String,
        pub description: String,
        pub agency: String,
        pub doc_type: String, // NOTICE | Rule | Proposed Rule
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
        pub sin: String, // GSA SIN
        pub price: f64,  // ceiling rate $/hr
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

    fn open_db() -> Database {
        let dir = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join("whobelooking");
        let _ = std::fs::create_dir_all(&dir);
        Database::create(dir.join("scout.redb")).expect("open redb scout")
    }

    fn compress(data: &[u8]) -> Vec<u8> {
        zstd::encode_all(data, 3).unwrap_or_else(|_| data.to_vec())
    }

    fn decompress(data: &[u8]) -> Vec<u8> {
        zstd::decode_all(data).unwrap_or_else(|_| data.to_vec())
    }

    /// Cache helper — returns `true` if the row is new, `false` if
    /// already present.  Serialization or redb write errors collapse to `false` so
    /// the scout can keep working through transient I/O hiccups.
    fn cache_put<T: serde::Serialize>(db: &Database, key: &str, value: &T) -> bool {
        let Ok(buf) = serde_json::to_vec(value) else {
            return false;
        };
        db_insert_is_new(db, key, &compress(&buf))
    }

    fn cache_bid(db: &Database, b: &Bid) -> bool {
        cache_put(db, &format!("bid:{}:{}", b.source, b.id), b)
    }
    fn cache_award(db: &Database, a: &Award) -> bool {
        cache_put(db, &format!("award:{}:{}", a.source, a.id), a)
    }
    fn cache_signal(db: &Database, s: &Signal) -> bool {
        cache_put(db, &format!("signal:{}:{}", s.source, s.id), s)
    }
    fn cache_rate(db: &Database, r: &Rate) -> bool {
        cache_put(db, &format!("rate:{}", r.id), r)
    }

    fn strip_html(s: &str) -> String {
        s.chars()
            .fold((String::new(), false), |(mut out, in_tag), c| match c {
                '<' => (out, true),
                '>' => (out, false),
                _ if !in_tag => {
                    out.push(c);
                    (out, false)
                }
                _ => (out, true),
            })
            .0
    }

    /// Fetch full description text from a URL, return as string
    async fn enrich(client: &reqwest::Client, url: &str) -> String {
        if url.is_empty() || !url.starts_with("http") {
            return String::new();
        }
        match tokio::time::timeout(std::time::Duration::from_secs(10), client.get(url).send()).await
        {
            Ok(Ok(resp)) => resp.text().await.unwrap_or_default(),
            _ => String::new(),
        }
    }

    /// Enrich a batch of bids — fetch full descriptions in parallel, cap concurrency
    async fn enrich_bids(bids: &mut [Bid], db: &Database) {
        let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
        else {
            tracing::warn!("enrich_bids: reqwest client build failed, skipping enrichment");
            return;
        };

        for b in bids.iter_mut() {
            // Skip if already enriched (description > 200 chars = probably full text)
            if b.description.len() > 200 {
                continue;
            }

            // Check redb for cached enrichment
            let ekey = format!("enriched:{}:{}", b.source, b.id);
            if let Some(cached) = db_get(db, &ekey) {
                let text = String::from_utf8_lossy(&decompress(&cached)).to_string();
                if !text.is_empty() {
                    b.description = text;
                    continue;
                }
            }

            // SAM.gov: description field is a URL to full solicitation text
            if b.description.starts_with("http") {
                let full = enrich(&client, &b.description).await;
                if !full.is_empty() {
                    let clean = strip_html(&full);
                    let trimmed = if clean.len() > 2000 {
                        clean[..2000].to_string()
                    } else {
                        clean
                    };
                    db_put(db, &ekey, &compress(trimmed.as_bytes()));
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
                            let trimmed = if clean.len() > 2000 {
                                clean[..2000].to_string()
                            } else {
                                clean
                            };
                            db_put(db, &ekey, &compress(trimmed.as_bytes()));
                            b.description = trimmed;
                        }
                    }
                }
            }
        }
    }

    pub async fn run(
        naics: &[&str],
        keyword: Option<&str>,
        sam_key: Option<&str>,
        min_amount: u64,
        max_amount: u64,
    ) -> anyhow::Result<()> {
        let db = open_db();
        let mut rpt = ScoutReport {
            bids: vec![],
            awards: vec![],
            signals: vec![],
            rates: vec![],
            new_count: 0,
        };

        // === BIDS (things you can respond to) ===

        // SAM.gov Opportunities
        if let Some(key) = sam_key {
            eprintln!("[sam.gov] querying...");
            match sam::query(key, naics, keyword, &db).await {
                Ok(bids) => {
                    eprintln!("[sam.gov] {} bids", bids.len());
                    for b in bids {
                        if cache_bid(&db, &b) {
                            rpt.new_count += 1;
                        }
                        rpt.bids.push(b);
                    }
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
                for b in bids {
                    if cache_bid(&db, &b) {
                        rpt.new_count += 1;
                    }
                    rpt.bids.push(b);
                }
            }
            Err(e) => eprintln!("[grants] error: {}", e),
        }

        // SBIR.gov
        eprintln!("[sbir] querying...");
        match sbir::query(keyword.unwrap_or("cyber")).await {
            Ok(bids) => {
                eprintln!("[sbir] {} bids", bids.len());
                for b in bids {
                    if cache_bid(&db, &b) {
                        rpt.new_count += 1;
                    }
                    rpt.bids.push(b);
                }
            }
            Err(e) => eprintln!("[sbir] error: {}", e),
        }

        // === ENRICH BIDS — fetch full descriptions, compress, cache ===
        if !rpt.bids.is_empty() {
            eprintln!(
                "[enrich] fetching full descriptions for {} bids...",
                rpt.bids.len()
            );
            enrich_bids(&mut rpt.bids, &db).await;
            eprintln!("[enrich] done");
        }

        // === AWARDS (competitive intel) ===

        eprintln!("[usaspending] querying...");
        match usaspending::query(naics, min_amount, max_amount).await {
            Ok(awards) => {
                eprintln!("[usaspending] {} awards", awards.len());
                for a in awards {
                    if cache_award(&db, &a) {
                        rpt.new_count += 1;
                    }
                    rpt.awards.push(a);
                }
            }
            Err(e) => eprintln!("[usaspending] error: {}", e),
        }

        if let Some(key) = sam_key {
            eprintln!("[awards] querying...");
            match contract_awards::query(key, naics).await {
                Ok(awards) => {
                    eprintln!("[awards] {} awards", awards.len());
                    for a in awards {
                        if cache_award(&db, &a) {
                            rpt.new_count += 1;
                        }
                        rpt.awards.push(a);
                    }
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
                for s in sigs {
                    if cache_signal(&db, &s) {
                        rpt.new_count += 1;
                    }
                    rpt.signals.push(s);
                }
            }
            Err(e) => eprintln!("[fedreg] error: {}", e),
        }

        let reg_kw = keyword.unwrap_or("cybersecurity");
        eprintln!("[regs] querying...");
        match regulations::query(reg_kw).await {
            Ok(sigs) => {
                eprintln!("[regs] {} signals", sigs.len());
                for s in sigs {
                    if cache_signal(&db, &s) {
                        rpt.new_count += 1;
                    }
                    rpt.signals.push(s);
                }
            }
            Err(e) => eprintln!("[regs] error: {}", e),
        }

        // === RATES (pricing intel) ===

        let calc_kw = keyword.unwrap_or("software engineer");
        eprintln!("[calc] querying...");
        match calc::query(calc_kw).await {
            Ok(rates) => {
                eprintln!("[calc] {} rates", rates.len());
                for r in rates {
                    if cache_rate(&db, &r) {
                        rpt.new_count += 1;
                    }
                    rpt.rates.push(r);
                }
            }
            Err(e) => eprintln!("[calc] error: {}", e),
        }

        // === REPORT (gamified) ===

        let total = rpt.bids.len() + rpt.awards.len() + rpt.signals.len() + rpt.rates.len();

        // Score bids by match quality
        let match_keywords = [
            "cyber",
            "software",
            "rust",
            "edge",
            "ai",
            "cloud",
            "zero trust",
            "sbir",
            "single binary",
            "open source",
            "secure",
            "memory safe",
            "veteran",
        ];

        fn score_bid(b: &Bid, keywords: &[&str]) -> u32 {
            let text = format!("{} {} {}", b.title, b.description, b.agency).to_lowercase();
            let mut s = 0u32;
            for kw in keywords {
                if text.contains(kw) {
                    s += 10;
                }
            }
            if !b.set_aside.is_empty() {
                s += 15;
            }
            if b.set_aside.contains("SDVOSB") {
                s += 25;
            }
            if b.deadline.is_empty() || b.deadline.contains("rolling") {
                s += 5;
            }
            // Agency boost — orgs you've worked with or align to
            let good_agencies = [
                "darpa",
                "nsf",
                "navy",
                "air force",
                "army",
                "dhs",
                "cisa",
                "cyber",
                "dod",
                "defense",
                "veterans",
                "nist",
                "nasa",
            ];
            for ga in good_agencies {
                if text.contains(ga) {
                    s += 8;
                }
            }
            // NAICS boost — your codes
            let your_naics = ["541511", "541512", "541519", "518210", "541690"];
            if your_naics.iter().any(|n| b.naics.contains(n)) {
                s += 20;
            }
            // Title keyword boost — things you actually build
            let hot = [
                "software",
                "web",
                "application",
                "platform",
                "data",
                "api",
                "infrastructure",
                "system design",
                "custom",
                "development",
                "modernization",
            ];
            for h in hot {
                if text.contains(h) {
                    s += 5;
                }
            }
            s
        }

        fn score_icon(score: u32) -> &'static str {
            if score >= 50 {
                "[!!!]"
            }
            // perfect match — drop everything
            else if score >= 30 {
                "[!! ]"
            }
            // strong match — bid this week
            else if score >= 15 {
                "[!  ]"
            }
            // worth a look
            else {
                "[   ]"
            } // low match
        }

        // Sort bids by score descending
        let mut scored_bids: Vec<(u32, &Bid)> = rpt
            .bids
            .iter()
            .map(|b| (score_bid(b, &match_keywords), b))
            .collect();
        scored_bids.sort_by(|a, b| b.0.cmp(&a.0));

        println!("\n  LOOT TABLE — OPEN BIDS ({} found)", rpt.bids.len());
        println!(
            "  {:<6} {:<10} {:<12} {:<48} Agency",
            "Match", "Source", "Deadline", "Title"
        );
        println!("  {}", "-".repeat(115));
        for (score, b) in &scored_bids {
            let dl = if b.deadline.is_empty() {
                "rolling"
            } else {
                &b.deadline[..10.min(b.deadline.len())]
            };
            let title = if b.title.len() > 46 {
                &b.title[..46]
            } else {
                &b.title
            };
            println!(
                "  {:<6} {:<10} {:<12} {:<48} {}",
                score_icon(*score),
                b.source,
                dl,
                title,
                b.agency
            );
        }

        // Awards — sorted by amount, show your weight class
        let mut sorted_awards = rpt.awards.clone();
        sorted_awards.sort_by(|a, b| {
            b.amount
                .partial_cmp(&a.amount)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        println!(
            "\n  SCOREBOARD — WHO'S WINNING ({} awards)",
            sorted_awards.len()
        );
        println!("  {:<12} {:<12} {:<38} Agency", "Amount", "NAICS", "Winner");
        println!("  {}", "-".repeat(105));
        let mut your_range = 0u32;
        for a in &sorted_awards {
            let tier = if a.amount < 50000.0 {
                ">"
            }
            // micro — easy entry
            else if a.amount < 150000.0 {
                ">>"
            }
            // your sweet spot
            else if a.amount < 300000.0 {
                ">>>"
            } else {
                ">>>>"
            };
            if a.amount >= 25000.0 && a.amount <= 250000.0 {
                your_range += 1;
            }
            let winner = if a.winner.len() > 36 {
                &a.winner[..36]
            } else {
                &a.winner
            };
            let agency = if a.agency.len() > 30 {
                &a.agency[..30]
            } else {
                &a.agency
            };
            println!(
                "  {:<2} ${:<10.0} {:<12} {:<38} {}",
                tier, a.amount, a.naics, winner, agency
            );
        }
        println!("  {} awards in your range ($25K-$250K)", your_range);

        // Pipeline — signals sorted by date
        println!(
            "\n  RADAR — PIPELINE SIGNALS ({} detected)",
            rpt.signals.len()
        );
        println!("  {:<8} {:<12} {:<58} Agency", "Source", "Date", "Title");
        println!("  {}", "-".repeat(105));
        for s in rpt.signals.iter().take(30) {
            let title = if s.title.len() > 56 {
                &s.title[..56]
            } else {
                &s.title
            };
            let date = if s.date.len() >= 10 {
                &s.date[..10]
            } else {
                &s.date
            };
            println!("  {:<8} {:<12} {:<58} {}", s.source, date, title, s.agency);
        }
        if rpt.signals.len() > 30 {
            println!("  ... +{} more", rpt.signals.len() - 30);
        }

        // Rates — your pricing intel
        println!(
            "\n  MARKET RATES — WHAT THEY CHARGE ({} benchmarks)",
            rpt.rates.len()
        );
        println!("  {:<10} {:<38} Vendor", "$/hr", "Labor Category");
        println!("  {}", "-".repeat(75));
        for r in &rpt.rates {
            let cat = if r.labor_category.len() > 36 {
                &r.labor_category[..36]
            } else {
                &r.labor_category
            };
            let vendor = if r.vendor.len() > 28 {
                &r.vendor[..28]
            } else {
                &r.vendor
            };
            println!("  ${:<9.2} {:<38} {}", r.price, cat, vendor);
        }

        // Summary
        let top_matches = scored_bids.iter().filter(|(s, _)| *s >= 30).count();
        println!("\n  === SCOUT SUMMARY ===");
        println!("  {} total records | {} new this run", total, rpt.new_count);
        println!(
            "  {} open bids | {} strong matches [!!+]",
            rpt.bids.len(),
            top_matches
        );
        println!(
            "  {} competitors tracked | {} in your range",
            rpt.awards.len(),
            your_range
        );
        println!(
            "  {} pipeline signals | {} rate benchmarks",
            rpt.signals.len(),
            rpt.rates.len()
        );
        if top_matches > 0 {
            println!("\n  [!!!] = perfect match, bid NOW");
            println!("  [!! ] = strong match, bid this week");
            println!("  [!  ] = worth a look");
        }

        Ok(())
    }

    /// Max records per source before stopping pagination
    const PAGE_CAP: usize = 200;

    mod usaspending {
        use super::{Award, PAGE_CAP};

        /// USASpending API — no auth, no rate limit
        /// Pagination: page param (1-indexed), limit per page, has_next_page in response
        pub async fn query(
            naics: &[&str],
            min_amount: u64,
            max_amount: u64,
        ) -> anyhow::Result<Vec<Award>> {
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
                            url: format!(
                                "https://www.usaspending.gov/award/{}",
                                r["generated_internal_id"].as_str().unwrap_or("")
                            ),
                        });
                    }
                }

                page += 1;
                if count == 0 || !has_next || all.len() >= PAGE_CAP {
                    break;
                }
            }
            Ok(all)
        }
    }

    mod sam {
        use super::Bid;

        pub async fn query(
            api_key: &str,
            naics: &[&str],
            keyword: Option<&str>,
            db: &super::Database,
        ) -> anyhow::Result<Vec<Bid>> {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let _naics_set: std::collections::HashSet<&str> = naics.iter().copied().collect();
            // Query each NAICS code separately, paginate until exhausted or 200 per code
            // Rate limit guard: skip codes fetched in last 24h (redb key: "sam_last:{code}")
            let mut all_opps = Vec::new();
            let page_size = 100;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            for code in naics {
                let cache_key = format!("sam_last:{}", code);
                if let Some(ts_bytes) = super::db_get(db, &cache_key) {
                    let ts = u64::from_le_bytes(ts_bytes.as_slice().try_into().unwrap_or([0; 8]));
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

                    let resp: serde_json::Value = client.get(&url).send().await?.json().await?;

                    let total = resp["totalRecords"].as_u64().unwrap_or(0);
                    let arr = resp["opportunitiesData"].as_array();
                    let page_count = arr.map(|a| a.len()).unwrap_or(0);

                    if let Some(arr) = arr {
                        for r in arr {
                            let set_aside_val = r["typeOfSetAsideDescription"]
                                .as_str()
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
                                url: format!(
                                    "https://sam.gov/opp/{}/view",
                                    r["noticeId"].as_str().unwrap_or("")
                                ),
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
                super::db_put(db, &cache_key, &now.to_le_bytes());
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
            let parsed: serde_json::Value =
                serde_json::from_str(&resp).unwrap_or(serde_json::Value::Array(vec![]));

            let results = parsed
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .map(|r| Bid {
                            source: "sbir".into(),
                            id: r["solicitationId"].as_str().unwrap_or("").into(),
                            title: r["solicitationTitle"].as_str().unwrap_or("").into(),
                            description: r["sbpiAbstract"].as_str().unwrap_or("").into(),
                            agency: r["agency"].as_str().unwrap_or("").into(),
                            naics: "SBIR".into(),
                            set_aside: String::new(),
                            posted: r["openDate"].as_str().unwrap_or("").into(),
                            deadline: r["closeDate"].as_str().unwrap_or("").into(),
                            url: format!(
                                "https://www.sbir.gov/node/{}",
                                r["solicitationId"].as_str().unwrap_or("")
                            ),
                        })
                        .collect()
                })
                .unwrap_or_default();

            Ok(results)
        }
    }

    mod fedreg {
        use super::{PAGE_CAP, Signal};

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
                        let agency = r["agencies"]
                            .as_array()
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
                if count == 0 || all.len() >= PAGE_CAP || all.len() as u64 >= total {
                    break;
                }
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
                            url: format!(
                                "https://www.grants.gov/search-results-detail/{}",
                                r["id"].as_str().unwrap_or("")
                            ),
                        });
                    }
                }

                start += count as u32;
                if count == 0 || all.len() >= PAGE_CAP || start as u64 >= hit_count {
                    break;
                }
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

            let results = resp["awardSummary"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .map(|r| {
                            let core = &r["coreData"];
                            let awardee = &r["awardeeData"];
                            Award {
                                source: "awards".into(),
                                id: core["contractId"].as_str().unwrap_or("").into(),
                                winner: awardee["awardeeLegalBusinessName"]
                                    .as_str()
                                    .unwrap_or("")
                                    .into(),
                                description: core["descriptionOfContractRequirement"]
                                    .as_str()
                                    .unwrap_or("")
                                    .into(),
                                amount: core["dollarsObligated"].as_f64().unwrap_or(0.0),
                                agency: core["fundingAgencyName"].as_str().unwrap_or("").into(),
                                naics: core["naicsCode"].as_str().unwrap_or("").into(),
                                date: core["dateSigned"].as_str().unwrap_or("").into(),
                                url: "https://sam.gov/search?keywords=contract+awards".into(),
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            Ok(results)
        }
    }

    mod regulations {
        use super::{PAGE_CAP, Signal};

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
                            url: format!(
                                "https://www.regulations.gov/document/{}",
                                attrs["documentId"].as_str().unwrap_or("")
                            ),
                        });
                    }
                }

                page += 1;
                if count == 0 || all.len() >= PAGE_CAP || all.len() as u64 >= total {
                    break;
                }
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

            let results = resp["hits"]["hits"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .map(|r| {
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
                        })
                        .collect()
                })
                .unwrap_or_default();

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

    pub async fn pull(
        zone: &str,
        token: &str,
        date: Option<&str>,
        country: &str,
        min_hits: u32,
    ) -> anyhow::Result<Vec<Visitor>> {
        let date = date
            .map(|d| d.to_string())
            .unwrap_or_else(chrono_free_today);

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

        let data = resp
            .data
            .ok_or_else(|| anyhow::anyhow!("no data in response"))?;
        let zone = data
            .viewer
            .zones
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no zone data"))?;

        Ok(zone
            .groups
            .into_iter()
            .filter(|g| g.count >= min_hits)
            .map(|g| Visitor {
                ip: g.dimensions.client_ip,
                hits: g.count,
            })
            .collect())
    }

    fn chrono_free_today() -> String {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let days = (secs / 86400) as i64;
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

    // ---- additions for fleet pull / enrichment ----

    /// Per-process throttle for CF GraphQL.  CF allows 5 req/s per token.
    /// We aim for ≤4 req/s with jittered spacing to leave headroom for
    /// the dashboard + bot-management lookups happening alongside.
    static GQL_GATE: tokio::sync::Mutex<Option<std::time::Instant>> =
        tokio::sync::Mutex::const_new(None);

    async fn pace() {
        const MIN_GAP_MS: u64 = 250; // 4 req/s
        let mut g = GQL_GATE.lock().await;
        let now = std::time::Instant::now();
        if let Some(prev) = *g {
            let elapsed = now.duration_since(prev);
            if elapsed < std::time::Duration::from_millis(MIN_GAP_MS) {
                let wait = std::time::Duration::from_millis(MIN_GAP_MS) - elapsed;
                drop(g);
                tokio::time::sleep(wait).await;
                g = GQL_GATE.lock().await;
            }
        }
        *g = Some(std::time::Instant::now());
    }

    /// POST a GraphQL request with retry + exponential backoff. Retries on:
    ///   * `429 Too Many Requests`
    ///   * any 5xx
    ///   * transient transport errors (timeouts, connect failures)
    ///
    /// Backoff: 500ms, 1s, 2s, 4s. After 4 attempts we surface the error.
    async fn graphql_post(
        client: &reqwest::Client,
        token: &str,
        body: &serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let mut attempt = 0u32;
        loop {
            pace().await;
            let res = client
                .post("https://api.cloudflare.com/client/v4/graphql")
                .header("Authorization", format!("Bearer {}", token))
                .json(body)
                .send()
                .await;
            let retry_reason: Option<String> = match res {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return Ok(resp.json().await?);
                    }
                    if status.as_u16() == 429 || status.is_server_error() {
                        Some(format!("HTTP {}", status))
                    } else {
                        let text = resp.text().await.unwrap_or_default();
                        anyhow::bail!(
                            "CF GraphQL non-retryable {}: {}",
                            status,
                            &text[..text.len().min(200)]
                        );
                    }
                }
                Err(e) if e.is_timeout() || e.is_connect() => Some(format!("transport: {}", e)),
                Err(e) => return Err(e.into()),
            };
            attempt += 1;
            if attempt > 4 {
                anyhow::bail!(
                    "CF GraphQL gave up after {} attempts: {}",
                    attempt,
                    retry_reason.as_deref().unwrap_or("?")
                );
            }
            // Exponential backoff with small jitter (ms = 500 << (attempt-1) ± 100).
            let base = 500u64 << (attempt - 1);
            let jitter = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_millis())
                .unwrap_or(0)
                % 200) as u64;
            let wait = base.saturating_add(jitter);
            tracing::warn!(
                "[cf-graphql] retry {} after {}ms ({})",
                attempt,
                wait,
                retry_reason.as_deref().unwrap_or("?")
            );
            tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
        }
    }

    /// List every zone the token can see (paginated).
    pub async fn list_zones(token: &str) -> anyhow::Result<Vec<(String, String)>> {
        #[derive(serde::Deserialize)]
        struct Zone {
            id: String,
            name: String,
        }
        #[derive(serde::Deserialize)]
        struct Resp {
            success: bool,
            #[serde(default)]
            result: Vec<Zone>,
        }
        let client = reqwest::Client::new();
        let mut out = Vec::new();
        let mut page = 1u32;
        loop {
            let r: Resp = client
                .get(format!(
                    "https://api.cloudflare.com/client/v4/zones?per_page=50&page={}",
                    page
                ))
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await?
                .json()
                .await?;
            if !r.success {
                anyhow::bail!("CF zones API: success=false");
            }
            let n = r.result.len();
            out.extend(r.result.into_iter().map(|z| (z.name, z.id)));
            if n < 50 {
                break;
            }
            page += 1;
            if page > 20 {
                break;
            }
        }
        Ok(out)
    }

    /// Build ISO-8601 RFC-3339 strings for `now-hours` → `now`, split into 24h chunks.
    pub fn windows_24h(hours: u64) -> Vec<(String, String)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let start = now.saturating_sub(hours * 3600);
        let mut chunks = Vec::new();
        let mut cur = start;
        while cur < now {
            let end = (cur + 24 * 3600).min(now);
            chunks.push((iso_z(cur), iso_z(end)));
            cur = end;
        }
        chunks
    }

    fn iso_z(secs: u64) -> String {
        let days = (secs / 86400) as i64;
        let z = days + 719468;
        let era = z.div_euclid(146097);
        let doe = (z - era * 146097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let yfix = y + if m <= 2 { 1 } else { 0 };
        let hod = secs % 86400;
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            yfix,
            m,
            d,
            hod / 3600,
            (hod % 3600) / 60,
            hod % 60
        )
    }

    #[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
    pub struct FleetGroup {
        pub count: u32,
        pub ip: String,
        pub country: Option<String>,
        pub host: Option<String>,
        pub path: Option<String>,
        pub status: Option<u32>,
        pub user_agent: Option<String>,
    }

    /// Pull `httpRequestsAdaptiveGroups` for every zone × every 24h window. Returns map zone-name → groups.
    pub async fn pull_fleet(
        token: &str,
        zones: &[(String, String)],
        hours: u64,
    ) -> anyhow::Result<std::collections::BTreeMap<String, Vec<FleetGroup>>> {
        let windows = windows_24h(hours);
        let client = reqwest::Client::new();
        let mut out = std::collections::BTreeMap::<String, Vec<FleetGroup>>::new();
        for (zname, zid) in zones {
            let entry = out.entry(zname.clone()).or_default();
            for (s, e) in &windows {
                let q = r#"query($zone:String!,$s:Time!,$e:Time!){
  viewer { zones(filter:{zoneTag:$zone}){
    httpRequestsAdaptiveGroups(limit:10000,
      filter:{datetime_geq:$s, datetime_leq:$e},
      orderBy:[count_DESC]){
        count
        dimensions { clientIP clientCountryName clientRequestHTTPHost clientRequestPath edgeResponseStatus userAgent }
    } } } }"#;
                let body =
                    serde_json::json!({ "query": q, "variables": {"zone": zid, "s": s, "e": e}});
                let v = match graphql_post(&client, token, &body).await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("[cf-fleet] {} {} {}", zname, s, e);
                        continue;
                    }
                };
                if let Some(errs) = v.get("errors").and_then(|x| x.as_array()) {
                    if !errs.is_empty() {
                        eprintln!(
                            "[cf-fleet] {} {} errors: {}",
                            zname,
                            s,
                            errs[0]
                                .get("message")
                                .and_then(|m| m.as_str())
                                .unwrap_or("?")
                        );
                        continue;
                    }
                }
                let groups = v
                    .pointer("/data/viewer/zones/0/httpRequestsAdaptiveGroups")
                    .and_then(|x| x.as_array());
                if let Some(arr) = groups {
                    for g in arr {
                        let dim = &g["dimensions"];
                        entry.push(FleetGroup {
                            count: g["count"].as_u64().unwrap_or(0) as u32,
                            ip: dim["clientIP"].as_str().unwrap_or("").to_string(),
                            country: dim["clientCountryName"].as_str().map(|s| s.to_string()),
                            host: dim["clientRequestHTTPHost"].as_str().map(|s| s.to_string()),
                            path: dim["clientRequestPath"].as_str().map(|s| s.to_string()),
                            status: dim["edgeResponseStatus"].as_u64().map(|x| x as u32),
                            user_agent: dim["userAgent"].as_str().map(|s| s.to_string()),
                        });
                    }
                }
            }
            eprintln!("[cf-fleet] {:25} {:6} groups", zname, entry.len());
        }
        Ok(out)
    }

    #[derive(serde::Serialize, Default, Clone)]
    pub struct EnrichRecord {
        pub cf_hits: u32,
        pub countries: std::collections::BTreeSet<String>,
        pub paths: std::collections::BTreeMap<String, u32>,
        pub zones: std::collections::BTreeMap<String, u32>,
        pub statuses: std::collections::BTreeMap<String, u32>,
        pub user_agents: std::collections::BTreeSet<String>,
        pub firewall_blocks: u32,
        pub firewall_events: Vec<FwEvent>,
    }

    #[derive(serde::Serialize, Default, Clone)]
    pub struct FwEvent {
        pub zone: String,
        pub action: String,
        pub source: String,
        pub rule: String,
        pub host: String,
        pub path: String,
        pub time: String,
        pub country: String,
    }

    /// Enrich a list of IPs across every zone, both `httpRequestsAdaptiveGroups` and `firewallEventsAdaptive`.
    pub async fn enrich_ips(
        token: &str,
        zones: &[(String, String)],
        ips: &[String],
        hours: u64,
    ) -> anyhow::Result<std::collections::BTreeMap<String, EnrichRecord>> {
        let windows = windows_24h(hours);
        let client = reqwest::Client::new();
        let mut out: std::collections::BTreeMap<String, EnrichRecord> = ips
            .iter()
            .map(|ip| (ip.clone(), EnrichRecord::default()))
            .collect();
        for (zname, zid) in zones {
            for (s, e) in &windows {
                let q = r#"query($zone:String!,$s:Time!,$e:Time!,$ips:[String!]!){
  viewer { zones(filter:{zoneTag:$zone}){
    httpRequestsAdaptiveGroups(limit:10000,
      filter:{datetime_geq:$s, datetime_leq:$e, clientIP_in:$ips},
      orderBy:[count_DESC]){
        count
        dimensions { clientIP clientCountryName clientRequestHTTPHost clientRequestPath edgeResponseStatus userAgent }
    }
    firewallEventsAdaptive(limit:1000,
      filter:{datetime_geq:$s, datetime_leq:$e, clientIP_in:$ips}){
        clientIP action source ruleId clientCountryName userAgent
        clientRequestHTTPHost clientRequestPath datetime
    }
  } } }"#;
                let body = serde_json::json!({ "query": q, "variables": {"zone": zid, "s": s, "e": e, "ips": ips}});
                let v = match graphql_post(&client, token, &body).await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("[cf-enrich] {} {} {}", zname, s, e);
                        continue;
                    }
                };
                if let Some(errs) = v.get("errors").and_then(|x| x.as_array()) {
                    if !errs.is_empty() {
                        eprintln!(
                            "[cf-enrich] {} {} {}",
                            zname,
                            s,
                            errs[0]
                                .get("message")
                                .and_then(|m| m.as_str())
                                .unwrap_or("?")
                        );
                        continue;
                    }
                }
                if let Some(arr) = v
                    .pointer("/data/viewer/zones/0/httpRequestsAdaptiveGroups")
                    .and_then(|x| x.as_array())
                {
                    for g in arr {
                        let dim = &g["dimensions"];
                        let ip = dim["clientIP"].as_str().unwrap_or("");
                        let Some(rec) = out.get_mut(ip) else { continue };
                        let n = g["count"].as_u64().unwrap_or(0) as u32;
                        rec.cf_hits += n;
                        if let Some(cc) = dim["clientCountryName"].as_str() {
                            rec.countries.insert(cc.to_string());
                        }
                        if let Some(p) = dim["clientRequestPath"].as_str() {
                            *rec.paths.entry(p.to_string()).or_insert(0) += n;
                        }
                        *rec.zones.entry(zname.clone()).or_insert(0) += n;
                        if let Some(st) = dim["edgeResponseStatus"].as_u64() {
                            *rec.statuses.entry(st.to_string()).or_insert(0) += n;
                        }
                        if let Some(ua) = dim["userAgent"].as_str() {
                            rec.user_agents.insert(ua.chars().take(160).collect());
                        }
                    }
                }
                if let Some(arr) = v
                    .pointer("/data/viewer/zones/0/firewallEventsAdaptive")
                    .and_then(|x| x.as_array())
                {
                    for ev in arr {
                        let ip = ev["clientIP"].as_str().unwrap_or("");
                        let Some(rec) = out.get_mut(ip) else { continue };
                        rec.firewall_blocks += 1;
                        rec.firewall_events.push(FwEvent {
                            zone: zname.clone(),
                            action: ev["action"].as_str().unwrap_or("").to_string(),
                            source: ev["source"].as_str().unwrap_or("").to_string(),
                            rule: ev["ruleId"].as_str().unwrap_or("").to_string(),
                            host: ev["clientRequestHTTPHost"]
                                .as_str()
                                .unwrap_or("")
                                .to_string(),
                            path: ev["clientRequestPath"].as_str().unwrap_or("").to_string(),
                            time: ev["datetime"].as_str().unwrap_or("").to_string(),
                            country: ev["clientCountryName"].as_str().unwrap_or("").to_string(),
                        });
                    }
                }
            }
        }
        Ok(out)
    }
}

/// Parse `whobelooking`-style base log lines (`visit ip=… cc=… method=… path=… ua="…" ref="…"`).
mod parse_logs {
    use regex_lite::Regex;
    use serde::Serialize;
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Serialize, Default, Clone)]
    pub struct PerIp {
        pub hits: u32,
        pub class: String,
        pub paths: BTreeMap<String, u32>,
        pub user_agents: BTreeMap<String, u32>,
        pub countries: BTreeMap<String, u32>,
        pub sites: BTreeMap<String, u32>,
        pub methods: BTreeMap<String, u32>,
        pub first_unix: u64,
        pub last_unix: u64,
    }

    pub fn parse_files(paths: &[String], hours: u64) -> anyhow::Result<BTreeMap<String, PerIp>> {
        // Pre-compile regexes (literal patterns, unit-tested — `expect` is correct).
        let ansi = Regex::new(r"\x1b\[[0-9;]*m").expect("ANSI strip regex must compile");
        let ts_re = Regex::new(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})")
            .expect("timestamp regex must compile");
        let visit_re = Regex::new(
            r#"visit ip=(\S+) cc=(\S+) method=(\S+) path=(\S+) ua="([^"]*)" ref="([^"]*)""#,
        )
        .expect("visit-line regex must compile");

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let cutoff = if hours == 0 {
            0
        } else {
            now.saturating_sub(hours * 3600)
        };

        let mut out: BTreeMap<String, PerIp> = BTreeMap::new();
        for path in paths {
            let site = std::path::Path::new(path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            // Stream the file line-by-line through a `BufReader` so we never
            // hold the whole log in memory. A 1 GB Cloudflare log used to
            // peak at ~2 GB RAM (utf8_lossy doubling); now it's bounded by
            // the longest single line.
            let file = match std::fs::File::open(path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("[parse-logs] skip {}: {}", path, e);
                    continue;
                }
            };
            use std::io::BufRead;
            let reader = std::io::BufReader::with_capacity(64 * 1024, file);
            for line in reader.lines() {
                let Ok(line) = line else { continue };
                let stripped = ansi.replace_all(&line, "");
                let Some(ts) = ts_re.captures(&stripped) else {
                    continue;
                };
                let Some(v) = visit_re.captures(&stripped) else {
                    continue;
                };
                let ts_unix = utc_to_unix(
                    ts[1].parse()?,
                    ts[2].parse()?,
                    ts[3].parse()?,
                    ts[4].parse()?,
                    ts[5].parse()?,
                    ts[6].parse()?,
                );
                if ts_unix < cutoff {
                    continue;
                }
                let ip = v[1].to_string();
                let rec = out.entry(ip.clone()).or_default();
                rec.hits += 1;
                *rec.paths.entry(v[4].to_string()).or_insert(0) += 1;
                let ua: String = v[5].chars().take(160).collect();
                *rec.user_agents.entry(ua).or_insert(0) += 1;
                *rec.countries.entry(v[2].to_string()).or_insert(0) += 1;
                *rec.sites.entry(site.clone()).or_insert(0) += 1;
                *rec.methods.entry(v[3].to_string()).or_insert(0) += 1;
                if rec.first_unix == 0 || ts_unix < rec.first_unix {
                    rec.first_unix = ts_unix;
                }
                if ts_unix > rec.last_unix {
                    rec.last_unix = ts_unix;
                }
            }
        }
        // Classify
        for rec in out.values_mut() {
            rec.class = classify(rec).to_string();
        }
        Ok(out)
    }

    pub fn classify(p: &PerIp) -> &'static str {
        let paths: Vec<&str> = p.paths.keys().map(String::as_str).collect();
        let uas: Vec<&str> = p.user_agents.keys().map(String::as_str).collect();
        whobelooking::redact::classify(&paths, &uas)
    }

    fn utc_to_unix(y: i64, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> u64 {
        // Howard Hinnant's days_from_civil
        let y = y - if mo <= 2 { 1 } else { 0 };
        let era = y.div_euclid(400);
        let yoe = (y - era * 400) as u64;
        let m = mo as u64;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + (d as u64) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146097 + doe as i64 - 719468;
        let secs = (days as i128) * 86400 + (h as i128) * 3600 + (mi as i128) * 60 + s as i128;
        secs.max(0) as u64
    }
}

/// RDAP whois lookup via rdap.org bootstrap.
///
/// The on-disk cache is **CIDR-keyed**: when a fetch returns a netblock
/// (e.g. `8.8.8.0/24`), we store one entry under `cidr:8.8.8.0/24` and
/// every subsequent lookup of an IP that falls inside that block returns
/// the cached `Info` without an HTTP call.  Same `Info` is also stored
/// under `ip:{exact}` so direct hits stay O(1); CIDR scan is the fallback.
mod rdap {
    use redb::{Database, ReadableTableMetadata, TableDefinition};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use whobelooking::cidr;

    const RDAP_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rdap");

    #[derive(Serialize, Deserialize, Default, Clone)]
    pub struct Info {
        pub handle: Option<String>,
        pub name: Option<String>,
        pub country: Option<String>,
        pub cidr: Option<String>,
        pub org: Option<String>,
        pub admin: Option<String>,
        pub remarks: Vec<String>,
        pub error: Option<String>,
    }

    fn cache_db_path() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("whobelooking")
            .join("rdap_cache.redb")
    }

    fn legacy_json_path() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("whobelooking")
            .join("rdap_cache.json")
    }

    /// Open the redb-backed RDAP cache. If absent, attempt to migrate from
    /// the legacy `rdap_cache.json` file (preserves existing /24 lookups
    /// across upgrades). Failure to open returns `None` so the caller can
    /// still proceed without persistence.
    fn open_cache() -> Option<Database> {
        let p = cache_db_path();
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let db = match Database::create(&p) {
            Ok(db) => db,
            Err(e) => {
                tracing::warn!("rdap redb open failed: {} — running without cache", e);
                return None;
            }
        };
        if is_cache_empty(&db) {
            if let Ok(s) = std::fs::read_to_string(legacy_json_path()) {
                if let Ok(m) = serde_json::from_str::<HashMap<String, Info>>(&s) {
                    let mut migrated = 0u32;
                    if let Ok(txn) = db.begin_write() {
                        {
                            if let Ok(mut tbl) = txn.open_table(RDAP_TABLE) {
                                for (k, v) in &m {
                                    if let Ok(buf) = serde_json::to_vec(v) {
                                        if tbl.insert(k.as_bytes(), buf.as_slice()).is_ok() {
                                            migrated += 1;
                                        }
                                    }
                                }
                            }
                        }
                        let _ = txn.commit();
                    }
                    if migrated > 0 {
                        tracing::info!(
                            "rdap cache: migrated {} entries from legacy JSON",
                            migrated
                        );
                    }
                }
            }
        }
        Some(db)
    }

    fn is_cache_empty(db: &Database) -> bool {
        let Ok(txn) = db.begin_read() else {
            return true;
        };
        match txn.open_table(RDAP_TABLE) {
            Err(redb::TableError::TableDoesNotExist(_)) => true,
            Err(_) => true,
            Ok(tbl) => tbl.is_empty().unwrap_or(true),
        }
    }

    fn cache_get(db: &Database, key: &str) -> Option<Info> {
        let txn = db.begin_read().ok()?;
        let tbl = match txn.open_table(RDAP_TABLE) {
            Ok(t) => t,
            Err(_) => return None,
        };
        let v = tbl.get(key.as_bytes()).ok()??;
        serde_json::from_slice(v.value()).ok()
    }

    fn cache_put(db: &Database, key: &str, info: &Info) {
        if let Ok(buf) = serde_json::to_vec(info) {
            let _ = (|| -> anyhow::Result<()> {
                let txn = db.begin_write()?;
                {
                    let mut tbl = txn.open_table(RDAP_TABLE)?;
                    tbl.insert(key.as_bytes(), buf.as_slice())?;
                }
                txn.commit()?;
                Ok(())
            })();
        }
    }

    /// Walk the redb table once; return the first `cidr:` entry whose prefix
    /// contains `ip`. Cache size in practice is hundreds to low thousands;
    /// linear scan beats indexing complexity at this scale.
    fn cache_cidr_match(db: &Database, ip: &str) -> Option<Info> {
        let txn = db.begin_read().ok()?;
        let tbl = txn.open_table(RDAP_TABLE).ok()?;
        let range = tbl.range(b"cidr:".as_ref()..).ok()?;
        for entry in range.flatten() {
            let (k, v) = entry;
            if !k.value().starts_with(b"cidr:") {
                break;
            }
            let key = String::from_utf8_lossy(k.value()).into_owned();
            let cidr_str = key.strip_prefix("cidr:").unwrap_or("");
            if cidr::contains(cidr_str, ip) {
                return serde_json::from_slice(v.value()).ok();
            }
        }
        None
    }

    fn cache_lookup(db: &Database, ip: &str) -> Option<Info> {
        cache_get(db, &format!("ip:{}", ip)).or_else(|| cache_cidr_match(db, ip))
    }

    fn cache_insert(db: &Database, ip: &str, info: &Info) {
        cache_put(db, &format!("ip:{}", ip), info);
        if let Some(c) = info.cidr.as_deref() {
            if cidr::contains(c, ip) {
                cache_put(db, &format!("cidr:{}", c), info);
            }
        }
    }

    pub async fn lookup_batch(ips: &[String]) -> Vec<Info> {
        let cache = open_cache();
        let client = reqwest::Client::builder()
            .user_agent("whobelooking-rdap/0.1")
            .timeout(std::time::Duration::from_secs(12))
            .build()
            .unwrap_or_default();
        let mut out = Vec::with_capacity(ips.len());
        for ip in ips {
            if let Some(db) = &cache {
                if let Some(hit) = cache_lookup(db, ip) {
                    out.push(hit);
                    continue;
                }
            }
            let info = match fetch_one(&client, ip).await {
                Ok(i) => i,
                Err(e) => Info {
                    error: Some(e.to_string()),
                    ..Info::default()
                },
            };
            if let Some(db) = &cache {
                cache_insert(db, ip, &info);
            }
            out.push(info);
            // Be kind to RDAP — 250ms between calls.
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        out
    }

    async fn fetch_one(client: &reqwest::Client, ip: &str) -> anyhow::Result<Info> {
        let url = format!("https://rdap.org/ip/{}", ip);
        let resp = client.get(&url).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("HTTP {}: {}", status, &text[..text.len().min(120)]);
        }
        let v: serde_json::Value = serde_json::from_str(&text)?;
        let mut out = Info {
            handle: v["handle"].as_str().map(|s| s.to_string()),
            name: v["name"].as_str().map(|s| s.to_string()),
            country: v["country"].as_str().map(|s| s.to_string()),
            ..Info::default()
        };
        // CIDR assembly
        if let Some(arr) = v["cidr0_cidrs"].as_array() {
            if let Some(c) = arr.first() {
                let pfx = c["v4prefix"]
                    .as_str()
                    .or_else(|| c["v6prefix"].as_str())
                    .unwrap_or("");
                let len = c["length"].as_u64().unwrap_or(0);
                if !pfx.is_empty() {
                    out.cidr = Some(format!("{}/{}", pfx, len));
                }
            }
        } else if let Some(s) = v["startAddress"].as_str() {
            out.cidr = Some(s.to_string());
        }
        if let Some(arr) = v["remarks"].as_array() {
            for r in arr.iter().take(3) {
                if let Some(s) = r["description"].as_str() {
                    out.remarks.push(s.to_string());
                }
            }
        }
        if let Some(arr) = v["entities"].as_array() {
            for e in arr {
                let roles = e["roles"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                let (fn_, org, kind) = vcard(&e["vcardArray"]);
                let label = match (fn_.as_deref(), org.as_deref(), kind.as_deref()) {
                    (_, Some(o), _) => Some(o.to_string()),
                    (Some(f), _, Some("org")) => Some(f.to_string()),
                    (Some(f), _, _) if !roles.contains("administrative") => Some(f.to_string()),
                    _ => None,
                };
                if out.org.is_none() {
                    if let Some(l) = label.clone() {
                        out.org = Some(l);
                    }
                }
                if roles.contains("administrative") && out.admin.is_none() {
                    if let Some(f) = fn_ {
                        out.admin = Some(f);
                    }
                }
            }
        }
        Ok(out)
    }

    fn vcard(v: &serde_json::Value) -> (Option<String>, Option<String>, Option<String>) {
        let arr = match v.as_array() {
            Some(a) if a.len() >= 2 => &a[1],
            _ => return (None, None, None),
        };
        let entries = match arr.as_array() {
            Some(a) => a,
            None => return (None, None, None),
        };
        let mut fn_ = None;
        let mut org = None;
        let mut kind = None;
        for entry in entries {
            let tup = match entry.as_array() {
                Some(t) if t.len() >= 4 => t,
                _ => continue,
            };
            let key = tup[0].as_str().unwrap_or("");
            let val = tup[3].as_str().map(|s| s.to_string());
            match key {
                "fn" => fn_ = val,
                "org" => org = val,
                "kind" => kind = val,
                _ => {}
            }
        }
        (fn_, org, kind)
    }
}

/// End-to-end intel pipeline orchestrator.  Reads base logs, hits CF GraphQL, runs rDNS + RDAP,
/// emits two HTML files (`intel.unredacted.html` + `intel.redacted.html`).
mod intel {
    use crate::{cf, dns, parse_logs, rdap};
    use std::collections::BTreeMap;
    use whobelooking::redact;

    pub async fn run(
        baselogs_dir: &str,
        cf_token: &str,
        hours: u64,
        out_dir: &str,
    ) -> anyhow::Result<()> {
        std::fs::create_dir_all(out_dir)?;

        // 1. Parse base logs (any *.log under the dir).
        eprintln!("[intel] parsing base logs in {}", baselogs_dir);
        let mut log_files = Vec::new();
        if let Ok(rd) = std::fs::read_dir(baselogs_dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|s| s.to_str()) == Some("log") {
                    if let Some(s) = p.to_str() {
                        log_files.push(s.to_string());
                    }
                }
            }
        }
        log_files.sort();
        let mut base = parse_logs::parse_files(&log_files, hours)?;

        // 2. Drop operator IPs entirely.
        let before = base.len();
        base.retain(|ip, _| !redact::is_operator(ip));
        eprintln!(
            "[intel] {} unique IPs ({} dropped as operator)",
            base.len(),
            before - base.len()
        );

        // 3. Pick priority IPs (top by hits, top per threat tier, top buyers).
        let priority = pick_priority(&base);
        eprintln!("[intel] {} priority IPs for enrichment", priority.len());

        // 4. CF zone discovery + enrichment.
        let zones = cf::list_zones(cf_token).await.unwrap_or_default();
        eprintln!("[intel] {} CF zones visible", zones.len());
        let cf_enrich = if !zones.is_empty() && !priority.is_empty() {
            cf::enrich_ips(cf_token, &zones, &priority, hours)
                .await
                .unwrap_or_default()
        } else {
            BTreeMap::new()
        };

        // 5. rDNS + RDAP for priority IPs only (ignore-listed are already gone).
        let rdns_results = dns::rdns_batch(&priority).await;
        let rdns_map: BTreeMap<String, String> = rdns_results
            .into_iter()
            .map(|(ip, h)| (ip, h.unwrap_or_else(|| "-".to_string())))
            .collect();
        let rdap_results = rdap::lookup_batch(&priority).await;
        let rdap_map: BTreeMap<String, rdap::Info> = priority
            .iter()
            .cloned()
            .zip(rdap_results.into_iter())
            .collect();

        // 6. Save raw artifacts (unredacted) for ops.
        let raw_path = format!("{}/intel.json", out_dir);
        let raw = serde_json::json!({
            "hours": hours,
            "baselogs_dir": baselogs_dir,
            "ips_total": base.len(),
            "base": base,
            "cf_enrich": cf_enrich,
            "rdns": rdns_map,
            "rdap": rdap_map,
        });
        std::fs::write(&raw_path, serde_json::to_string_pretty(&raw)?)?;
        eprintln!("[intel] wrote {}", raw_path);

        // 7. Build HTML — unredacted first, then redacted.
        let html_unredacted = render_html(
            &base, &cf_enrich, &rdns_map, &rdap_map, hours, /*redacted=*/ false,
        );
        let html_redacted = render_html(
            &base, &cf_enrich, &rdns_map, &rdap_map, hours, /*redacted=*/ true,
        );
        let unred_path = format!("{}/intel.unredacted.html", out_dir);
        let red_path = format!("{}/intel.redacted.html", out_dir);
        std::fs::write(&unred_path, &html_unredacted)?;
        std::fs::write(&red_path, &html_redacted)?;
        eprintln!("[intel] wrote {}", unred_path);
        eprintln!("[intel] wrote {}", red_path);
        Ok(())
    }

    fn pick_priority(base: &BTreeMap<String, parse_logs::PerIp>) -> Vec<String> {
        let mut by_class: std::collections::HashMap<&str, Vec<(&String, u32)>> = Default::default();
        let mut all: Vec<(&String, u32)> = base.iter().map(|(k, v)| (k, v.hits)).collect();
        for (ip, p) in base {
            by_class
                .entry(p.class.as_str())
                .or_default()
                .push((ip, p.hits));
        }
        all.sort_by(|a, b| b.1.cmp(&a.1));
        let mut out: Vec<String> = all.iter().take(40).map(|(ip, _)| (*ip).clone()).collect();
        for cls in ["CRED_HUNT", "EXPLOIT", "LLM_PROBE", "BUYER"] {
            if let Some(v) = by_class.get_mut(cls) {
                v.sort_by(|a, b| b.1.cmp(&a.1));
                for (ip, _) in v.iter().take(15) {
                    if !out.contains(*ip) {
                        out.push((*ip).clone());
                    }
                }
            }
        }
        out
    }

    fn render_html(
        base: &BTreeMap<String, parse_logs::PerIp>,
        cf_enrich: &BTreeMap<String, cf::EnrichRecord>,
        rdns: &BTreeMap<String, String>,
        rdap_map: &BTreeMap<String, rdap::Info>,
        hours: u64,
        redacted: bool,
    ) -> String {
        let label = if redacted {
            "REDACTED"
        } else {
            "INTERNAL — UNREDACTED"
        };
        let mut ranked: Vec<(&String, &parse_logs::PerIp)> = base.iter().collect();
        ranked.sort_by(|a, b| b.1.hits.cmp(&a.1.hits));

        // Top-25 rows with per-zone column.
        let mut top_rows = String::new();
        for (ip, p) in ranked.iter().take(25) {
            let display_ip = if redacted {
                redact::redact(ip)
            } else {
                (*ip).clone()
            };
            let cc = p.countries.keys().next().cloned().unwrap_or_default();
            let top_path = p
                .paths
                .iter()
                .max_by_key(|(_, c)| **c)
                .map(|(k, _)| k.clone())
                .unwrap_or_default();
            let rd_raw = rdns.get(*ip).cloned().unwrap_or_else(|| "-".to_string());
            let rd = if redacted {
                redact::redact_text(&rd_raw)
            } else {
                rd_raw
            };
            let org = rdap_map
                .get(*ip)
                .and_then(|r| r.org.clone().or_else(|| r.name.clone()))
                .unwrap_or_else(|| "-".to_string());
            let cf_hits = cf_enrich.get(*ip).map(|e| e.cf_hits).unwrap_or(0);
            let fw = cf_enrich.get(*ip).map(|e| e.firewall_blocks).unwrap_or(0);
            let zones_cell = cf_enrich
                .get(*ip)
                .map(|e| {
                    e.zones
                        .iter()
                        .map(|(z, n)| format!("{} ({})", z, n))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            top_rows.push_str(&format!(
                "<tr><td>{ip}</td><td>{cc}</td><td>{org}</td><td>{rd}</td><td class=r>{base}</td><td class=r>{cf}</td><td class=r>{fw}</td><td>{cls}</td><td>{zones}</td><td>{path}</td></tr>",
                ip = display_ip,
                cc = cc,
                org = htmlesc(&org),
                rd = htmlesc(&rd),
                base = p.hits,
                cf = cf_hits,
                fw = fw,
                cls = p.class,
                zones = htmlesc(&zones_cell),
                path = htmlesc(&top_path),
            ));
        }

        // Cross-site actors: IPs that appeared in 2+ CF zones.
        let mut cross_site: Vec<(&String, &cf::EnrichRecord)> = cf_enrich
            .iter()
            .filter(|(_, e)| e.zones.len() >= 2)
            .collect();
        cross_site.sort_by(|a, b| {
            b.1.zones
                .len()
                .cmp(&a.1.zones.len())
                .then(b.1.cf_hits.cmp(&a.1.cf_hits))
        });
        let mut cross_rows = String::new();
        for (ip, e) in cross_site.iter().take(20) {
            let display_ip = if redacted {
                redact::redact(ip)
            } else {
                (*ip).clone()
            };
            let org = rdap_map
                .get(*ip)
                .and_then(|r| r.org.clone().or_else(|| r.name.clone()))
                .unwrap_or_else(|| "-".to_string());
            let zones_str = e
                .zones
                .iter()
                .map(|(z, n)| format!("{} ({})", z, n))
                .collect::<Vec<_>>()
                .join(", ");
            cross_rows.push_str(&format!(
                "<tr><td>{ip}</td><td class=r>{n}</td><td class=r>{cf}</td><td>{org}</td><td>{zones}</td></tr>",
                ip = display_ip,
                n = e.zones.len(),
                cf = e.cf_hits,
                org = htmlesc(&org),
                zones = htmlesc(&zones_str),
            ));
        }
        let cross_section = if cross_rows.is_empty() {
            "<p style='color:#7d8497;font-size:9pt'>No cross-site actors detected in this window.</p>".to_string()
        } else {
            format!(
                "<table><tr><th>IP</th><th class=r>Zones</th><th class=r>CF hits</th><th>Org</th><th>Zones detail</th></tr>{}</table>",
                cross_rows
            )
        };

        // Per-zone summary: collect all zones and their top-3 IPs.
        let mut zone_map: BTreeMap<String, Vec<(String, u32)>> = BTreeMap::new();
        for (ip, e) in cf_enrich {
            for (zone, hits) in &e.zones {
                zone_map
                    .entry(zone.clone())
                    .or_default()
                    .push((ip.clone(), *hits));
            }
        }
        let mut zone_section = String::new();
        for (zone, mut ips) in zone_map {
            ips.sort_by(|a, b| b.1.cmp(&a.1));
            let rows: String = ips
                .iter()
                .take(5)
                .map(|(ip, hits)| {
                    let display_ip = if redacted {
                        redact::redact(ip)
                    } else {
                        ip.clone()
                    };
                    let org = rdap_map
                        .get(ip.as_str())
                        .and_then(|r| r.org.clone().or_else(|| r.name.clone()))
                        .unwrap_or_else(|| "-".to_string());
                    format!(
                        "<tr><td>{ip}</td><td class=r>{hits}</td><td>{org}</td></tr>",
                        ip = display_ip,
                        hits = hits,
                        org = htmlesc(&org)
                    )
                })
                .collect();
            let _ = std::fmt::write(
                &mut zone_section,
                format_args!(
                    "<h3 style='font-size:10pt;color:#c4d4e0;margin:12pt 0 4pt'>{zone} — {n} IPs</h3>\
                     <table><tr><th>IP</th><th class=r>CF hits</th><th>Org</th></tr>{rows}</table>",
                    zone = htmlesc(&zone),
                    n = ips.len(),
                    rows = rows,
                ),
            );
        }

        // CF firewall block list: THREAT IPs + IPs CF already blocked.
        // Only include real (unredacted) IPs — redacted report gets a stub.
        let fw_section = {
            // Collect candidate IPs: threat class OR CF firewall_blocks > 0.
            let mut block_ips: Vec<(String, String, String)> = Vec::new(); // (ip, reason, org)
            for (ip, p) in &ranked {
                let is_threat = p.class == "threat";
                let fw_hits = cf_enrich.get(*ip).map(|e| e.firewall_blocks).unwrap_or(0);
                if is_threat || fw_hits > 0 {
                    let reason = if is_threat && fw_hits > 0 {
                        format!("THREAT · {} FW blocks", fw_hits)
                    } else if is_threat {
                        "THREAT".to_string()
                    } else {
                        format!("{} FW blocks", fw_hits)
                    };
                    let org = rdap_map
                        .get(*ip)
                        .and_then(|r| r.org.clone().or_else(|| r.name.clone()))
                        .unwrap_or_default();
                    block_ips.push(((*ip).clone(), reason, org));
                }
            }

            if block_ips.is_empty() {
                "<p style='color:#7d8497;font-size:9pt'>No THREAT IPs detected in this window.</p>"
                    .to_string()
            } else if redacted {
                format!(
                    "<p style='color:#e07b5e;font-size:9pt'>{} THREAT/FW IPs — IPs redacted; see internal report for CF rule.</p>",
                    block_ips.len()
                )
            } else {
                let ip_list: Vec<&str> = block_ips.iter().map(|(ip, _, _)| ip.as_str()).collect();
                let expr = if ip_list.len() <= 5 {
                    format!("(ip.src in {{{}}})", ip_list.join(" "))
                } else {
                    format!("(ip.src in {{\n  {}\n}})", ip_list.join("\n  "))
                };
                let mut detail_rows = String::new();
                for (ip, reason, org) in &block_ips {
                    let rd = rdns.get(ip.as_str()).cloned().unwrap_or_default();
                    detail_rows.push_str(&format!(
                        "<tr><td><code>{ip}</code></td><td>{reason}</td><td>{org}</td><td style='font-size:8pt;color:#9ba2b3'>{rd}</td></tr>",
                        ip = htmlesc(ip),
                        reason = htmlesc(reason),
                        org = htmlesc(org),
                        rd = htmlesc(&rd),
                    ));
                }
                format!(
                    r#"<p style='font-size:8pt;color:#9ba2b3;margin:0 0 6pt'>{n} IPs — paste directly into Cloudflare Firewall → Create custom rule → Edit expression.</p>
<pre style='background:#2c3346;color:#e07b5e;padding:10pt 12pt;border-radius:4pt;font-size:8pt;overflow-x:auto;white-space:pre-wrap;word-break:break-all'>{expr}</pre>
<table><tr><th>IP</th><th>Reason</th><th>Org</th><th>rDNS</th></tr>{detail_rows}</table>"#,
                    n = block_ips.len(),
                    expr = htmlesc(&expr),
                    detail_rows = detail_rows,
                )
            }
        };

        format!(
            r#"<!doctype html><html><head><meta charset=utf-8>
<title>WHOBELOOKING — {label} — last {hours}h</title>
<style>
@page {{ size: letter; margin: 0.6in; background: #1a1f2e; }}
html, body {{ background: #1a1f2e; }}
body {{ font: 10pt/1.45 'Helvetica Neue',Arial,sans-serif; color: #d8d4cc; padding: 0.6in; margin:0; }}
h1 {{ font-size:18pt; color:#f1ede4; letter-spacing:.04em; margin:0 0 4pt; }}
h2 {{ font-size:12pt; color:#f1ede4; text-transform:uppercase; letter-spacing:.05em;
      border-bottom:2px solid #4a5670; padding:14pt 0 4pt; margin:0; }}
h3 {{ font-size:10pt; color:#c4d4e0; margin:12pt 0 4pt; }}
.classification {{ font-size:7pt; letter-spacing:.3em; text-transform:uppercase; color:#e07b5e;
      text-align:center; padding:4pt 0; border:1px solid #6b4338;
      background:rgba(224,123,94,.06); margin-bottom:14pt; }}
.header {{ border-bottom:3px solid #4a5670; padding-bottom:8pt; margin-bottom:14pt; }}
.header .sub {{ font-size:8pt; color:#9ba2b3; margin-top:4pt; }}
table {{ width:100%; border-collapse:collapse; font-size:9pt; margin:6pt 0 12pt; }}
th {{ background:#2c3346; color:#f1ede4; text-align:left; padding:5pt 8pt;
      font-size:8pt; letter-spacing:.05em; text-transform:uppercase; }}
td {{ padding:4pt 8pt; border-bottom:1px solid #2c3346; vertical-align:top; }}
tr:nth-child(even) td {{ background:#1f2536; }}
td.r {{ text-align:right; }}
code {{ font-family:'SF Mono',Consolas,monospace; font-size:8pt;
       background:#2c3346; color:#c4d4e0; padding:1pt 3pt; border-radius:2pt; }}
pre {{ font-family:'SF Mono',Consolas,monospace; }}
.footer {{ margin-top:16pt; padding-top:6pt; border-top:1px solid #4a5670;
       font-size:7pt; color:#7d8497; text-align:center; }}
</style></head><body>
<div class=classification>Confidential — {label} — The Cochran Block, LLC</div>
<div class=header>
<h1>WHOBELOOKING — FLEET INTEL ({hours}h)</h1>
<div class=sub>Source: app base logs + CF GraphQL (24h chunks) · rDNS · RDAP whois<br>
Generated: <code>whobelooking intel</code></div>
</div>

<h2>Top 25 IPs</h2>
<table>
<tr><th>IP</th><th>CC</th><th>Org (RDAP)</th><th>rDNS</th><th class=r>Base</th><th class=r>CF</th><th class=r>FW</th><th>Class</th><th>Zones</th><th>Top path</th></tr>
{top_rows}
</table>

<h2>CF Firewall Block List</h2>
{fw_section}

<h2>Cross-Site Actors</h2>
<p style='font-size:8pt;color:#9ba2b3;margin:0 0 6pt'>IPs observed across 2 or more of your CF zones in this window.</p>
{cross_section}

<h2>Per-Zone Summary</h2>
<p style='font-size:8pt;color:#9ba2b3;margin:0 0 6pt'>Top 5 IPs per zone by CF hit count.</p>
{zone_section}

<div class=footer>Unlicense — public domain — The Cochran Block, LLC — operator IP filtered via ignore-list — {label}</div>
</body></html>"#,
            label = label,
            hours = hours,
            top_rows = top_rows,
            fw_section = fw_section,
            cross_section = cross_section,
            zone_section = zone_section,
        )
    }

    fn htmlesc(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }
}

mod actor_history {
    use redb::{Database, ReadableTable, TableDefinition};
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("actors");

    #[derive(Serialize, Deserialize, Default, Clone)]
    pub struct ActorRecord {
        pub first_seen: i64,
        pub last_seen: i64,
        pub total_hits: u32,
        pub total_reports: u32,
        pub last_class: String,
    }

    fn db_path() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("whobelooking")
            .join("actors.redb")
    }

    fn open_db() -> Option<Database> {
        let p = db_path();
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        Database::create(&p).ok()
    }

    pub fn lookup(ips: &[String]) -> BTreeMap<String, ActorRecord> {
        let db = match open_db() {
            Some(db) => db,
            None => return BTreeMap::new(),
        };
        let rtx = match db.begin_read() {
            Ok(tx) => tx,
            Err(_) => return BTreeMap::new(),
        };
        let table = match rtx.open_table(TABLE) {
            Ok(t) => t,
            Err(_) => return BTreeMap::new(),
        };
        let mut out = BTreeMap::new();
        for ip in ips {
            if let Ok(Some(v)) = table.get(ip.as_str()) {
                if let Ok((rec, _)) = bincode::serde::decode_from_slice::<ActorRecord, _>(
                    v.value(),
                    bincode::config::standard(),
                ) {
                    out.insert(ip.clone(), rec);
                }
            }
        }
        out
    }

    pub fn update(ips: &BTreeMap<String, wbl_detect::t105>) {
        let db = match open_db() {
            Some(db) => db,
            None => return,
        };
        let wtx = match db.begin_write() {
            Ok(tx) => tx,
            Err(_) => return,
        };
        {
            let mut table = match wtx.open_table(TABLE) {
                Ok(t) => t,
                Err(_) => return,
            };
            for (ip, rec) in ips {
                let class = rec.class.map(|c| c.name().to_string()).unwrap_or_default();
                let new_rec = if let Ok(Some(v)) = table.get(ip.as_str()) {
                    let bytes: &[u8] = v.value();
                    if let Ok((existing, _)) = bincode::serde::decode_from_slice::<ActorRecord, _>(
                        bytes,
                        bincode::config::standard(),
                    ) {
                        ActorRecord {
                            first_seen: existing.first_seen.min(rec.first_unix),
                            last_seen: existing.last_seen.max(rec.last_unix),
                            total_hits: existing.total_hits.saturating_add(rec.hits),
                            total_reports: existing.total_reports + 1,
                            last_class: class,
                        }
                    } else {
                        ActorRecord {
                            first_seen: rec.first_unix,
                            last_seen: rec.last_unix,
                            total_hits: rec.hits,
                            total_reports: 1,
                            last_class: class,
                        }
                    }
                } else {
                    ActorRecord {
                        first_seen: rec.first_unix,
                        last_seen: rec.last_unix,
                        total_hits: rec.hits,
                        total_reports: 1,
                        last_class: class,
                    }
                };
                if let Ok(encoded) =
                    bincode::serde::encode_to_vec(&new_rec, bincode::config::standard())
                {
                    let _ = table.insert(ip.as_str(), encoded.as_slice());
                }
            }
        }
        let _ = wtx.commit();
    }
}

mod dns {
    use hickory_resolver::TokioResolver;
    use hickory_resolver::lookup::Lookup;
    use hickory_resolver::proto::rr::RData;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;

    const ISP_PATTERNS: &[&str] = &[
        "spectrum",
        "comcast",
        "verizon",
        "sbcglobal",
        "att.net",
        "cox",
        "cable",
        "pool-",
        "dsl",
        "dhcp",
        "static-",
        "cpe.",
        "res.",
        "biz.",
        "biz6.",
        "inf6.",
        "lightspeed",
        "hsd1.",
        "socal.",
        "nycmny",
        "rr.com",
        "charter.com",
        "alticeusa",
    ];

    fn make_resolver() -> TokioResolver {
        // hickory 0.26: builder_tokio() and build() are both fallible. Falling
        // back to a default config keeps lookups working when /etc/resolv.conf
        // is missing or malformed (containers, minimal images), which is the
        // same posture as 0.25 where build() was infallible.
        let builder = TokioResolver::builder_tokio().unwrap_or_else(|_| {
            TokioResolver::builder_with_config(Default::default(), Default::default())
        });
        builder.build().unwrap_or_else(|_| {
            TokioResolver::builder_with_config(Default::default(), Default::default())
                .build()
                .expect("default-config resolver must build")
        })
    }

    fn hostname_from_lookup(lookup: Lookup) -> Option<String> {
        // 0.26 returns a generic Lookup (not a ReverseLookup type). Walk the
        // answer records, pick the first PTR's name, strip the trailing dot.
        // `data` is a public field on Record in 0.26 (was a method via RecordRef).
        lookup.answers().iter().find_map(|r| match &r.data {
            RData::PTR(n) => Some(n.to_string().trim_end_matches('.').to_string()),
            _ => None,
        })
    }

    pub async fn rdns_batch(ips: &[String]) -> Vec<(String, Option<String>)> {
        let resolver = make_resolver();
        let mut results = Vec::new();
        for ip in ips {
            let addr = match IpAddr::from_str(ip) {
                Ok(a) => a,
                Err(_) => {
                    results.push((ip.clone(), None));
                    continue;
                }
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
            let rdns = tokio::time::timeout(
                Duration::from_secs(2),
                resolver.reverse_lookup(neighbor_addr),
            )
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

    pub async fn run(
        zone: &str,
        token: &str,
        date: Option<&str>,
        country: &str,
        min_hits: u32,
        scan_neighbors: bool,
    ) -> anyhow::Result<()> {
        eprintln!("pulling visitors from Cloudflare...");
        let visitors = cf::pull(zone, token, date, country, min_hits).await?;
        eprintln!("{} IPs above {} hits", visitors.len(), min_hits);

        let ips: Vec<String> = visitors.iter().map(|v| v.ip.clone()).collect();
        eprintln!("running rDNS on {} IPs...", ips.len());
        let rdns_results = dns::rdns_batch(&ips).await;

        println!("{:<6} {:<42} {:<55} Neighbors", "Hits", "IP", "rDNS");
        println!("{}", "=".repeat(130));

        for (v, (_ip, rdns)) in visitors.iter().zip(rdns_results.iter()) {
            let rdns_str = rdns.as_deref().unwrap_or("-");

            let mut neighbor_str = String::new();
            if scan_neighbors && rdns.is_none() {
                // Only scan /24 for IPv4 with no rDNS (most likely to reveal company)
                if !v.ip.contains(':') {
                    if let Ok(neighbors) = dns::scan_neighbors(&v.ip, true).await {
                        if !neighbors.is_empty() {
                            let names: Vec<&str> =
                                neighbors.iter().map(|(_, h)| h.as_str()).take(3).collect();
                            neighbor_str = names.join(", ");
                        }
                    }
                }
            }

            println!(
                "{:<6} {:<42} {:<55} {}",
                v.hits, v.ip, rdns_str, neighbor_str
            );
        }

        Ok(())
    }
}

#[cfg(feature = "browser")]
mod browse {
    use std::path::Path;
    use std::time::Duration;

    /// Long-lived headless Chrome session for multiple fetches in one run.
    /// Reused by ctos puller + email scraper to avoid launching Chrome per URL.
    pub struct Session {
        browser: chromiumoxide::Browser,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Session {
        pub async fn open() -> anyhow::Result<Self> {
            let config = browser_config().await.map_err(|e| anyhow::anyhow!(e))?;
            let (browser, mut handler) = chromiumoxide::Browser::launch(config)
                .await
                .map_err(|e| anyhow::anyhow!("launch: {}", e))?;
            let handle = tokio::spawn(async move {
                while futures::StreamExt::next(&mut handler).await.is_some() {}
            });
            Ok(Session { browser, handle })
        }

        /// Navigate, wait for JS, return innerText. Empty string on any failure.
        pub async fn fetch_text(&self, url: &str, wait_secs: u64) -> anyhow::Result<String> {
            let page = self
                .browser
                .new_page("about:blank")
                .await
                .map_err(|e| anyhow::anyhow!("new_page: {}", e))?;
            if page.goto(url).await.is_err() {
                let _ = page.close().await;
                return Ok(String::new());
            }
            tokio::time::sleep(Duration::from_secs(wait_secs)).await;
            let text = page
                .evaluate("document.body.innerText")
                .await
                .ok()
                .and_then(|v| v.into_value::<String>().ok())
                .unwrap_or_default();
            let _ = page.close().await;
            Ok(text)
        }

        pub async fn close(mut self) {
            let _ = self.browser.close().await;
            self.handle.abort();
        }
    }

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
        let info = fetcher
            .fetch()
            .await
            .map_err(|e| format!("fetcher: {}", e))?;
        chromiumoxide::BrowserConfig::builder()
            .chrome_executable(info.executable_path)
            .build()
            .map_err(|e| format!("browser config: {}", e))
    }

    pub async fn run(
        url: &str,
        out_dir: &str,
        wait: u64,
        extract: bool,
        mobile: bool,
    ) -> anyhow::Result<()> {
        let out = Path::new(out_dir);
        std::fs::create_dir_all(out)?;

        eprintln!(
            "[browse] launching headless chrome{}...",
            if mobile { " (mobile)" } else { "" }
        );
        let config = browser_config().await.map_err(|e| anyhow::anyhow!(e))?;
        let (mut browser, mut handler) = chromiumoxide::Browser::launch(config)
            .await
            .map_err(|e| anyhow::anyhow!("launch: {}", e))?;

        let handle =
            tokio::spawn(
                async move { while futures::StreamExt::next(&mut handler).await.is_some() {} },
            );

        let page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| anyhow::anyhow!("new_page: {}", e))?;

        // Set mobile viewport if requested (iPhone 14: 390x844)
        if mobile {
            // Set mobile viewport — CSS pixels, not device pixels
            // device_scale_factor affects rendering density but NOT media query breakpoints
            let _ = page.evaluate("window.resizeTo(390, 844)").await;
            use chromiumoxide::cdp::browser_protocol::emulation::SetDeviceMetricsOverrideParams;
            if let Ok(params) = SetDeviceMetricsOverrideParams::builder()
                .width(390)
                .height(844)
                .device_scale_factor(1.0)
                .mobile(true)
                .build()
            {
                let _ = page.execute(params).await;
            }
        }

        eprintln!("[browse] navigating to {}...", url);
        let _ = page
            .goto(url)
            .await
            .map_err(|e| anyhow::anyhow!("goto: {}", e))?;
        tokio::time::sleep(Duration::from_secs(wait)).await;

        // Screenshot
        let slug: String = url
            .chars()
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
        )
        .await
        .map_err(|e| anyhow::anyhow!("screenshot: {}", e))?;
        eprintln!("[browse] screenshot saved: {}", screenshot_path.display());

        // Debug mobile viewport
        if mobile {
            if let Ok(w) = page.evaluate("JSON.stringify({w:window.innerWidth, navDisplay:getComputedStyle(document.querySelector('.nav-links')).display, checked:document.getElementById('nav-check').checked})").await {
                eprintln!("[browse] mobile debug: {}", w.into_value::<String>().unwrap_or_default());
            }
        }

        // Extract text — use innerText for clean rendered content (no CSS/JS noise)
        if extract {
            let text = page
                .evaluate("document.body.innerText")
                .await
                .map_err(|e| anyhow::anyhow!("evaluate: {}", e))?
                .into_value::<String>()
                .unwrap_or_default();
            println!("{}", text);
        }

        let _ = browser.close().await;
        handle.abort();
        Ok(())
    }

    /// Render a URL or local HTML file to PDF via Chrome DevTools `Page.printToPDF`.
    pub async fn pdf(
        input: &str,
        out_path: &str,
        wait: u64,
        landscape: bool,
        background: bool,
    ) -> anyhow::Result<()> {
        use chromiumoxide::cdp::browser_protocol::page::PrintToPdfParams;

        let url = if input.starts_with("http://") || input.starts_with("https://") {
            input.to_string()
        } else {
            let abs = std::fs::canonicalize(input)
                .map_err(|e| anyhow::anyhow!("canonicalize {}: {}", input, e))?;
            format!("file://{}", abs.display())
        };

        eprintln!("[pdf] launching headless chrome...");
        let config = browser_config().await.map_err(|e| anyhow::anyhow!(e))?;
        let (mut browser, mut handler) = chromiumoxide::Browser::launch(config)
            .await
            .map_err(|e| anyhow::anyhow!("launch: {}", e))?;
        let handle =
            tokio::spawn(
                async move { while futures::StreamExt::next(&mut handler).await.is_some() {} },
            );

        let page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| anyhow::anyhow!("new_page: {}", e))?;

        eprintln!("[pdf] navigating to {}...", url);
        page.goto(&url)
            .await
            .map_err(|e| anyhow::anyhow!("goto: {}", e))?;
        tokio::time::sleep(Duration::from_secs(wait)).await;

        let params = PrintToPdfParams {
            landscape: Some(landscape),
            print_background: Some(background),
            prefer_css_page_size: Some(true),
            ..Default::default()
        };
        let bytes = page
            .pdf(params)
            .await
            .map_err(|e| anyhow::anyhow!("printToPDF: {}", e))?;

        if let Some(parent) = Path::new(out_path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(out_path, &bytes)?;
        eprintln!("[pdf] wrote {} ({} bytes)", out_path, bytes.len());

        let _ = page.close().await;
        let _ = browser.close().await;
        handle.abort();
        Ok(())
    }

    /// Perf benchmark — measure render performance via Chrome DevTools Protocol.
    /// Uses CDP Network domain for real transfer sizes (not Performance API which
    /// returns 0 for cross-origin resources without CORS headers).
    pub async fn perf(url: &str, wait: u64) -> anyhow::Result<()> {
        use chromiumoxide::cdp::browser_protocol::network::{
            EnableParams, EventLoadingFinished, EventResponseReceived, SetCacheDisabledParams,
        };
        use std::sync::Arc;
        use tokio::sync::Mutex;

        eprintln!("[perf] launching headless chrome...");
        let config = browser_config().await.map_err(|e| anyhow::anyhow!(e))?;
        let (mut browser, mut handler) = chromiumoxide::Browser::launch(config)
            .await
            .map_err(|e| anyhow::anyhow!("launch: {}", e))?;

        let handle =
            tokio::spawn(
                async move { while futures::StreamExt::next(&mut handler).await.is_some() {} },
            );

        let page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| anyhow::anyhow!("new_page: {}", e))?;

        // Enable CDP Network domain + disable cache so encodedDataLength is real
        let _ = page.execute(EnableParams::default()).await;
        let _ = page.execute(SetCacheDisabledParams::new(true)).await;

        // Subscribe to network events BEFORE navigation
        let total_bytes = Arc::new(Mutex::new(0u64));
        let request_count = Arc::new(Mutex::new(0u64));
        let resource_types: Arc<Mutex<std::collections::HashMap<String, u64>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));

        // Listen for LoadingFinished (has real encodedDataLength)
        let bytes_clone = total_bytes.clone();
        let count_clone = request_count.clone();
        let mut loading_events = page
            .event_listener::<EventLoadingFinished>()
            .await
            .map_err(|e| anyhow::anyhow!("listen loading: {}", e))?;
        tokio::spawn(async move {
            while let Some(ev) = futures::StreamExt::next(&mut loading_events).await {
                let mut b = bytes_clone.lock().await;
                *b += ev.encoded_data_length as u64;
                let mut c = count_clone.lock().await;
                *c += 1;
            }
        });

        // Listen for ResponseReceived (has resource type)
        let types_clone = resource_types.clone();
        let mut response_events = page
            .event_listener::<EventResponseReceived>()
            .await
            .map_err(|e| anyhow::anyhow!("listen response: {}", e))?;
        tokio::spawn(async move {
            while let Some(ev) = futures::StreamExt::next(&mut response_events).await {
                let rtype = format!("{:?}", ev.r#type);
                let mut t = types_clone.lock().await;
                *t.entry(rtype).or_insert(0) += 1;
            }
        });

        eprintln!("[perf] navigating to {}...", url);
        let _ = page.goto(url).await;
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;

        // Performance timing
        let timing = page
            .evaluate("JSON.stringify(performance.timing)")
            .await
            .map_err(|e| anyhow::anyhow!("timing: {}", e))?
            .into_value::<String>()
            .unwrap_or_default();

        // Paint metrics
        let paint = page
            .evaluate("JSON.stringify(performance.getEntriesByType('paint'))")
            .await
            .map_err(|e| anyhow::anyhow!("paint: {}", e))?
            .into_value::<String>()
            .unwrap_or_default();

        // Layout shift
        let cls = page.evaluate(
            "new Promise(r => { let c=0; new PerformanceObserver(l => { l.getEntries().forEach(e => c += e.value); r(c); }).observe({type:'layout-shift',buffered:true}); setTimeout(() => r(c), 2000); })"
        ).await.map_err(|e| anyhow::anyhow!("cls: {}", e))?
            .into_value::<f64>().unwrap_or(0.0);

        // DOM element count
        let dom_elements = page
            .evaluate("document.querySelectorAll('*').length")
            .await
            .map_err(|e| anyhow::anyhow!("dom: {}", e))?
            .into_value::<f64>()
            .unwrap_or(0.0);

        // Animation frame rate
        let fps = page.evaluate(
            "new Promise(r => { let frames=0; let start=performance.now(); function count(){frames++;if(performance.now()-start<2000){requestAnimationFrame(count)}else{r(Math.round(frames/((performance.now()-start)/1000)))}} requestAnimationFrame(count); })"
        ).await.map_err(|e| anyhow::anyhow!("fps: {}", e))?
            .into_value::<f64>().unwrap_or(0.0);

        // Read CDP network totals
        let cdp_bytes = *total_bytes.lock().await;
        let cdp_requests = *request_count.lock().await;
        let cdp_types = resource_types.lock().await.clone();

        // Parse and display
        println!("\n=== RENDER PERFORMANCE: {} ===\n", url);

        if let Ok(t) = serde_json::from_str::<serde_json::Value>(&timing) {
            let nav_start = t["navigationStart"].as_f64().unwrap_or(0.0);
            let dom_complete = t["domComplete"].as_f64().unwrap_or(0.0) - nav_start;
            let load_end = t["loadEventEnd"].as_f64().unwrap_or(0.0) - nav_start;
            let dom_interactive = t["domInteractive"].as_f64().unwrap_or(0.0) - nav_start;
            let response_end = t["responseEnd"].as_f64().unwrap_or(0.0) - nav_start;
            println!("  TTFB (response end):     {:.0}ms", response_end);
            println!("  DOM Interactive:         {:.0}ms", dom_interactive);
            println!("  DOM Complete:            {:.0}ms", dom_complete);
            println!("  Load Event End:          {:.0}ms", load_end);
        }

        if let Ok(paints) = serde_json::from_str::<Vec<serde_json::Value>>(&paint) {
            for p in &paints {
                let name = p["name"].as_str().unwrap_or("");
                let time = p["startTime"].as_f64().unwrap_or(0.0);
                println!("  {:<27}{:.0}ms", format!("{}:", name), time);
            }
        }

        println!("  FPS (2s sample):         {:.0}", fps);
        println!("  CLS (layout shift):      {:.4}", cls);
        println!("  DOM elements:            {:.0}", dom_elements);

        // CDP network — real transfer sizes
        println!("\n  --- NETWORK (CDP) ---");
        println!(
            "  Total transfer:          {} ({:.0} KB)",
            cdp_bytes,
            cdp_bytes as f64 / 1024.0
        );
        println!("  Requests:                {}", cdp_requests);
        let mut type_vec: Vec<_> = cdp_types.iter().collect();
        type_vec.sort_by(|a, b| b.1.cmp(a.1));
        for (rtype, count) in &type_vec {
            println!("    {:<22} {}", rtype, count);
        }

        // Verdict
        println!("\n  --- VERDICT ---");
        if fps >= 55.0 {
            println!("  FPS:  PASS ({:.0} fps)", fps);
        } else {
            println!("  FPS:  FAIL ({:.0} fps — should be 60)", fps);
        }
        if cls < 0.1 {
            println!("  CLS:  PASS ({:.4} — under 0.1 threshold)", cls);
        } else {
            println!("  CLS:  FAIL ({:.4} — over 0.1 threshold)", cls);
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
        eprintln!(
            "[scrape] {} cached, {} remaining",
            total - todo.len(),
            todo.len()
        );
        if todo.is_empty() {
            return Ok(());
        }

        eprintln!("[scrape] launching headless chrome...");
        let config = browser_config().await.map_err(|e| anyhow::anyhow!(e))?;
        let (browser, mut handler) = chromiumoxide::Browser::launch(config)
            .await
            .map_err(|e| anyhow::anyhow!("launch: {}", e))?;

        let handle =
            tokio::spawn(
                async move { while futures::StreamExt::next(&mut handler).await.is_some() {} },
            );

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
                // `acquire` only errors after `sem.close()`, which we never call.
                let _permit = sem
                    .acquire()
                    .await
                    .expect("scrape semaphore should not be closed");
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
            .map(|c| {
                if c.is_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
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
        let page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| anyhow::anyhow!("new_page: {}", e))?;
        let _ = page
            .goto(url)
            .await
            .map_err(|e| anyhow::anyhow!("goto: {}", e))?;
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;

        // Screenshot
        use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
        use chromiumoxide::page::ScreenshotParams;
        let _ = page
            .save_screenshot(
                ScreenshotParams::builder()
                    .format(CaptureScreenshotFormat::Png)
                    .full_page(true)
                    .build(),
                png,
            )
            .await;

        // Extract text — innerText gives clean rendered content
        if let Ok(val) = page.evaluate("document.body.innerText").await {
            let text = val.into_value::<String>().unwrap_or_default();
            let _ = std::fs::write(txt, &text);
        }

        let _ = page.close().await;
        Ok(())
    }
}

// =============================================================================
// ctos — cross-verified CTO OSINT scout
// =============================================================================
//
// Rules (never violate):
//   1. Every contact field must come from a real, observed source URL.
//   2. Never derive emails from company-name heuristics. Scrape or skip.
//   3. A CTO is "verified" only when the same name + company appears in
//      2+ distinct source types (hn, yc, github, reddit, podcasts).
//   4. Drafts are only written when a scraped email exists for the CTO.
//      No email → no draft. Period.
//
#[cfg(feature = "browser")]
mod ctos {
    use crate::CtosOp;
    use crate::browse;
    use redb::{Database, TableDefinition};
    use serde::{Deserialize, Serialize};

    const CTO_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("cto");

    fn db_get(db: &Database, key: &str) -> Option<Vec<u8>> {
        let txn = db.begin_read().ok()?;
        let tbl = txn.open_table(CTO_TABLE).ok()?;
        tbl.get(key.as_bytes()).ok()?.map(|g| g.value().to_vec())
    }

    fn db_insert_is_new(db: &Database, key: &str, val: &[u8]) -> bool {
        (|| -> anyhow::Result<bool> {
            let txn = db.begin_write()?;
            let is_new = {
                let mut tbl = txn.open_table(CTO_TABLE)?;
                tbl.insert(key.as_bytes(), val)?.is_none()
            };
            txn.commit()?;
            Ok(is_new)
        })()
        .unwrap_or(false)
    }

    fn db_put(db: &Database, key: &str, val: &[u8]) {
        let _ = (|| -> anyhow::Result<()> {
            let txn = db.begin_write()?;
            {
                let mut tbl = txn.open_table(CTO_TABLE)?;
                tbl.insert(key.as_bytes(), val)?;
            }
            txn.commit()?;
            Ok(())
        })();
    }

    fn db_scan_values_prefix(db: &Database, prefix: &[u8]) -> Vec<Vec<u8>> {
        let Ok(txn) = db.begin_read() else {
            return vec![];
        };
        let tbl = match txn.open_table(CTO_TABLE) {
            Ok(t) => t,
            Err(_) => return vec![],
        };
        let mut out = Vec::new();
        if let Ok(range) = tbl.range(prefix..) {
            for entry in range.flatten() {
                let (k, v) = entry;
                if !k.value().starts_with(prefix) {
                    break;
                }
                out.push(v.value().to_vec());
            }
        }
        out
    }

    fn db_count_prefix(db: &Database, prefix: &[u8]) -> usize {
        db_scan_values_prefix(db, prefix).len()
    }

    // Pure logic lives in the lib crate so the test binary can exercise it
    // without launching Chrome. Re-export for the pullers + commands below.
    pub use whobelooking::ctos::{
        CtoMention, extract_cto_from_text, extract_first_email, norm, norm_company, now_secs,
        slugify, today_iso, truncate, verify,
    };

    // ----- Contact record (redb-backed type, stays here) -----

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct CtoContact {
        pub email: String,
        pub email_source_url: String,
        pub scraped_at: u64,
    }

    // ----- Redb I/O -----

    fn open_db() -> Database {
        let dir = dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join("whobelooking");
        let _ = std::fs::create_dir_all(&dir);
        Database::create(dir.join("cto.redb")).expect("open redb cto")
    }

    fn hash_str(s: &str) -> String {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        s.hash(&mut h);
        format!("{:016x}", h.finish())
    }

    fn compress(data: &[u8]) -> Vec<u8> {
        zstd::encode_all(data, 3).unwrap_or_else(|_| data.to_vec())
    }
    fn decompress(data: &[u8]) -> Vec<u8> {
        zstd::decode_all(data).unwrap_or_else(|_| data.to_vec())
    }

    pub fn cache_mention(db: &Database, m: &CtoMention) -> bool {
        let uniq = format!("{}|{}|{}", m.source_url, m.name, m.company);
        let key = format!("cto:mention:{}:{}", m.source, hash_str(&uniq));
        let Ok(buf) = serde_json::to_vec(m) else {
            return false;
        };
        db_insert_is_new(db, &key, &compress(&buf))
    }

    pub fn load_mentions(db: &Database) -> Vec<CtoMention> {
        db_scan_values_prefix(db, b"cto:mention:")
            .into_iter()
            .filter_map(|v| serde_json::from_slice::<CtoMention>(&decompress(&v)).ok())
            .collect()
    }

    fn contact_key(name: &str, company: &str) -> String {
        format!("{}|{}", norm(name), norm_company(company))
    }

    fn cache_contact(db: &Database, key: &str, c: &CtoContact) {
        let k = format!("cto:contact:{}", key);
        if let Ok(buf) = serde_json::to_vec(c) {
            db_put(db, &k, &compress(&buf));
        }
    }

    fn load_contact(db: &Database, key: &str) -> Option<CtoContact> {
        let k = format!("cto:contact:{}", key);
        db_get(db, &k).and_then(|v| serde_json::from_slice::<CtoContact>(&decompress(&v)).ok())
    }

    // ----- URL / HTML helpers used by the pullers -----

    /// Minimal URL-encoder (alnum + unreserved stay raw, others become %HH).
    fn urlencode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char);
                }
                b' ' => out.push('+'),
                _ => out.push_str(&format!("%{:02X}", b)),
            }
        }
        out
    }

    fn strip_html_simple(s: &str) -> String {
        s.chars()
            .fold((String::new(), false), |(mut out, in_tag), c| match c {
                '<' => (out, true),
                '>' => (out, false),
                _ if !in_tag => {
                    out.push(c);
                    (out, false)
                }
                _ => (out, true),
            })
            .0
    }

    // =========================================================================
    // Source pullers
    // =========================================================================

    mod hn {
        use super::*;

        /// HN Algolia search — no auth, covers stories + comments.
        pub async fn pull(keyword: &str) -> anyhow::Result<Vec<CtoMention>> {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .user_agent("whobelooking/0.1 (+https://cochranblock.org)")
                .build()?;
            let query = if keyword.is_empty() {
                "I'm the CTO"
            } else {
                keyword
            };
            let enc = urlencode(query);
            let mut out = Vec::new();

            // Comments thread — "I'm the CTO of X" style mentions
            let curl = format!(
                "https://hn.algolia.com/api/v1/search?query={}&tags=comment&hitsPerPage=100",
                enc
            );
            if let Ok(resp) = client.get(&curl).send().await {
                if let Ok(v) = resp.json::<serde_json::Value>().await {
                    let hits = v["hits"].as_array().cloned().unwrap_or_default();
                    for hit in hits {
                        let text = hit["comment_text"].as_str().unwrap_or("");
                        let clean = strip_html_simple(text);
                        let story_id = hit["story_id"].as_u64().unwrap_or(0);
                        let obj_id = hit["objectID"].as_str().unwrap_or("");
                        let item_url = if story_id > 0 {
                            format!("https://news.ycombinator.com/item?id={}", story_id)
                        } else {
                            format!("https://news.ycombinator.com/item?id={}", obj_id)
                        };
                        let author = hit["author"].as_str().unwrap_or("").to_string();
                        for mut m in extract_cto_from_text(&clean, "hn", &item_url) {
                            m.handle = author.clone();
                            out.push(m);
                        }
                    }
                }
            }

            // Story threads — launch posts, founder announcements
            let surl = format!(
                "https://hn.algolia.com/api/v1/search?query={}&tags=story&hitsPerPage=50",
                enc
            );
            if let Ok(resp) = client.get(&surl).send().await {
                if let Ok(v) = resp.json::<serde_json::Value>().await {
                    let hits = v["hits"].as_array().cloned().unwrap_or_default();
                    for hit in hits {
                        let text = format!(
                            "{} {}",
                            hit["title"].as_str().unwrap_or(""),
                            hit["story_text"].as_str().unwrap_or("")
                        );
                        let clean = strip_html_simple(&text);
                        let obj_id = hit["objectID"].as_str().unwrap_or("");
                        let item_url = format!("https://news.ycombinator.com/item?id={}", obj_id);
                        out.extend(extract_cto_from_text(&clean, "hn", &item_url));
                    }
                }
            }

            Ok(out)
        }
    }

    mod github {
        use super::*;

        /// GitHub user search — bio field filtered on "cto".
        /// Populates name + company + email directly from profile API (real,
        /// not derived). Uses GITHUB_TOKEN if set to raise rate limits.
        pub async fn pull(keyword: &str) -> anyhow::Result<Vec<CtoMention>> {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .user_agent("whobelooking/0.1 (+https://cochranblock.org)")
                .build()?;
            let token = std::env::var("GITHUB_TOKEN").ok();
            let q = if keyword.is_empty() { "cto" } else { keyword };
            let search_url = format!(
                "https://api.github.com/search/users?q={}+in:bio&per_page=30",
                urlencode(q)
            );
            let mut req = client
                .get(&search_url)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28");
            if let Some(t) = &token {
                req = req.header("Authorization", format!("Bearer {}", t));
            }
            let resp: serde_json::Value = match req.send().await {
                Ok(r) => r.json().await.unwrap_or(serde_json::Value::Null),
                Err(e) => return Err(anyhow::anyhow!("github search: {}", e)),
            };
            let items = resp["items"].as_array().cloned().unwrap_or_default();
            let mut out = Vec::new();
            for item in items.into_iter().take(30) {
                let login = item["login"].as_str().unwrap_or("");
                if login.is_empty() {
                    continue;
                }
                let prof_url = format!("https://api.github.com/users/{}", login);
                let mut preq = client
                    .get(&prof_url)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28");
                if let Some(t) = &token {
                    preq = preq.header("Authorization", format!("Bearer {}", t));
                }
                let prof: serde_json::Value = match preq.send().await {
                    Ok(r) => r.json().await.unwrap_or(serde_json::Value::Null),
                    Err(_) => continue,
                };
                let name = prof["name"].as_str().unwrap_or("").trim().to_string();
                let bio = prof["bio"].as_str().unwrap_or("").to_string();
                let company_raw = prof["company"].as_str().unwrap_or("").trim().to_string();
                let blog = prof["blog"].as_str().unwrap_or("").trim().to_string();
                let public_email = prof["email"].as_str().unwrap_or("").trim().to_string();
                let html_url = prof["html_url"].as_str().unwrap_or("").to_string();
                let html_url = if html_url.is_empty() {
                    format!("https://github.com/{}", login)
                } else {
                    html_url
                };

                let bio_lower = bio.to_lowercase();
                if !bio_lower.contains("cto") && !bio_lower.contains("chief technology") {
                    continue;
                }
                if name.is_empty() || company_raw.is_empty() {
                    continue;
                }

                let company = company_raw.trim_start_matches('@').to_string();
                let company_url = if blog.starts_with("http") {
                    blog
                } else if !blog.is_empty() {
                    format!("https://{}", blog)
                } else {
                    String::new()
                };

                out.push(CtoMention {
                    source: "github".to_string(),
                    source_url: html_url,
                    name,
                    company,
                    handle: login.to_string(),
                    context: truncate(&bio, 200),
                    company_url,
                    scraped_email: public_email,
                    fetched_at: now_secs(),
                });
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Ok(out)
        }
    }

    mod reddit {
        use super::*;

        /// Reddit JSON — r/cto hot + r/startups CTO search.
        pub async fn pull(keyword: &str) -> anyhow::Result<Vec<CtoMention>> {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .user_agent("whobelooking/0.1 (by u/cochranblock)")
                .build()?;
            let kw = if keyword.is_empty() { "CTO" } else { keyword };
            let urls = vec![
                "https://www.reddit.com/r/cto/top.json?limit=100&t=year".to_string(),
                format!(
                    "https://www.reddit.com/r/startups/search.json?q={}&limit=100&restrict_sr=1",
                    urlencode(kw)
                ),
            ];
            let mut out = Vec::new();
            for url in urls {
                let resp: serde_json::Value = match client.get(&url).send().await {
                    Ok(r) => r.json().await.unwrap_or(serde_json::Value::Null),
                    Err(_) => continue,
                };
                let children = resp["data"]["children"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                for child in children {
                    let d = &child["data"];
                    let title = d["title"].as_str().unwrap_or("");
                    let selftext = d["selftext"].as_str().unwrap_or("");
                    let permalink = d["permalink"].as_str().unwrap_or("");
                    let author = d["author"].as_str().unwrap_or("").to_string();
                    let full_url = format!("https://www.reddit.com{}", permalink);
                    let text = format!("{} {}", title, selftext);
                    for mut m in extract_cto_from_text(&text, "reddit", &full_url) {
                        if m.handle.is_empty() {
                            m.handle = author.clone();
                        }
                        out.push(m);
                    }
                }
            }
            Ok(out)
        }
    }

    mod yc {
        use super::*;

        /// YC company directory — JS-rendered, needs headless Chrome.
        /// CTO info lives on individual company pages; this first pass pulls
        /// whatever CTO text appears on the main directory and people pages.
        pub async fn pull(session: &browse::Session) -> anyhow::Result<Vec<CtoMention>> {
            let mut out = Vec::new();
            let pages = [
                "https://www.ycombinator.com/companies",
                "https://www.ycombinator.com/people",
            ];
            for url in pages {
                let text = session.fetch_text(url, 6).await.unwrap_or_default();
                out.extend(extract_cto_from_text(&text, "yc", url));
            }
            Ok(out)
        }
    }

    mod podcasts {
        use super::*;

        /// Find podcast episode stories on HN Algolia, then browse the episode
        /// page with headless Chrome to pull guest info.
        pub async fn pull(
            session: &browse::Session,
            keyword: &str,
        ) -> anyhow::Result<Vec<CtoMention>> {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .user_agent("whobelooking/0.1")
                .build()?;
            let q = if keyword.is_empty() {
                "podcast CTO"
            } else {
                keyword
            };
            let url = format!(
                "https://hn.algolia.com/api/v1/search?query={}&tags=story&hitsPerPage=40",
                urlencode(q)
            );
            let resp: serde_json::Value = client.get(&url).send().await?.json().await?;
            let hits = resp["hits"].as_array().cloned().unwrap_or_default();
            let podcast_hosts = [
                "transistor.fm",
                "anchor.fm",
                "simplecast",
                "libsyn",
                "buzzsprout",
                "podbean",
                "spotify.com/episode",
                "apple.com/podcast",
                "podcasts.apple.com",
                "overcast.fm",
                "fireside.fm",
                "pca.st",
                "castro.fm",
                "pod.link",
            ];
            let mut out = Vec::new();
            for hit in hits {
                let story_url = hit["url"].as_str().unwrap_or("").to_string();
                if story_url.is_empty() {
                    continue;
                }
                if !podcast_hosts.iter().any(|h| story_url.contains(h)) {
                    continue;
                }
                let text = session.fetch_text(&story_url, 4).await.unwrap_or_default();
                out.extend(extract_cto_from_text(&text, "podcasts", &story_url));
            }
            Ok(out)
        }
    }

    // =========================================================================
    // Commands: pull, verified, draft
    // =========================================================================

    pub async fn run(op: CtosOp) -> anyhow::Result<()> {
        match op {
            CtosOp::Pull { source, keyword } => {
                pull_cmd(&source, keyword.as_deref().unwrap_or("")).await
            }
            CtosOp::Verified { scrape_emails } => verified_cmd(scrape_emails).await,
            CtosOp::Draft { out } => draft_cmd(&out).await,
        }
    }

    async fn pull_cmd(source: &str, keyword: &str) -> anyhow::Result<()> {
        let db = open_db();
        let pick = |s: &str| source == "all" || source == s;
        let mut all = Vec::new();

        if pick("hn") {
            eprintln!("[hn] pulling...");
            match hn::pull(keyword).await {
                Ok(ms) => {
                    eprintln!("[hn] {} mentions", ms.len());
                    all.extend(ms);
                }
                Err(e) => eprintln!("[hn] error: {}", e),
            }
        }
        if pick("github") {
            eprintln!("[github] pulling...");
            match github::pull(keyword).await {
                Ok(ms) => {
                    eprintln!("[github] {} mentions", ms.len());
                    all.extend(ms);
                }
                Err(e) => eprintln!("[github] error: {}", e),
            }
        }
        if pick("reddit") {
            eprintln!("[reddit] pulling...");
            match reddit::pull(keyword).await {
                Ok(ms) => {
                    eprintln!("[reddit] {} mentions", ms.len());
                    all.extend(ms);
                }
                Err(e) => eprintln!("[reddit] error: {}", e),
            }
        }

        let needs_browser = pick("yc") || pick("podcasts");
        if needs_browser {
            eprintln!("[browser] launching headless chrome...");
            match browse::Session::open().await {
                Ok(session) => {
                    if pick("yc") {
                        eprintln!("[yc] browsing ycombinator.com...");
                        match yc::pull(&session).await {
                            Ok(ms) => {
                                eprintln!("[yc] {} mentions", ms.len());
                                all.extend(ms);
                            }
                            Err(e) => eprintln!("[yc] error: {}", e),
                        }
                    }
                    if pick("podcasts") {
                        eprintln!("[podcasts] browsing episode pages...");
                        match podcasts::pull(&session, keyword).await {
                            Ok(ms) => {
                                eprintln!("[podcasts] {} mentions", ms.len());
                                all.extend(ms);
                            }
                            Err(e) => eprintln!("[podcasts] error: {}", e),
                        }
                    }
                    session.close().await;
                }
                Err(e) => eprintln!("[browser] launch failed: {}", e),
            }
        }

        // Cache direct emails scraped during pull (GitHub public email) into
        // the contact tree right away — they're already source-cited.
        let mut new_mentions = 0u32;
        let mut direct_contacts = 0u32;
        for m in &all {
            if cache_mention(&db, m) {
                new_mentions += 1;
            }
            if !m.scraped_email.is_empty() {
                let key = contact_key(&m.name, &m.company);
                if load_contact(&db, &key).is_none() {
                    cache_contact(
                        &db,
                        &key,
                        &CtoContact {
                            email: m.scraped_email.clone(),
                            email_source_url: m.source_url.clone(),
                            scraped_at: now_secs(),
                        },
                    );
                    direct_contacts += 1;
                }
            }
        }
        let total_cached = db_count_prefix(&db, b"cto:mention:");
        eprintln!("\n=== PULL SUMMARY ===");
        eprintln!("  observed:         {}", all.len());
        eprintln!("  new mentions:     {}", new_mentions);
        eprintln!("  direct emails:    {}", direct_contacts);
        eprintln!("  total in redb:    {}", total_cached);
        Ok(())
    }

    async fn verified_cmd(scrape_emails: bool) -> anyhow::Result<()> {
        let db = open_db();
        let mentions = load_mentions(&db);
        eprintln!("loaded {} mentions from redb", mentions.len());
        let verified = verify(&mentions);
        eprintln!("{} verified CTOs (2+ distinct sources)\n", verified.len());

        println!("=== VERIFIED CTOs ===");
        println!("{:<28} {:<30} {:<8} sources", "Name", "Company", "#src");
        println!("{}", "-".repeat(100));
        for v in &verified {
            let src_list: Vec<&str> = v.sources.iter().map(|(s, _)| s.as_str()).collect();
            let mut distinct: Vec<&str> = src_list.to_vec();
            distinct.sort();
            distinct.dedup();
            println!(
                "{:<28} {:<30} {:<8} {}",
                truncate(&v.name, 28),
                truncate(&v.company, 30),
                distinct.len(),
                distinct.join(",")
            );
            for (s, u) in &v.sources {
                println!("  [{}] {}", s, u);
            }
        }

        if scrape_emails {
            eprintln!("\n[email] scraping company URLs observed in pull data...");
            let session = browse::Session::open().await?;
            let mut new_contacts = 0u32;
            for v in &verified {
                let key = contact_key(&v.name, &v.company);
                if load_contact(&db, &key).is_some() {
                    continue;
                }

                // Priority 1: emails already scraped during pull (e.g. GitHub)
                if let Some((email, src)) = v.direct_emails.first() {
                    cache_contact(
                        &db,
                        &key,
                        &CtoContact {
                            email: email.clone(),
                            email_source_url: src.clone(),
                            scraped_at: now_secs(),
                        },
                    );
                    new_contacts += 1;
                    continue;
                }

                // Priority 2: browse company URLs observed in mentions.
                // ONLY URLs we actually saw in the data — no guessing from
                // the company name.
                let mut found = false;
                for cu in &v.company_urls {
                    if cu.is_empty() || !cu.starts_with("http") {
                        continue;
                    }
                    for path in &["", "/about", "/team", "/contact"] {
                        let full = format!("{}{}", cu.trim_end_matches('/'), path);
                        let text = match session.fetch_text(&full, 4).await {
                            Ok(t) => t,
                            Err(_) => continue,
                        };
                        if let Some((email, _)) = extract_first_email(&text) {
                            // Domain correlation: email domain should appear
                            // in the observed URL. If not, skip — may be a
                            // third-party support address.
                            let url_host = full
                                .trim_start_matches("https://")
                                .trim_start_matches("http://")
                                .split('/')
                                .next()
                                .unwrap_or("")
                                .trim_start_matches("www.");
                            let email_domain = email.split('@').nth(1).unwrap_or("");
                            if url_host.contains(email_domain)
                                || email_domain.contains(url_host)
                                || url_host.ends_with(email_domain)
                            {
                                cache_contact(
                                    &db,
                                    &key,
                                    &CtoContact {
                                        email: email.clone(),
                                        email_source_url: full.clone(),
                                        scraped_at: now_secs(),
                                    },
                                );
                                println!("  [ok] {} → {} (from {})", v.name, email, full);
                                new_contacts += 1;
                                found = true;
                                break;
                            }
                        }
                    }
                    if found {
                        break;
                    }
                }
                if !found && v.company_urls.is_empty() {
                    println!(
                        "  [skip] {} ({}) — no observed URL to scrape",
                        v.name, v.company
                    );
                }
            }
            session.close().await;
            eprintln!("[email] {} new contacts saved", new_contacts);
            db.flush()?;
        }
        Ok(())
    }

    async fn draft_cmd(out_dir: &str) -> anyhow::Result<()> {
        let db = open_db();
        let mentions = load_mentions(&db);
        let verified = verify(&mentions);

        let out = std::path::Path::new(out_dir);
        std::fs::create_dir_all(out)?;

        let today = today_iso();
        let mut written = 0u32;
        let mut skipped_no_email = 0u32;
        for v in &verified {
            let key = contact_key(&v.name, &v.company);
            let contact = match load_contact(&db, &key) {
                Some(c) if !c.email.is_empty() => c,
                _ => {
                    skipped_no_email += 1;
                    continue;
                }
            };

            // SOURCE: headers = every URL used to get this draft
            let mut source_lines = Vec::new();
            for (src, url) in &v.sources {
                source_lines.push(format!("SOURCE: [{}] {}", src, url));
            }
            source_lines.push(format!("SOURCE: [email] {}", contact.email_source_url));

            let slug = slugify(&format!("{}-{}", v.name, v.company));
            let path = out.join(format!("{}.md", slug));

            let body = format!(
                "---\n\
                {sources}\n\
                NAME: {name}\n\
                COMPANY: {company}\n\
                EMAIL: {email}\n\
                EMAIL_SOURCE: {email_src}\n\
                VERIFIED: {nsrc} distinct sources\n\
                DRAFT_DATE: {today}\n\
                ---\n\
                \n\
                Subject: Cross-verified intro — {company}\n\
                \n\
                Hi {first_name},\n\
                \n\
                Saw you mentioned as CTO of {company} across {nsrc} public sources\n\
                ({src_list}). I run a small team at cochranblock.org — we build\n\
                single-binary Rust infra for teams that want zero-cloud tooling.\n\
                \n\
                Worth a short call to compare notes?\n\
                \n\
                — Matt\n\
                cochranblock.org\n",
                sources = source_lines.join("\n"),
                name = v.name,
                company = v.company,
                email = contact.email,
                email_src = contact.email_source_url,
                nsrc = {
                    let mut s: Vec<&str> = v.sources.iter().map(|(s, _)| s.as_str()).collect();
                    s.sort();
                    s.dedup();
                    s.len()
                },
                today = today,
                first_name = v.name.split_whitespace().next().unwrap_or(&v.name),
                src_list = {
                    let mut s: Vec<&str> = v.sources.iter().map(|(s, _)| s.as_str()).collect();
                    s.sort();
                    s.dedup();
                    s.join(", ")
                },
            );
            std::fs::write(&path, body)?;
            written += 1;
            println!("  [draft] {}", path.display());
        }

        eprintln!("\n=== DRAFT SUMMARY ===");
        eprintln!("  verified:              {}", verified.len());
        eprintln!("  drafts written:        {}", written);
        eprintln!("  skipped (no email):    {}", skipped_no_email);
        eprintln!("  output dir:            {}", out.display());
        if skipped_no_email > 0 {
            eprintln!("\n  → run `ctos verified --scrape-emails` to pull more contacts");
            eprintln!("  → skipped entries will never get a fabricated email");
        }
        Ok(())
    }
}

mod scan_cli {
    use reqwest::redirect;
    use serde::Serialize;
    use std::time::{Duration, Instant};
    use tokio::task::JoinSet;

    #[derive(Clone)]
    struct Probe {
        path: &'static str,
        label: &'static str,
        sev: &'static str,
    }

    #[derive(Serialize)]
    pub struct Finding {
        pub path: String,
        pub label: String,
        pub sev: String,
        pub status: u16,
        pub ms: u64,
        pub verdict: String,
    }

    fn probes() -> &'static [Probe] {
        &[
            // CRITICAL
            Probe {
                path: "/.env",
                label: ".env",
                sev: "critical",
            },
            Probe {
                path: "/.env.local",
                label: ".env.local",
                sev: "critical",
            },
            Probe {
                path: "/.env.production",
                label: ".env.production",
                sev: "critical",
            },
            Probe {
                path: "/.env.development",
                label: ".env.development",
                sev: "critical",
            },
            Probe {
                path: "/.env.backup",
                label: ".env.backup",
                sev: "critical",
            },
            Probe {
                path: "/.env.bak",
                label: ".env.bak",
                sev: "critical",
            },
            Probe {
                path: "/config.php",
                label: "config.php",
                sev: "critical",
            },
            Probe {
                path: "/configuration.php",
                label: "configuration.php",
                sev: "critical",
            },
            Probe {
                path: "/wp-config.php",
                label: "wp-config.php",
                sev: "critical",
            },
            Probe {
                path: "/wp-config.php.bak",
                label: "wp-config.php.bak",
                sev: "critical",
            },
            Probe {
                path: "/config.yml",
                label: "config.yml",
                sev: "critical",
            },
            Probe {
                path: "/config.yaml",
                label: "config.yaml",
                sev: "critical",
            },
            Probe {
                path: "/secrets.json",
                label: "secrets.json",
                sev: "critical",
            },
            Probe {
                path: "/credentials.json",
                label: "credentials.json",
                sev: "critical",
            },
            Probe {
                path: "/serviceAccountKey.json",
                label: "GCP service account",
                sev: "critical",
            },
            Probe {
                path: "/.aws/credentials",
                label: "AWS credentials",
                sev: "critical",
            },
            Probe {
                path: "/.ssh/id_rsa",
                label: "SSH private key",
                sev: "critical",
            },
            Probe {
                path: "/.ssh/id_ed25519",
                label: "SSH Ed25519 key",
                sev: "critical",
            },
            Probe {
                path: "/private.key",
                label: "private.key",
                sev: "critical",
            },
            Probe {
                path: "/server.key",
                label: "server.key",
                sev: "critical",
            },
            Probe {
                path: "/.git/HEAD",
                label: "Git HEAD",
                sev: "critical",
            },
            Probe {
                path: "/.git/config",
                label: "Git config",
                sev: "critical",
            },
            Probe {
                path: "/.git/COMMIT_EDITMSG",
                label: "Git last commit msg",
                sev: "critical",
            },
            Probe {
                path: "/database.sql",
                label: "database.sql",
                sev: "critical",
            },
            Probe {
                path: "/db.sql",
                label: "db.sql",
                sev: "critical",
            },
            Probe {
                path: "/backup.sql",
                label: "backup.sql",
                sev: "critical",
            },
            Probe {
                path: "/dump.sql",
                label: "dump.sql",
                sev: "critical",
            },
            Probe {
                path: "/phpinfo.php",
                label: "phpinfo",
                sev: "critical",
            },
            Probe {
                path: "/info.php",
                label: "info.php",
                sev: "critical",
            },
            Probe {
                path: "/test.php",
                label: "test.php",
                sev: "high",
            },
            Probe {
                path: "/wp-login.php",
                label: "WordPress login",
                sev: "critical",
            },
            // HIGH
            Probe {
                path: "/phpmyadmin",
                label: "phpMyAdmin",
                sev: "high",
            },
            Probe {
                path: "/phpmyadmin/",
                label: "phpMyAdmin/",
                sev: "high",
            },
            Probe {
                path: "/pma",
                label: "PMA shortcut",
                sev: "high",
            },
            Probe {
                path: "/adminer.php",
                label: "Adminer",
                sev: "high",
            },
            Probe {
                path: "/.cursor/mcp.json",
                label: "Cursor MCP config",
                sev: "high",
            },
            Probe {
                path: "/.cursor/settings.json",
                label: "Cursor settings",
                sev: "high",
            },
            Probe {
                path: "/.vscode/settings.json",
                label: "VS Code settings",
                sev: "high",
            },
            Probe {
                path: "/api/v1/users",
                label: "User list API",
                sev: "high",
            },
            Probe {
                path: "/api/v1/admin",
                label: "Admin API",
                sev: "high",
            },
            Probe {
                path: "/api/admin",
                label: "Admin API (alt)",
                sev: "high",
            },
            Probe {
                path: "/api/users",
                label: "Users API",
                sev: "high",
            },
            Probe {
                path: "/api/keys",
                label: "Keys API",
                sev: "high",
            },
            Probe {
                path: "/api/v1/keys",
                label: "Keys API v1",
                sev: "high",
            },
            Probe {
                path: "/api/config",
                label: "Config API",
                sev: "high",
            },
            Probe {
                path: "/backup/",
                label: "Backup dir",
                sev: "high",
            },
            Probe {
                path: "/backups/",
                label: "Backups dir",
                sev: "high",
            },
            Probe {
                path: "/backup.zip",
                label: "backup.zip",
                sev: "high",
            },
            Probe {
                path: "/backup.tar.gz",
                label: "backup.tar.gz",
                sev: "high",
            },
            Probe {
                path: "/site.tar.gz",
                label: "site.tar.gz",
                sev: "high",
            },
            Probe {
                path: "/logs/",
                label: "Logs dir",
                sev: "high",
            },
            Probe {
                path: "/log/",
                label: "Log dir",
                sev: "high",
            },
            Probe {
                path: "/error.log",
                label: "error.log",
                sev: "high",
            },
            Probe {
                path: "/access.log",
                label: "access.log",
                sev: "high",
            },
            Probe {
                path: "/debug.log",
                label: "debug.log",
                sev: "high",
            },
            Probe {
                path: "/storage/logs/laravel.log",
                label: "Laravel log",
                sev: "high",
            },
            Probe {
                path: "/.openai",
                label: ".openai dir",
                sev: "high",
            },
            Probe {
                path: "/.openai/config.json",
                label: "OpenAI config",
                sev: "high",
            },
            Probe {
                path: "/openai.json",
                label: "openai.json",
                sev: "high",
            },
            // MEDIUM
            Probe {
                path: "/admin/",
                label: "Admin panel",
                sev: "medium",
            },
            Probe {
                path: "/administrator/",
                label: "Joomla admin",
                sev: "medium",
            },
            Probe {
                path: "/wp-admin/",
                label: "WordPress admin",
                sev: "medium",
            },
            Probe {
                path: "/server-status",
                label: "Apache status",
                sev: "medium",
            },
            Probe {
                path: "/server-info",
                label: "Apache info",
                sev: "medium",
            },
            Probe {
                path: "/graphql",
                label: "GraphQL",
                sev: "medium",
            },
            Probe {
                path: "/swagger.json",
                label: "Swagger docs",
                sev: "medium",
            },
            Probe {
                path: "/openapi.json",
                label: "OpenAPI docs",
                sev: "medium",
            },
            Probe {
                path: "/api-docs",
                label: "API docs",
                sev: "medium",
            },
            Probe {
                path: "/api/docs",
                label: "API docs (alt)",
                sev: "medium",
            },
            Probe {
                path: "/xmlrpc.php",
                label: "XML-RPC",
                sev: "medium",
            },
            Probe {
                path: "/.DS_Store",
                label: ".DS_Store",
                sev: "medium",
            },
            Probe {
                path: "/.htaccess",
                label: ".htaccess",
                sev: "medium",
            },
            Probe {
                path: "/docker-compose.yml",
                label: "Docker Compose",
                sev: "medium",
            },
            Probe {
                path: "/.travis.yml",
                label: "Travis CI config",
                sev: "medium",
            },
            Probe {
                path: "/Jenkinsfile",
                label: "Jenkinsfile",
                sev: "medium",
            },
            Probe {
                path: "/.circleci/config.yml",
                label: "CircleCI config",
                sev: "medium",
            },
            Probe {
                path: "/.gitlab-ci.yml",
                label: "GitLab CI config",
                sev: "medium",
            },
            Probe {
                path: "/install.php",
                label: "Install script",
                sev: "medium",
            },
            Probe {
                path: "/console",
                label: "Console",
                sev: "medium",
            },
            Probe {
                path: "/.gitignore",
                label: ".gitignore",
                sev: "medium",
            },
            Probe {
                path: "/package-lock.json",
                label: "package-lock.json",
                sev: "medium",
            },
            Probe {
                path: "/requirements.txt",
                label: "requirements.txt",
                sev: "medium",
            },
            Probe {
                path: "/CHANGELOG.md",
                label: "CHANGELOG",
                sev: "medium",
            },
            // LOW / INFO
            Probe {
                path: "/robots.txt",
                label: "robots.txt",
                sev: "info",
            },
            Probe {
                path: "/sitemap.xml",
                label: "Sitemap",
                sev: "info",
            },
            Probe {
                path: "/",
                label: "Root",
                sev: "info",
            },
        ]
    }

    fn verdict(status: u16) -> &'static str {
        if status == 0 {
            return "unreachable";
        }
        if (200..300).contains(&status) {
            return "EXPOSED";
        }
        if status == 401 || status == 403 {
            return "auth-wall";
        }
        if (300..400).contains(&status) {
            return "redirect";
        }
        if status >= 500 {
            return "server-error";
        }
        "clean"
    }

    fn is_finding(status: u16) -> bool {
        (200..300).contains(&status) || status == 401 || status == 403
    }

    fn sev_order(sev: &str) -> u8 {
        match sev {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        }
    }

    pub async fn run(url: &str, as_json: bool) -> anyhow::Result<()> {
        let base = url.trim_end_matches('/');
        let base = if base.starts_with("http") {
            base.to_string()
        } else {
            format!("https://{}", base)
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .redirect(redirect::Policy::none())
            .user_agent("whobelooking-scan/1.0 (+https://whobelooking.org/scan)")
            .build()?;

        let probes = probes();
        let total = probes.len();
        let mut set: JoinSet<Finding> = JoinSet::new();

        for p in probes {
            let client = client.clone();
            let target = format!("{}{}", base, p.path);
            let path = p.path;
            let label = p.label;
            let sev = p.sev;
            set.spawn(async move {
                let t0 = Instant::now();
                let (status, ms) = match client.head(&target).send().await {
                    Ok(r) => (r.status().as_u16(), t0.elapsed().as_millis() as u64),
                    Err(_) => (0u16, t0.elapsed().as_millis() as u64),
                };
                Finding {
                    path: path.to_string(),
                    label: label.to_string(),
                    sev: sev.to_string(),
                    status,
                    ms,
                    verdict: verdict(status).to_string(),
                }
            });
        }

        let mut findings: Vec<Finding> = Vec::with_capacity(total);
        while let Some(r) = set.join_next().await {
            if let Ok(f) = r {
                findings.push(f);
            }
        }

        findings.sort_by(|a, b| {
            sev_order(&a.sev)
                .cmp(&sev_order(&b.sev))
                .then(b.status.cmp(&a.status))
        });

        if as_json {
            println!("{}", serde_json::to_string_pretty(&findings)?);
            return Ok(());
        }

        // Terminal output
        let hits: Vec<&Finding> = findings.iter().filter(|f| is_finding(f.status)).collect();
        let crit: Vec<&Finding> = hits
            .iter()
            .filter(|f| f.sev == "critical")
            .copied()
            .collect();

        eprintln!();
        eprintln!("  whobelooking scan — {}", base);
        eprintln!("  {} paths probed", total);
        eprintln!();

        if hits.is_empty() {
            eprintln!("  \x1b[32m✓ No exposed paths found.\x1b[0m");
        } else {
            if !crit.is_empty() {
                eprintln!(
                    "  \x1b[1;31m⚠  {} CRITICAL FINDING{}\x1b[0m",
                    crit.len(),
                    if crit.len() > 1 { "S" } else { "" }
                );
                for f in &crit {
                    eprintln!(
                        "  \x1b[31m  {} — {} (HTTP {})\x1b[0m",
                        f.path, f.label, f.status
                    );
                }
                eprintln!();
            }
            eprintln!(
                "  \x1b[33m{} path{} answered\x1b[0m",
                hits.len(),
                if hits.len() > 1 { "s" } else { "" }
            );
        }

        eprintln!();
        eprintln!(
            "  {:<40}  {:<10}  {:<10}  {:>6}  {:>6}",
            "PATH", "LABEL", "VERDICT", "STATUS", "MS"
        );
        eprintln!("  {}", "-".repeat(80));

        let mut last_sev = "";
        for f in &findings {
            if f.sev != last_sev {
                eprintln!("  \x1b[2m[{}]\x1b[0m", f.sev.to_uppercase());
                last_sev = &f.sev;
            }
            let color = match f.verdict.as_str() {
                "EXPOSED" => "\x1b[1;31m",
                "auth-wall" => "\x1b[33m",
                "redirect" => "\x1b[2m",
                "server-error" => "\x1b[2;33m",
                _ => "\x1b[2m",
            };
            eprintln!(
                "  {}{:<40}  {:<10}  {:<10}  {:>6}  {:>6}\x1b[0m",
                color,
                &f.path[..f.path.len().min(39)],
                &f.label[..f.label.len().min(10)],
                &f.verdict[..f.verdict.len().min(10)],
                if f.status == 0 {
                    "-".to_string()
                } else {
                    f.status.to_string()
                },
                f.ms,
            );
        }

        eprintln!();
        if !hits.is_empty() {
            eprintln!("  Need help closing these gaps? https://cochranblock.org/book");
        }
        eprintln!();

        Ok(())
    }
}
