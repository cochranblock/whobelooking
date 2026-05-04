// All Rights Reserved — The Cochran Block, LLC
//! `/api/scan/run` — full server-side surface area scan as one API call.
//!
//! The browser flow in `scan.rs` fans out N HEAD requests from the client; this
//! endpoint does the fan-out server-side and returns one structured JSON
//! response. Free, no Stripe gate. Designed to be hit from a Claude skill,
//! CLI, or CI step.
//!
//! POST /api/scan/run        body: {"url":"https://example.com","severity":"all"}
//! GET  /api/scan/run?url=…&severity=…
//! GET  /api/scan/probes     canonical probe list
//!
//! TODO: dedupe SSRF guard / probe list with `scan.rs` once the API surface
//! settles. Currently duplicated so the existing browser scan stays untouched.

use axum::{Json, extract::Query, http::{HeaderMap, StatusCode, header}, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Write,
    net::IpAddr,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Probe {
    pub path: &'static str,
    pub label: &'static str,
    pub sev: &'static str,
}

// Seed list. Port the rest from the JS PROBES array in `scan.rs` as needed.
pub const PROBES: &[Probe] = &[
    Probe { path: "/.env",                 label: ".env",                 sev: "critical" },
    Probe { path: "/.env.production",      label: ".env.production",      sev: "critical" },
    Probe { path: "/.env.local",           label: ".env.local",           sev: "critical" },
    Probe { path: "/.env.staging",         label: ".env.staging",         sev: "critical" },
    Probe { path: "/.env.backup",          label: ".env.backup",          sev: "critical" },
    Probe { path: "/.git/config",          label: "Git config",           sev: "critical" },
    Probe { path: "/.git/HEAD",            label: "Git HEAD",             sev: "critical" },
    Probe { path: "/wp-config.php",        label: "WordPress config",     sev: "critical" },
    Probe { path: "/wp-config.php.bak",    label: "WordPress config bak", sev: "critical" },
    Probe { path: "/configuration.php",    label: "Joomla config",        sev: "critical" },
    Probe { path: "/config.json",          label: "config.json",          sev: "critical" },
    Probe { path: "/config.yml",           label: "config.yml",           sev: "critical" },
    Probe { path: "/credentials.json",     label: "credentials.json",     sev: "critical" },
    Probe { path: "/secrets.yml",          label: "secrets.yml",          sev: "critical" },
    Probe { path: "/secrets.json",         label: "secrets.json",         sev: "critical" },
    Probe { path: "/database.yml",         label: "Rails database.yml",   sev: "critical" },
    Probe { path: "/application.yml",      label: "Spring application.yml", sev: "critical" },
    Probe { path: "/settings.py",          label: "Django settings",      sev: "critical" },
    Probe { path: "/backup.sql",           label: "SQL backup",           sev: "critical" },
    Probe { path: "/database.sql",         label: "database.sql",         sev: "critical" },
    Probe { path: "/dump.sql",             label: "dump.sql",             sev: "critical" },
    Probe { path: "/backup.zip",           label: "Zip backup",           sev: "critical" },
    Probe { path: "/backup.tar.gz",        label: "Tarball backup",       sev: "critical" },
    Probe { path: "/db.sqlite3",           label: "SQLite3 database",     sev: "critical" },
    Probe { path: "/id_rsa",               label: "SSH private key",      sev: "critical" },
    Probe { path: "/.ssh/id_rsa",          label: ".ssh/id_rsa",          sev: "critical" },
    Probe { path: "/server.key",           label: "server.key",           sev: "critical" },
    Probe { path: "/.htpasswd",            label: ".htpasswd",            sev: "critical" },
    Probe { path: "/.npmrc",               label: ".npmrc tokens",        sev: "critical" },
    Probe { path: "/storage/logs/laravel.log", label: "Laravel log",      sev: "critical" },
    Probe { path: "/wp-content/debug.log", label: "WordPress debug log",  sev: "critical" },
    Probe { path: "/phpmyadmin/",          label: "phpMyAdmin",           sev: "high"     },
    Probe { path: "/info.php",             label: "phpinfo",              sev: "high"     },
    Probe { path: "/phpinfo.php",          label: "phpinfo (alt)",        sev: "high"     },
    Probe { path: "/actuator",             label: "Spring actuator",      sev: "high"     },
    Probe { path: "/actuator/env",         label: "Spring env dump",      sev: "high"     },
    Probe { path: "/actuator/mappings",    label: "Spring route map",     sev: "high"     },
    Probe { path: "/actuator/httptrace",   label: "Spring HTTP trace",    sev: "high"     },
    Probe { path: "/api/admin",            label: "API /admin",           sev: "high"     },
    Probe { path: "/api/v1/admin",         label: "API v1 /admin",        sev: "high"     },
    Probe { path: "/api/users",            label: "API /users",           sev: "high"     },
    Probe { path: "/api/config",           label: "API /config",          sev: "high"     },
    Probe { path: "/wp-json/wp/v2/users",  label: "WordPress user enum",  sev: "high"     },
    Probe { path: "/rails/info/routes",    label: "Rails routes",         sev: "high"     },
    Probe { path: "/debug/pprof",          label: "Go pprof",             sev: "high"     },
    Probe { path: "/elmah.axd",            label: "ELMAH log",            sev: "high"     },
    Probe { path: "/_profiler/",           label: "Symfony profiler",     sev: "high"     },
    Probe { path: "/admin/",               label: "Admin panel",          sev: "medium"   },
    Probe { path: "/administrator/",       label: "Joomla admin",         sev: "medium"   },
    Probe { path: "/wp-admin/",            label: "WordPress admin",      sev: "medium"   },
    Probe { path: "/server-status",        label: "Apache status",        sev: "medium"   },
    Probe { path: "/server-info",          label: "Apache info",          sev: "medium"   },
    Probe { path: "/swagger.json",         label: "Swagger docs",         sev: "medium"   },
    Probe { path: "/openapi.json",         label: "OpenAPI docs",         sev: "medium"   },
    Probe { path: "/api-docs",             label: "API docs",             sev: "medium"   },
    Probe { path: "/graphql",              label: "GraphQL",              sev: "medium"   },
    Probe { path: "/xmlrpc.php",           label: "XML-RPC",              sev: "medium"   },
    Probe { path: "/.DS_Store",            label: ".DS_Store",            sev: "medium"   },
    Probe { path: "/.htaccess",            label: ".htaccess",            sev: "medium"   },
    Probe { path: "/docker-compose.yml",   label: "Docker Compose",       sev: "medium"   },
    Probe { path: "/.gitlab-ci.yml",       label: "GitLab CI config",     sev: "medium"   },
    Probe { path: "/.travis.yml",          label: "Travis CI config",     sev: "medium"   },
    Probe { path: "/Jenkinsfile",          label: "Jenkinsfile",          sev: "medium"   },
    Probe { path: "/install.php",          label: "Install script",       sev: "medium"   },
    Probe { path: "/console",              label: "Console",              sev: "medium"   },
    Probe { path: "/.gitignore",           label: ".gitignore",           sev: "medium"   },
    Probe { path: "/package.json",         label: "package.json",         sev: "medium"   },
    Probe { path: "/composer.json",        label: "composer.json",        sev: "medium"   },
    Probe { path: "/Dockerfile",           label: "Dockerfile",           sev: "low"      },
    Probe { path: "/VERSION",              label: "VERSION file",         sev: "low"      },
    Probe { path: "/README.md",            label: "README",               sev: "low"      },
    Probe { path: "/crossdomain.xml",      label: "crossdomain.xml",      sev: "low"      },
    Probe { path: "/wp-login.php",         label: "WordPress login",      sev: "info"     },
    Probe { path: "/login",                label: "Login page",           sev: "info"     },
    Probe { path: "/cpanel",               label: "cPanel",               sev: "info"     },
    Probe { path: "/webmail",              label: "Webmail",              sev: "info"     },
    Probe { path: "/actuator/health",      label: "Spring health",        sev: "info"     },
    Probe { path: "/",                     label: "Root",                 sev: "info"     },
    Probe { path: "/robots.txt",           label: "robots.txt",           sev: "info"     },
    Probe { path: "/sitemap.xml",          label: "Sitemap",              sev: "info"     },
];

#[derive(Deserialize)]
pub struct ScanBody {
    pub url: String,
    pub severity: Option<String>,
    /// Response format: "json" (default) or "csv".
    pub format: Option<String>,
}

#[derive(Deserialize)]
pub struct ScanQuery {
    pub url: String,
    pub severity: Option<String>,
    pub format: Option<String>,
}

#[derive(Deserialize)]
pub struct EmailBody {
    pub url: String,
    pub email: String,
    pub severity: Option<String>,
    /// Attachment format: "csv" | "json" | "both" (default).
    pub format: Option<String>,
}

#[derive(Serialize)]
pub struct EmailResponse {
    pub ok: bool,
    pub queued: bool,
}

#[derive(Serialize)]
pub struct ProbeOutcome {
    pub path: String,
    pub label: String,
    pub sev: String,
    pub status: u16,
    pub ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<&'static str>,
    pub hit: bool,
    /// Coarse category derived from status. Lets consumers distinguish a real
    /// exposure (`accessible`) from an auth/WAF wall (`wall`).
    /// Values: accessible | wall | redirect | missing | server_error | unreachable
    pub kind: &'static str,
}

#[derive(Serialize)]
pub struct ScanSummary {
    pub total: usize,
    pub hits: usize,
    pub critical_hits: usize,
    pub reachable: bool,
}

#[derive(Serialize)]
pub struct ScanResult {
    pub target: String,
    pub started_at: u64,
    pub elapsed_ms: u64,
    pub probes: Vec<ProbeOutcome>,
    pub summary: ScanSummary,
}

fn is_private(host: &str) -> bool {
    if matches!(host, "localhost" | "ip6-localhost" | "ip6-loopback") {
        return true;
    }
    if let Ok(addr) = host.parse::<IpAddr>() {
        return match addr {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
                    || v4.is_documentation()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
            }
        };
    }
    false
}

fn extract_host(raw: &str) -> Option<&str> {
    let after = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("http://"))?;
    let host_port = after.split('/').next()?.split('?').next()?;
    if host_port.starts_with('[') {
        return host_port
            .split(']')
            .next()
            .map(|s| s.trim_start_matches('['));
    }
    Some(host_port.split(':').next().unwrap_or(host_port))
}

struct ScanBucket {
    minute: u64,
    count: u32,
}
static SCAN_RATE: OnceLock<Mutex<HashMap<String, ScanBucket>>> = OnceLock::new();
const MAX_SCANS_PER_MIN: u32 = 5;

fn scan_rate_exceeded(ip: &str) -> bool {
    let now_min = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0);
    let mut map = SCAN_RATE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    let bucket = map.entry(ip.to_string()).or_insert(ScanBucket {
        minute: now_min,
        count: 0,
    });
    if bucket.minute != now_min {
        bucket.minute = now_min;
        bucket.count = 0;
    }
    bucket.count += 1;
    bucket.count > MAX_SCANS_PER_MIN
}

const MAX_INFLIGHT_PER_SCAN: usize = 32;

fn probe_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .user_agent(
                "Mozilla/5.0 (compatible; whobelooking-scan-api/1.0; +https://whobelooking.cochranblock.org/scan)",
            )
            .build()
            .expect("reqwest client")
    })
}

fn is_hit(status: u16) -> bool {
    matches!(status, 200..=299) || status == 401 || status == 403
}

fn classify(status: u16, err: Option<&str>) -> &'static str {
    if status == 0 || err.is_some() {
        return "unreachable";
    }
    match status {
        200..=299 => "accessible",
        401 | 403 => "wall",
        300..=399 => "redirect",
        400..=499 => "missing",
        500..=599 => "server_error",
        _ => "unreachable",
    }
}

pub async fn probes_list() -> Json<Vec<Probe>> {
    Json(PROBES.to_vec())
}

pub async fn run_post(
    headers: HeaderMap,
    Json(body): Json<ScanBody>,
) -> Result<axum::response::Response, (StatusCode, &'static str)> {
    let Json(result) = run_inner(&headers, &body.url, body.severity.as_deref()).await?;
    Ok(format_response(result, body.format.as_deref()))
}

pub async fn run_get(
    headers: HeaderMap,
    Query(q): Query<ScanQuery>,
) -> Result<axum::response::Response, (StatusCode, &'static str)> {
    let Json(result) = run_inner(&headers, &q.url, q.severity.as_deref()).await?;
    Ok(format_response(result, q.format.as_deref()))
}

fn format_response(result: ScanResult, format: Option<&str>) -> axum::response::Response {
    if matches!(format, Some("csv")) {
        let csv = result_to_csv(&result);
        (
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"whobelooking-scan.csv\"",
                ),
            ],
            csv,
        )
            .into_response()
    } else {
        Json(result).into_response()
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn result_to_csv(r: &ScanResult) -> String {
    let mut out = String::with_capacity(r.probes.len() * 96);
    out.push_str("path,label,sev,status,ms,hit,kind,err\n");
    for p in &r.probes {
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{}",
            csv_escape(&p.path),
            csv_escape(&p.label),
            p.sev,
            p.status,
            p.ms,
            p.hit,
            p.kind,
            csv_escape(p.err.unwrap_or("")),
        );
    }
    out
}

struct EmailBucket {
    minute: u64,
    count: u32,
}
static EMAIL_RATE: OnceLock<Mutex<HashMap<String, EmailBucket>>> = OnceLock::new();
const MAX_EMAILS_PER_MIN: u32 = 2;

fn email_rate_exceeded(ip: &str) -> bool {
    let now_min = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0);
    let mut map = EMAIL_RATE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    let bucket = map.entry(ip.to_string()).or_insert(EmailBucket {
        minute: now_min,
        count: 0,
    });
    if bucket.minute != now_min {
        bucket.minute = now_min;
        bucket.count = 0;
    }
    bucket.count += 1;
    bucket.count > MAX_EMAILS_PER_MIN
}

pub async fn email_post(
    headers: HeaderMap,
    Json(body): Json<EmailBody>,
) -> Result<Json<EmailResponse>, (StatusCode, &'static str)> {
    let ip = crate::web::visits::client_ip(&headers);
    if email_rate_exceeded(&ip) {
        return Err((StatusCode::TOO_MANY_REQUESTS, "email rate limited"));
    }
    let to = body.email.trim().to_string();
    if to.is_empty() || !to.contains('@') || !to.contains('.') || to.len() > 254 {
        return Err((StatusCode::BAD_REQUEST, "invalid email"));
    }

    let Json(result) = run_inner(&headers, &body.url, body.severity.as_deref()).await?;
    let format = body.format.as_deref().unwrap_or("both").to_string();

    tokio::task::spawn_blocking(move || {
        if let Err(e) = send_scan_email(&to, &result, &format) {
            tracing::warn!("scan-email failed for {}: {}", to, e);
        } else {
            tracing::info!(
                "scan-email sent to {} (target={}, hits={})",
                to,
                result.target,
                result.summary.hits
            );
        }
    });

    Ok(Json(EmailResponse {
        ok: true,
        queued: true,
    }))
}

fn host_from_target(target: &str) -> &str {
    let after = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
        .unwrap_or(target);
    after.split('/').next().unwrap_or(after)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render_plain_email(result: &ScanResult, attached: &[&str]) -> String {
    let s = &result.summary;
    let target_host = host_from_target(&result.target);
    let reachable = if s.reachable { "yes" } else { "no" };
    let mut out = String::with_capacity(1024);
    let _ = writeln!(out, "Surface-area scan: {}", target_host);
    let _ = writeln!(out, "{}", "=".repeat(target_host.len() + 19));
    out.push('\n');
    let _ = writeln!(out, "  Target       {}", result.target);
    let _ = writeln!(out, "  Reachable    {}", reachable);
    let _ = writeln!(out, "  Probed       {}", s.total);
    let _ = writeln!(out, "  Hits         {}  ({} critical)", s.hits, s.critical_hits);
    let _ = writeln!(out, "  Elapsed      {} ms", result.elapsed_ms);

    let accessible: Vec<&ProbeOutcome> = result.probes.iter().filter(|p| p.kind == "accessible").collect();
    let walls: Vec<&ProbeOutcome> = result.probes.iter().filter(|p| p.kind == "wall").collect();

    if !accessible.is_empty() {
        out.push('\n');
        out.push_str("Accessible (real exposures, 2xx)\n");
        out.push_str("--------------------------------\n");
        for p in &accessible {
            let _ = writeln!(out, "  {:<10} {:<6} {}", p.sev, p.status, p.path);
        }
    }
    if !walls.is_empty() {
        out.push('\n');
        out.push_str("Walls (server processed, 401/403 — usually a WAF/auth)\n");
        out.push_str("------------------------------------------------------\n");
        for p in &walls {
            let _ = writeln!(out, "  {:<10} {:<6} {}", p.sev, p.status, p.path);
        }
    }
    if accessible.is_empty() && walls.is_empty() {
        out.push('\n');
        out.push_str("No hits. Surface looks clean against the probe set.\n");
    }

    if !attached.is_empty() {
        out.push('\n');
        let _ = writeln!(out, "Attached: {}", attached.join(", "));
    }
    out.push('\n');
    out.push_str("--\n");
    out.push_str("whobelooking — free attack-surface scanner\n");
    out.push_str("https://whobelooking.cochranblock.org\n");
    out
}

fn render_html_email(result: &ScanResult, attached: &[&str]) -> String {
    let s = &result.summary;
    let target = html_escape(&result.target);
    let target_host = html_escape(host_from_target(&result.target));
    let reachable = if s.reachable { "yes" } else { "no" };

    let sev_color = |sev: &str| match sev {
        "critical" => "#ff6b35",
        "high" => "#fbbf24",
        "medium" => "#9d4edd",
        "low" => "#9ca3af",
        _ => "#00d9ff",
    };

    let row = |p: &ProbeOutcome| -> String {
        format!(
            "<tr>\
              <td style=\"padding:6px 12px;border-bottom:1px solid #1f2937;color:{color};font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.04em\">{sev}</td>\
              <td style=\"padding:6px 12px;border-bottom:1px solid #1f2937;color:#cbd5e1;font-family:ui-monospace,monospace\">{status}</td>\
              <td style=\"padding:6px 12px;border-bottom:1px solid #1f2937;color:#e5e7eb;font-family:ui-monospace,monospace\">{path}</td>\
              <td style=\"padding:6px 12px;border-bottom:1px solid #1f2937;color:#94a3b8\">{label}</td>\
            </tr>",
            color = sev_color(&p.sev),
            sev = html_escape(&p.sev),
            status = p.status,
            path = html_escape(&p.path),
            label = html_escape(&p.label),
        )
    };

    let mut hit_rows = String::new();
    let accessible: Vec<&ProbeOutcome> = result.probes.iter().filter(|p| p.kind == "accessible").collect();
    let walls: Vec<&ProbeOutcome> = result.probes.iter().filter(|p| p.kind == "wall").collect();
    let sev_rank = |s: &str| match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    };
    if !accessible.is_empty() {
        let mut sorted = accessible.clone();
        sorted.sort_by_key(|p| (sev_rank(&p.sev), p.path.clone()));
        hit_rows.push_str(
            "<tr><td colspan=\"4\" style=\"padding:18px 12px 6px;color:#ff6b35;font-weight:700;font-size:11px;letter-spacing:.08em;text-transform:uppercase\">accessible · 2xx</td></tr>",
        );
        for p in sorted { hit_rows.push_str(&row(p)); }
    }
    if !walls.is_empty() {
        let mut sorted = walls.clone();
        sorted.sort_by_key(|p| (sev_rank(&p.sev), p.path.clone()));
        hit_rows.push_str(
            "<tr><td colspan=\"4\" style=\"padding:18px 12px 6px;color:#fbbf24;font-weight:700;font-size:11px;letter-spacing:.08em;text-transform:uppercase\">wall · 401/403 (usually WAF / auth)</td></tr>",
        );
        for p in sorted { hit_rows.push_str(&row(p)); }
    }

    let no_hits_block = if accessible.is_empty() && walls.is_empty() {
        "<p style=\"margin:18px 0 0;color:#10b981;font-size:14px\">No hits. Surface looks clean against the probe set.</p>"
    } else {
        ""
    };

    let attach_line = if attached.is_empty() {
        String::new()
    } else {
        format!(
            "<p style=\"margin:18px 0 0;color:#94a3b8;font-size:13px\">Attached: <span style=\"color:#cbd5e1\">{}</span></p>",
            html_escape(&attached.join(", "))
        )
    };

    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head>\
         <body style=\"margin:0;padding:24px;background:#050508;color:#e5e7eb;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5\">\
         <div style=\"max-width:640px;margin:0 auto;background:#0d0d14;border:1px solid #1f2937;border-radius:8px;overflow:hidden\">\
           <div style=\"padding:20px 24px;border-bottom:1px solid #1f2937;background:#0a0a10\">\
             <div style=\"font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#00d9ff;font-weight:700\">whobelooking · surface-area scan</div>\
             <div style=\"font-size:18px;font-weight:600;color:#fff;margin-top:4px;font-family:ui-monospace,monospace\">{target_host}</div>\
           </div>\
           <div style=\"padding:20px 24px\">\
             <table cellspacing=\"0\" cellpadding=\"0\" style=\"width:100%;border-collapse:collapse;font-size:13px\">\
               <tr><td style=\"color:#94a3b8;padding:4px 0;width:120px\">Target</td><td style=\"color:#cbd5e1;font-family:ui-monospace,monospace;word-break:break-all\">{target}</td></tr>\
               <tr><td style=\"color:#94a3b8;padding:4px 0\">Reachable</td><td style=\"color:#cbd5e1\">{reachable}</td></tr>\
               <tr><td style=\"color:#94a3b8;padding:4px 0\">Probed</td><td style=\"color:#cbd5e1\">{total}</td></tr>\
               <tr><td style=\"color:#94a3b8;padding:4px 0\">Hits</td><td style=\"color:#cbd5e1\">{hits} <span style=\"color:#ff6b35\">({critical} critical)</span></td></tr>\
               <tr><td style=\"color:#94a3b8;padding:4px 0\">Elapsed</td><td style=\"color:#cbd5e1\">{elapsed} ms</td></tr>\
             </table>\
             {no_hits_block}\
             {hits_table}\
             {attach_line}\
           </div>\
           <div style=\"padding:14px 24px;border-top:1px solid #1f2937;background:#0a0a10;color:#6b7280;font-size:12px\">\
             whobelooking — free attack-surface scanner · <a href=\"https://whobelooking.cochranblock.org\" style=\"color:#00d9ff;text-decoration:none\">whobelooking.cochranblock.org</a>\
           </div>\
         </div></body></html>",
        target_host = target_host,
        target = target,
        reachable = reachable,
        total = s.total,
        hits = s.hits,
        critical = s.critical_hits,
        elapsed = result.elapsed_ms,
        no_hits_block = no_hits_block,
        hits_table = if hit_rows.is_empty() { String::new() } else {
            format!(
                "<table cellspacing=\"0\" cellpadding=\"0\" style=\"width:100%;margin-top:12px;border-collapse:collapse;font-size:13px;background:#050508;border-radius:6px;overflow:hidden;border:1px solid #1f2937\">{}</table>",
                hit_rows
            )
        },
        attach_line = attach_line,
    )
}

fn send_scan_email(to_addr: &str, result: &ScanResult, format: &str) -> Result<(), String> {
    use lettre::message::header::ContentType;
    use lettre::message::{Attachment, MultiPart, SinglePart};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};

    let host = std::env::var("SMTP_HOST").unwrap_or_else(|_| "smtp.gmail.com".into());
    let port: u16 = std::env::var("SMTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(465);
    let user = std::env::var("SMTP_USER").map_err(|_| "SMTP_USER unset".to_string())?;
    let pass = std::env::var("SMTP_PASS").map_err(|_| "SMTP_PASS unset".to_string())?;

    let want_json = matches!(format, "json" | "both" | "");
    let want_csv = matches!(format, "csv" | "both" | "");
    let want_json = if !matches!(format, "json" | "csv" | "both") { true } else { want_json };
    let want_csv = if !matches!(format, "json" | "csv" | "both") { true } else { want_csv };

    let mut attached: Vec<&str> = Vec::new();
    if want_json { attached.push("whobelooking-scan.json"); }
    if want_csv { attached.push("whobelooking-scan.csv"); }

    let plain = render_plain_email(result, &attached);
    let html = render_html_email(result, &attached);

    let target_host = host_from_target(&result.target);
    let subject = if result.summary.hits == 0 {
        format!("[whobelooking] {} — clean", target_host)
    } else {
        format!(
            "[whobelooking] {} — {} hit{}{}",
            target_host,
            result.summary.hits,
            if result.summary.hits == 1 { "" } else { "s" },
            if result.summary.critical_hits > 0 {
                format!(" ({} critical)", result.summary.critical_hits)
            } else {
                String::new()
            }
        )
    };
    let from_mbox = format!("whobelooking <{}>", user);

    let alt = MultiPart::alternative()
        .singlepart(
            SinglePart::builder()
                .header(ContentType::TEXT_PLAIN)
                .body(plain),
        )
        .singlepart(
            SinglePart::builder()
                .header(ContentType::TEXT_HTML)
                .body(html),
        );

    let mut multipart = MultiPart::mixed().multipart(alt);

    if want_json {
        let json_bytes = serde_json::to_vec_pretty(result)
            .map_err(|e| format!("json serialize: {}", e))?;
        multipart = multipart.singlepart(
            Attachment::new("whobelooking-scan.json".to_string()).body(
                json_bytes,
                ContentType::parse("application/json").unwrap(),
            ),
        );
    }
    if want_csv {
        let csv_bytes = result_to_csv(result).into_bytes();
        multipart = multipart.singlepart(
            Attachment::new("whobelooking-scan.csv".to_string())
                .body(csv_bytes, ContentType::parse("text/csv").unwrap()),
        );
    }

    let msg = Message::builder()
        .from(from_mbox.parse().map_err(|e| format!("from: {}", e))?)
        .to(to_addr.parse().map_err(|e| format!("to: {}", e))?)
        .subject(subject)
        .multipart(multipart)
        .map_err(|e| format!("build: {}", e))?;

    let creds = Credentials::new(user, pass);
    let mailer = SmtpTransport::relay(&host)
        .map_err(|e| format!("relay: {}", e))?
        .port(port)
        .credentials(creds)
        .build();
    mailer.send(&msg).map_err(|e| format!("send: {}", e))?;
    Ok(())
}

async fn run_inner(
    headers: &HeaderMap,
    url: &str,
    severity: Option<&str>,
) -> Result<Json<ScanResult>, (StatusCode, &'static str)> {
    let ip = crate::web::visits::client_ip(headers);
    if scan_rate_exceeded(&ip) {
        return Err((StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }

    let raw = url.trim();
    let normalized = if raw.starts_with("https://") || raw.starts_with("http://") {
        raw.to_string()
    } else {
        format!("https://{}", raw)
    };
    let normalized = normalized.trim_end_matches('/').to_string();

    let host = extract_host(&normalized).ok_or((StatusCode::BAD_REQUEST, "invalid url"))?;
    if is_private(host) {
        return Err((StatusCode::FORBIDDEN, "private host"));
    }

    let selected: Vec<Probe> = match severity.unwrap_or("all") {
        "critical" => PROBES.iter().copied().filter(|p| p.sev == "critical").collect(),
        "high" => PROBES
            .iter()
            .copied()
            .filter(|p| p.sev == "critical" || p.sev == "high")
            .collect(),
        _ => PROBES.to_vec(),
    };

    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let t0 = Instant::now();

    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_PER_SCAN));
    let mut handles = Vec::with_capacity(selected.len());
    for p in &selected {
        let probe_url = format!("{}{}", normalized, p.path);
        let path = p.path.to_string();
        let label = p.label.to_string();
        let sev = p.sev.to_string();
        let sem = semaphore.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore");
            let t = Instant::now();
            let (status, err): (u16, Option<&'static str>) =
                match probe_client().head(&probe_url).send().await {
                    Ok(r) => (r.status().as_u16(), None),
                    Err(_) => match probe_client().get(&probe_url).send().await {
                        Ok(r) => (r.status().as_u16(), None),
                        Err(e) => {
                            let msg = if e.is_timeout() {
                                "timeout"
                            } else if e.is_connect() {
                                "no route"
                            } else {
                                let s = format!("{:?}", e).to_ascii_lowercase();
                                if s.contains("dns") {
                                    "dns fail"
                                } else if s.contains("certificate") || s.contains("tls") {
                                    "tls error"
                                } else {
                                    "unreachable"
                                }
                            };
                            (0, Some(msg))
                        }
                    },
                };
            ProbeOutcome {
                path,
                label,
                sev,
                status,
                ms: t.elapsed().as_millis() as u64,
                err,
                hit: is_hit(status),
                kind: classify(status, err),
            }
        }));
    }

    let mut outcomes: Vec<ProbeOutcome> = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(o) = h.await {
            outcomes.push(o);
        }
    }

    let total = outcomes.len();
    let hits = outcomes.iter().filter(|o| o.hit).count();
    let critical_hits = outcomes
        .iter()
        .filter(|o| o.hit && o.sev == "critical")
        .count();
    let reachable_count = outcomes
        .iter()
        .filter(|o| o.err.is_none() && o.status != 0)
        .count();
    let reachable = total > 0 && reachable_count * 2 >= total;

    Ok(Json(ScanResult {
        target: normalized,
        started_at,
        elapsed_ms: t0.elapsed().as_millis() as u64,
        probes: outcomes,
        summary: ScanSummary {
            total,
            hits,
            critical_hits,
            reachable,
        },
    }))
}
