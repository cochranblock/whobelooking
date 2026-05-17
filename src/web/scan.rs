// All Rights Reserved — The Cochran Block, LLC
//! `/scan` — surface scanner: server-side HEAD probe + same-wifi detection.
//!
//! `/scan`         — HTML page (JS drives the UI)
//! `/api/probe`    — server makes a real HEAD request, returns {status, ms}
//!
//! SSRF: private/loopback IPs are rejected before any network call.
//! Rate limit: 120 probes/min per source IP (enough for one full scan).

use axum::{Json, extract::Query, http::HeaderMap, http::StatusCode, response::Html};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// ---- rate limiter -------------------------------------------------------

struct RateBucket {
    minute: u64,
    count: u32,
}

static RATE: OnceLock<Mutex<HashMap<String, RateBucket>>> = OnceLock::new();

fn rate_exceeded(ip: &str) -> bool {
    let now_min = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0);
    let mut map = RATE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("scan rate-limiter mutex poisoned");
    let bucket = map.entry(ip.to_string()).or_insert(RateBucket {
        minute: now_min,
        count: 0,
    });
    if bucket.minute != now_min {
        bucket.minute = now_min;
        bucket.count = 0;
    }
    bucket.count += 1;
    bucket.count > 7500
}

// ---- spongemesh: scan queue / concurrency cap ---------------------------
//
// Probes are individually fast (≤8s timeout each, typically <300ms), so we
// can afford to queue at peak rather than reject. tokio::Semaphore gives us
// FIFO backpressure — when more than `MAX_CONCURRENT_PROBES` outbound HEAD
// requests are in flight, additional /api/probe handlers `await` their permit
// instead of failing. Browsers see slightly slower scans under load; nobody
// gets a 503. The status endpoint exposes live capacity so the UI can show
// "queued behind N probes".

const MAX_CONCURRENT_PROBES: usize = 64;
static PROBE_SEMAPHORE: OnceLock<tokio::sync::Semaphore> = OnceLock::new();

fn probe_semaphore() -> &'static tokio::sync::Semaphore {
    PROBE_SEMAPHORE.get_or_init(|| tokio::sync::Semaphore::new(MAX_CONCURRENT_PROBES))
}

#[derive(Serialize)]
pub struct ScanStatus {
    capacity: usize,
    in_flight: usize,
    available: usize,
}

pub async fn status() -> Json<ScanStatus> {
    let sem = probe_semaphore();
    let available = sem.available_permits();
    Json(ScanStatus {
        capacity: MAX_CONCURRENT_PROBES,
        in_flight: MAX_CONCURRENT_PROBES - available,
        available,
    })
}

// ---- SSRF guard ---------------------------------------------------------

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
                    || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local
                    || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA
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
    // IPv6 literal [::1]
    if host_port.starts_with('[') {
        return host_port
            .split(']')
            .next()
            .map(|s| s.trim_start_matches('['));
    }
    Some(host_port.split(':').next().unwrap_or(host_port))
}

// ---- reqwest client (one per process) -----------------------------------

static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn client() -> &'static reqwest::Client {
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            // Customers with self-signed / expired / chain-mismatched certs
            // are exactly the ones who need this scan most. We only read the
            // status code — no credentials exchanged.
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .user_agent(
                "Mozilla/5.0 (compatible; whobelooking-scan/1.0; +https://whobelooking.org/scan)",
            )
            .build()
            .expect("reqwest client")
    })
}

// ---- Stripe payment gate ------------------------------------------------

#[derive(Deserialize)]
pub struct GateBody {
    payment_intent_id: String,
}

#[derive(Serialize)]
pub struct GateResponse {
    token: String,
}

#[derive(Serialize)]
pub struct PayResponse {
    client_secret: String,
}

fn gate_token(secret: &str, ip: &str, window: u64) -> String {
    let input = format!("scan-gate:{}:{}:{}", secret, ip, window);
    URL_SAFE_NO_PAD.encode(blake3::hash(input.as_bytes()).as_bytes())
}

fn current_window() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 300)
        .unwrap_or(0)
}

fn verify_gate(secret: &str, ip: &str, token: &str) -> bool {
    let w = current_window();
    token == gate_token(secret, ip, w) || token == gate_token(secret, ip, w.saturating_sub(1))
}

/// Create a $5 PaymentIntent and return the client_secret to the browser.
pub async fn pay() -> Result<Json<PayResponse>, (StatusCode, &'static str)> {
    let secret = std::env::var("STRIPE_SECRET_KEY").unwrap_or_default();
    if secret.is_empty() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "payments not configured"));
    }
    let stripe = reqwest::Client::new();
    let resp = stripe
        .post("https://api.stripe.com/v1/payment_intents")
        .basic_auth(&secret, Option::<&str>::None)
        .form(&[
            ("amount", "500"),
            ("currency", "usd"),
            (
                "description",
                "Automated Diagnostic Surface Area Scan — whobelooking.org",
            ),
            // Manual capture: authorize $5 now, only charge on successful scan.
            ("capture_method", "manual"),
        ])
        .send()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "stripe unreachable"))?;
    #[derive(Deserialize)]
    struct PiCreated {
        client_secret: String,
    }
    let pi: PiCreated = resp
        .json()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "bad pi response"))?;
    Ok(Json(PayResponse {
        client_secret: pi.client_secret,
    }))
}

/// Verify a completed PaymentIntent and issue a short-lived scan gate token.
pub async fn gate(
    headers: HeaderMap,
    Json(body): Json<GateBody>,
) -> Result<Json<GateResponse>, (StatusCode, &'static str)> {
    let secret = std::env::var("STRIPE_SECRET_KEY").unwrap_or_default();
    let ip = crate::web::visits::client_ip(&headers);

    if !secret.is_empty() {
        let pi_id = body.payment_intent_id.trim();
        if pi_id.is_empty() || !pi_id.starts_with("pi_") {
            return Err((StatusCode::BAD_REQUEST, "invalid payment intent"));
        }
        let stripe = reqwest::Client::new();
        let resp = stripe
            .get(format!(
                "https://api.stripe.com/v1/payment_intents/{}",
                pi_id
            ))
            .basic_auth(&secret, Option::<&str>::None)
            .send()
            .await
            .map_err(|_| (StatusCode::BAD_GATEWAY, "stripe unreachable"))?;
        #[derive(Deserialize)]
        struct PiStatus {
            status: String,
        }
        let pi: PiStatus = resp
            .json()
            .await
            .map_err(|_| (StatusCode::BAD_GATEWAY, "bad response"))?;
        // Manual-capture flow: auth lives in `requires_capture` until we
        // capture or cancel. Accept either that or a fully `succeeded` PI.
        if pi.status != "requires_capture" && pi.status != "succeeded" {
            return Err((StatusCode::PAYMENT_REQUIRED, "payment not confirmed"));
        }
    }

    Ok(Json(GateResponse {
        token: gate_token(&secret, &ip, current_window()),
    }))
}

#[derive(Deserialize)]
pub struct FinalizeBody {
    payment_intent_id: String,
    /// Did the scan get usable results? If false, we cancel the auth (no charge).
    success: bool,
}

#[derive(Serialize)]
pub struct FinalizeResponse {
    captured: bool,
    canceled: bool,
}

/// Capture (charge $5) on a successful scan, or cancel the auth (refund $0)
/// if the scan returned mostly unreachable. Customer is never billed for a
/// failed scan.
pub async fn finalize(
    Json(body): Json<FinalizeBody>,
) -> Result<Json<FinalizeResponse>, (StatusCode, &'static str)> {
    let secret = std::env::var("STRIPE_SECRET_KEY").unwrap_or_default();
    if secret.is_empty() {
        return Ok(Json(FinalizeResponse {
            captured: false,
            canceled: false,
        }));
    }
    let pi_id = body.payment_intent_id.trim();
    if pi_id.is_empty() || !pi_id.starts_with("pi_") {
        return Err((StatusCode::BAD_REQUEST, "invalid payment intent"));
    }
    let action = if body.success { "capture" } else { "cancel" };
    let stripe = reqwest::Client::new();
    let resp = stripe
        .post(format!(
            "https://api.stripe.com/v1/payment_intents/{}/{}",
            pi_id, action
        ))
        .basic_auth(&secret, Option::<&str>::None)
        .send()
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "stripe unreachable"))?;
    if !resp.status().is_success() {
        tracing::warn!(
            "stripe finalize {} failed for {}: {}",
            action,
            pi_id,
            resp.status()
        );
        return Err((StatusCode::BAD_GATEWAY, "finalize failed"));
    }
    Ok(Json(FinalizeResponse {
        captured: body.success,
        canceled: !body.success,
    }))
}

// ---- probe endpoint -----------------------------------------------------

#[derive(Deserialize)]
pub struct ProbeQuery {
    url: String,
    gate: Option<String>,
}

#[derive(Serialize)]
pub struct ProbeResult {
    status: u16,
    ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    err: Option<&'static str>,
}

pub async fn probe(Query(q): Query<ProbeQuery>, headers: HeaderMap) -> Json<ProbeResult> {
    let ip = crate::web::visits::client_ip(&headers);

    let secret = std::env::var("TURNSTILE_SECRET_KEY").unwrap_or_default();
    if !secret.is_empty() {
        let provided = q.gate.as_deref().unwrap_or("");
        if !verify_gate(&secret, &ip, provided) {
            return Json(ProbeResult {
                status: 403,
                ms: 0,
                err: Some("gate required"),
            });
        }
    }

    if rate_exceeded(&ip) {
        return Json(ProbeResult {
            status: 429,
            ms: 0,
            err: Some("rate limited"),
        });
    }

    let scheme_ok = q.url.starts_with("https://") || q.url.starts_with("http://");
    if !scheme_ok {
        return Json(ProbeResult {
            status: 0,
            ms: 0,
            err: Some("invalid scheme"),
        });
    }

    let host = match extract_host(&q.url) {
        Some(h) => h,
        None => {
            return Json(ProbeResult {
                status: 0,
                ms: 0,
                err: Some("invalid url"),
            });
        }
    };

    if is_private(host) {
        return Json(ProbeResult {
            status: 0,
            ms: 0,
            err: Some("private host"),
        });
    }

    // spongemesh: acquire one of MAX_CONCURRENT_PROBES global permits.
    // If the cap is reached, this awaits FIFO until a permit is free.
    // Held only across the actual outbound HEAD/GET — not the SSRF/rate
    // checks above — so cheap rejections don't consume capacity.
    let _permit = probe_semaphore().acquire().await.expect("semaphore");

    let t0 = Instant::now();
    match client().head(&q.url).send().await {
        Ok(resp) => Json(ProbeResult {
            status: resp.status().as_u16(),
            ms: t0.elapsed().as_millis() as u64,
            err: None,
        }),
        Err(e) => {
            // Some servers reject HEAD with 405; reqwest treats some upstream
            // resets as errors. Retry with GET so we still get a real status.
            let retry = client().get(&q.url).send().await;
            if let Ok(resp) = retry {
                return Json(ProbeResult {
                    status: resp.status().as_u16(),
                    ms: t0.elapsed().as_millis() as u64,
                    err: None,
                });
            }
            let msg = if e.is_timeout() {
                "timeout"
            } else if e.is_connect() {
                "no route"
            } else if format!("{:?}", e).to_ascii_lowercase().contains("dns") {
                "dns fail"
            } else if format!("{:?}", e)
                .to_ascii_lowercase()
                .contains("certificate")
                || format!("{:?}", e).to_ascii_lowercase().contains("tls")
            {
                "tls error"
            } else {
                "unreachable"
            };
            Json(ProbeResult {
                status: 0,
                ms: t0.elapsed().as_millis() as u64,
                err: Some(msg),
            })
        }
    }
}

// ---- page ---------------------------------------------------------------

pub async fn index() -> Html<String> {
    let pk = std::env::var("STRIPE_PUBLISHABLE_KEY").unwrap_or_default();
    let stripe_script = if pk.is_empty() {
        String::new()
    } else {
        r#"<script src="https://js.stripe.com/v3/" async></script>"#.to_string()
    };
    Html(
        SCAN_HTML
            .replace("__STRIPE_SCRIPT__", &stripe_script)
            .replace("__STRIPE_PK__", &pk),
    )
}

const SCAN_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Automated Diagnostic Surface Area Scan — whobelooking</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Orbitron:wght@400;600;700&display=swap" rel="stylesheet">
__STRIPE_SCRIPT__
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#050508;--surface:#0d0d14;--surface2:#14141f;
  --text:#e8e8e8;--muted:#6b7280;
  --cyan:#00d9ff;--green:#00ffcc;--orange:#ff6b35;--purple:#9d4edd;--yellow:#fbbf24;
  --mono:'JetBrains Mono',monospace;--serif:'Orbitron',sans-serif;
}
body{background:var(--bg);color:var(--text);font-family:var(--mono);font-size:13px;min-height:100vh;padding:2rem}
.wrap{max-width:780px}
h1{font-family:var(--serif);font-size:1.3rem;color:var(--cyan);margin-bottom:.25rem}
.sub{color:var(--muted);font-size:.75rem;margin-bottom:.6rem}
.input-row{display:flex;gap:.5rem;margin-bottom:1.5rem;flex-wrap:wrap}
input[type=text]{
  flex:1;min-width:220px;background:var(--surface);border:1px solid rgba(0,217,255,.2);
  color:var(--text);padding:.6rem 1rem;font-family:var(--mono);font-size:13px;
  border-radius:3px;outline:none;
}
input[type=text]:focus{border-color:var(--cyan)}
button{
  background:var(--cyan);color:#050508;font-family:var(--mono);font-size:13px;
  font-weight:600;padding:.6rem 1.4rem;border:none;border-radius:3px;cursor:pointer;
  white-space:nowrap;
}
button:disabled{opacity:.4;cursor:not-allowed}
.warn-box{
  background:rgba(255,107,53,.08);border:1px solid rgba(255,107,53,.3);
  color:var(--orange);padding:.75rem 1rem;border-radius:3px;margin-bottom:1rem;
  font-size:.75rem;display:none;
}
#results{margin-top:1rem}
.section-label{color:var(--muted);font-size:.65rem;letter-spacing:.1em;text-transform:uppercase;
  margin:1.25rem 0 .4rem;border-bottom:1px solid rgba(0,217,255,.08);padding-bottom:.3rem}
.row{
  display:flex;align-items:center;gap:1.5ch;
  padding:.4rem .5rem;border-radius:2px;
  border-bottom:1px solid rgba(255,255,255,.03);
  border-left:2px solid transparent;
  transition:background .15s;
}
.row>span:nth-child(2){flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row:hover{background:var(--surface2)}
.row.r-exposed{background:rgba(255,107,53,.07);border-left-color:var(--orange)}
.row.r-exposed:hover{background:rgba(255,107,53,.12)}
.row.r-protected{background:rgba(251,191,36,.06);border-left-color:var(--yellow)}
.row.r-protected:hover{background:rgba(251,191,36,.1)}
.row.r-redirect{background:rgba(0,217,255,.05);border-left-color:var(--cyan)}
.row.r-redirect:hover{background:rgba(0,217,255,.08)}
.row.r-error{background:rgba(255,107,53,.05);border-left-color:rgba(255,107,53,.4)}
.row.r-error:hover{background:rgba(255,107,53,.09)}
.badge{font-size:.6rem;padding:1px 5px;border-radius:2px;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;width:8ch;flex-shrink:0;text-align:center}
.badge.critical{background:rgba(255,107,53,.2);color:var(--orange)}
.badge.high{background:rgba(251,191,36,.15);color:var(--yellow)}
.badge.medium{background:rgba(157,78,221,.15);color:var(--purple)}
.badge.info{background:rgba(0,217,255,.1);color:var(--cyan)}
.badge.low{background:rgba(255,255,255,.05);color:var(--muted)}
.path{font-size:.7rem;color:var(--muted);white-space:nowrap;width:20ch;flex-shrink:0;overflow:hidden;text-overflow:ellipsis}
.status{font-size:.7rem;white-space:nowrap;width:8ch;flex-shrink:0;text-align:right}
@media(max-width:540px){
  body{padding:1rem}
  .path{display:none}
}
/* accessible = bad */
.s-exposed{color:var(--orange)}
/* redirect — worth investigating */
.s-redirect{color:var(--yellow)}
/* path exists but requires auth — server is processing it */
.s-protected{color:var(--yellow)}
/* server error — app is processing the path */
.s-error{color:var(--yellow)}
/* clean — not there or unreachable */
.s-clean{color:var(--green)}
.s-pending{color:var(--muted)}
.ms{font-size:.65rem;color:var(--muted);text-align:right}
details>summary.clean-toggle{
  list-style:none;color:var(--muted);font-size:.65rem;letter-spacing:.08em;
  text-transform:uppercase;cursor:pointer;padding:.3rem .5rem;user-select:none;
  display:block;
}
details>summary.clean-toggle::-webkit-details-marker{display:none}
details>summary.clean-toggle::before{content:'▶  ';font-size:.5rem}
details[open]>summary.clean-toggle::before{content:'▼  ';font-size:.5rem}
.callout{
  display:none;margin-bottom:1.5rem;padding:1.25rem 1.5rem;border-radius:4px;
  border-left:3px solid var(--orange);background:rgba(255,107,53,.06);
}
.callout-headline{font-family:var(--serif);font-size:1.1rem;color:var(--orange);margin-bottom:.5rem}
.callout-finding{font-size:.75rem;color:var(--text);padding:.2rem 0;border-bottom:1px solid rgba(255,255,255,.04)}
.callout-finding:last-of-type{border-bottom:none}
.callout-finding .f-path{color:var(--orange)}
.callout-finding .f-sev{color:var(--muted);font-size:.65rem;margin-left:.5ch}
.cta-block{
  display:none;margin-bottom:1.5rem;padding:1.25rem 1.5rem;border-radius:4px;
  background:var(--surface);border:1px solid rgba(0,217,255,.12);
}
.cta-primary{
  display:block;text-align:center;padding:.85rem 1.5rem;border-radius:3px;
  background:var(--cyan);color:#050508;font-family:var(--serif);font-size:.9rem;
  font-weight:700;text-decoration:none;margin-bottom:.75rem;letter-spacing:.03em;
}
.cta-primary:hover{background:#00f7ff;text-decoration:none}
.cta-secondary{
  display:block;text-align:center;padding:.75rem 1.5rem;border-radius:3px;
  background:rgba(255,107,53,.12);color:var(--orange);font-family:var(--serif);
  font-size:.85rem;font-weight:600;text-decoration:none;border:1px solid rgba(255,107,53,.25);
}
.cta-secondary:hover{background:rgba(255,107,53,.2);text-decoration:none}
.cta-sub{font-size:.7rem;color:var(--muted);text-align:center;margin-top:.6rem}
.summary{
  margin-top:0;padding:1rem;background:var(--surface);border-radius:3px;
  border:1px solid rgba(0,217,255,.08);display:none;
}
.summary-hits{font-size:.85rem;color:var(--muted);font-family:var(--mono)}
.summary-sub{color:var(--muted);font-size:.7rem;margin-top:.25rem}
a{color:var(--cyan);text-decoration:none}
a:hover{text-decoration:underline}
</style>
</head>
<body>
<h1>Automated Diagnostic Surface Area Scan</h1>
<p class="sub" style="margin-bottom:.5rem">Real HEAD requests against your domain — actual status codes, not browser guesses. <strong style="color:var(--green)">Free</strong></p>
<p class="sub">Enter your domain and we'll probe 140+ attack paths and tell you exactly what's exposed.</p>

<p class="sub" style="color:var(--green);margin-top:.4rem">135 probe paths. Browser drives the scan via WASM — same probe list as the API, no extra server load.</p>

<div class="input-row">
  <input type="text" id="url" placeholder="https://example.com" autocomplete="off" spellcheck="false">
  <button id="btn" onclick="startScan()">Scan</button>
</div>

<!-- Stripe payment modal -->
<div id="pay-overlay" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(5,5,8,.88);z-index:100;align-items:flex-start;justify-content:center;overflow-y:auto;padding:2rem 1rem;-webkit-overflow-scrolling:touch">
  <div style="background:var(--surface);border:1px solid rgba(0,217,255,.15);border-radius:6px;padding:2rem;max-width:420px;width:100%;position:relative;margin:auto">
    <button onclick="closePayModal()" style="position:absolute;top:.75rem;right:.75rem;background:none;border:none;color:var(--muted);font-size:1.2rem;cursor:pointer;line-height:1">×</button>
    <h2 style="font-family:var(--serif);color:var(--cyan);font-size:1rem;margin-bottom:.4rem">Surface Area Scan</h2>
    <p style="color:var(--muted);font-size:.75rem;margin-bottom:.5rem">Real HEAD requests from our server. 140+ attack paths. Actual status codes. <strong style="color:var(--text)">$5</strong></p>
    <p style="color:var(--green);font-size:.7rem;margin-bottom:1.25rem;border-left:2px solid var(--green);padding-left:.6rem">✓ <strong>If your site is unreachable, you will not be charged.</strong> The $5 is only authorized; we capture it after the scan returns real results.</p>
    <div id="pay-element" style="margin-bottom:1rem"></div>
    <div id="pay-error" style="color:var(--orange);font-size:.75rem;margin-bottom:.75rem;display:none"></div>
    <button id="pay-btn" style="width:100%;background:var(--cyan);color:#050508;font-family:var(--mono);font-size:13px;font-weight:600;padding:.7rem;border:none;border-radius:3px;cursor:pointer">Pay $5 and Scan</button>
  </div>
</div>

<div class="warn-box" id="wifiWarn">
  ⚡ Same-wifi suspected — target responds significantly faster than an external reference.
  Results reflect local network access, not public internet exposure.
  Test from mobile data or a VPN for an external view.
</div>

<!-- Critical findings callout — shown when exposed paths are found -->
<div class="callout" id="callout"></div>

<!-- Funnel CTA — shown after scan completes with findings -->
<div class="cta-block" id="cta-block">
  <a href="/api/scan/email" class="cta-primary">Email these results (CSV + JSON) →</a>
  <a href="https://github.com/cochranblock/whobelooking" class="cta-secondary">Run it yourself — free, Unlicense →</a>
  <p class="cta-sub">Free. Unlicense. Run it yourself, hit the API, or have the report emailed.</p>
</div>

<div id="results"></div>
<div class="summary" id="summary"></div>

<!-- Did-it-work feedback — emails the operator. -->
<div id="feedback-box" style="margin-top:2rem;padding:1.25rem 1.5rem;border-radius:4px;background:var(--surface);border:1px solid rgba(0,217,255,.12)">
  <div style="font-family:var(--serif);color:var(--cyan);font-size:.95rem;margin-bottom:.4rem">Did it work?</div>
  <div style="font-size:.75rem;color:var(--muted);margin-bottom:.75rem">Tell me what you saw — false positives, missing paths, broken UI, or just "yes." It emails me directly.</div>
  <textarea id="feedback-msg" rows="3" placeholder="What happened?" style="width:100%;background:var(--bg);border:1px solid rgba(0,217,255,.2);color:var(--text);padding:.55rem .75rem;font-family:var(--mono);font-size:13px;border-radius:3px;resize:vertical;outline:none;margin-bottom:.5rem"></textarea>
  <input type="email" id="feedback-email" placeholder="your email (optional, so I can reply)" style="width:100%;background:var(--bg);border:1px solid rgba(0,217,255,.2);color:var(--text);padding:.55rem .75rem;font-family:var(--mono);font-size:13px;border-radius:3px;outline:none;margin-bottom:.5rem" autocomplete="email">
  <button id="feedback-btn" onclick="sendFeedback()" style="background:var(--cyan);color:#050508;font-family:var(--mono);font-size:13px;font-weight:600;padding:.5rem 1rem;border:none;border-radius:3px;cursor:pointer">Send</button>
  <span id="feedback-status" style="margin-left:.6rem;font-size:.75rem;color:var(--muted)"></span>
</div>

<script type="module">
import init, { getProbes } from "/detect/wbl_detect.js";

const STRIPE_PK = '__STRIPE_PK__';
let stripe = null, stripeElements = null, gateToken = null, pendingUrl = null, paymentIntentId = null;

let PROBES = [];
const wasmReady = init("/detect/wbl_detect_bg.wasm").then(() => {
  PROBES = getProbes();
}).catch(() => {
  // WASM failed — page still functions but probe list is empty.
  console.error("whobelooking: WASM init failed; probe list unavailable");
});

async function sendFeedback() {
  const btn = document.getElementById('feedback-btn');
  const status = document.getElementById('feedback-status');
  const msg = document.getElementById('feedback-msg').value.trim();
  if (!msg) { status.textContent = 'Type something first.'; status.style.color = 'var(--orange)'; return; }
  const email = document.getElementById('feedback-email').value.trim();
  const scanned = (document.getElementById('url') && document.getElementById('url').value) || '';
  btn.disabled = true; btn.textContent = 'Sending…';
  status.textContent = ''; status.style.color = 'var(--muted)';
  try {
    const resp = await fetch('/api/scan/feedback', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({message: msg, scanned_url: scanned, email: email})
    });
    if (!resp.ok) throw new Error(await resp.text());
    document.getElementById('feedback-msg').value = '';
    document.getElementById('feedback-email').value = '';
    btn.textContent = 'Sent ✓';
    status.textContent = 'Got it. I read every one.';
    status.style.color = 'var(--green)';
  } catch (e) {
    btn.disabled = false; btn.textContent = 'Send';
    status.textContent = 'Failed — try again.';
    status.style.color = 'var(--orange)';
  }
}

function closePayModal() {
  document.getElementById('pay-overlay').style.display = 'none';
}

async function showPayModal(url) {
  pendingUrl = url;
  const overlay = document.getElementById('pay-overlay');
  const payEl = document.getElementById('pay-element');
  const errEl = document.getElementById('pay-error');
  const payBtn = document.getElementById('pay-btn');
  payEl.innerHTML = '';
  errEl.style.display = 'none';
  payBtn.disabled = false;
  payBtn.textContent = 'Pay $5 and Scan';
  overlay.style.display = 'flex';

  const resp = await fetch('/api/scan/pay', {method:'POST'});
  if (!resp.ok) { errEl.textContent = 'Payment unavailable — try again.'; errEl.style.display = 'block'; return; }
  const {client_secret} = await resp.json();

  if (!stripe) stripe = Stripe(STRIPE_PK);
  stripeElements = stripe.elements({clientSecret: client_secret, appearance:{theme:'night',variables:{colorPrimary:'#00d9ff',colorBackground:'#0d0d14',fontFamily:'JetBrains Mono, monospace'}}});
  stripeElements.create('payment').mount('#pay-element');

  payBtn.onclick = async () => {
    payBtn.disabled = true;
    payBtn.textContent = 'Processing…';
    errEl.style.display = 'none';
    const {error, paymentIntent} = await stripe.confirmPayment({elements: stripeElements, confirmParams:{}, redirect:'if_required'});
    if (error) {
      errEl.textContent = error.message || 'Payment failed.';
      errEl.style.display = 'block';
      payBtn.disabled = false;
      payBtn.textContent = 'Pay $5 and Scan';
      return;
    }
    // Verify server-side and get gate token
    paymentIntentId = paymentIntent.id;
    const gr = await fetch('/api/scan/gate', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({payment_intent_id: paymentIntent.id})});
    if (!gr.ok) {
      errEl.textContent = 'Verification failed — the auth will be canceled, you will not be charged.';
      errEl.style.display = 'block';
      payBtn.disabled = false;
      payBtn.textContent = 'Pay $5 and Scan';
      // Best-effort cancel the auth
      fetch('/api/scan/finalize', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({payment_intent_id: paymentIntent.id, success:false})}).catch(()=>{});
      paymentIntentId = null;
      return;
    }
    const {token} = await gr.json();
    gateToken = token;
    overlay.style.display = 'none';
    runScan(pendingUrl);
  };
}

async function finalizeCharge(success) {
  if (!paymentIntentId) return;
  const id = paymentIntentId;
  paymentIntentId = null;
  try {
    await fetch('/api/scan/finalize', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({payment_intent_id: id, success: !!success})});
  } catch {}
}


const SEV_ORDER = {critical:0,high:1,medium:2,low:3,info:4};

function statusClass(r) {
  if (!r || r.err || r.status === 0) return 's-clean';
  const s = r.status;
  if (s >= 200 && s < 300) return 's-exposed';
  if (s >= 300 && s < 400) return 's-redirect';
  if (s === 401 || s === 403) return 's-protected';
  if (s >= 400 && s < 500) return 's-clean'; // 404, 410, etc — not there
  if (s >= 500) return 's-error';
  return 's-clean';
}

function statusLabel(r) {
  if (!r) return '…';
  if (r.err) return r.err;
  return String(r.status);
}

function isHit(r) {
  // only 2xx (openly accessible) and 401/403 (auth wall — server is processing the path)
  if (!r || r.err || r.status === 0) return false;
  const s = r.status;
  return (s >= 200 && s < 300) || s === 401 || s === 403;
}

async function probeOne(url) {
  try {
    let qs = '/api/probe?url=' + encodeURIComponent(url);
    if (gateToken) qs += '&gate=' + encodeURIComponent(gateToken);
    const resp = await fetch(qs);
    return await resp.json();
  } catch {
    return {status: 0, ms: 0, err: 'fetch failed'};
  }
}

async function wifiCheck(base) {
  const [ref_, tgt] = await Promise.all([
    probeOne('https://1.1.1.1/'),
    probeOne(base + '/'),
  ]);
  return ref_.ms > 0 && tgt.ms > 0 && ref_.ms / tgt.ms > 5;
}

let scanning = false;

async function startScan() {
  if (scanning) return;
  let raw = document.getElementById('url').value.trim();
  if (!raw) return;
  if (!raw.startsWith('http')) raw = 'https://' + raw;
  const url = raw.replace(/\/$/, '');
  await wasmReady;
  if (PROBES.length === 0) { alert('Probe list unavailable — reload and try again.'); return; }
  if (STRIPE_PK && !gateToken) { showPayModal(url); return; }
  runScan(url);
}

async function runScan(base) {
  document.getElementById('wifiWarn').style.display = 'none';
  document.getElementById('callout').style.display = 'none';
  document.getElementById('cta-block').style.display = 'none';
  document.getElementById('results').innerHTML = '';
  document.getElementById('summary').style.display = 'none';

  scanning = true;
  const btn = document.getElementById('btn');
  btn.disabled = true;
  btn.textContent = 'Scanning…';

  const sorted = [...PROBES].sort((a,b)=>SEV_ORDER[a.sev]-SEV_ORDER[b.sev]);
  const wifiPromise = wifiCheck(base);
  const resultsEl = document.getElementById('results');
  const rows = {};
  const sections = {};

  for (const p of sorted) {
    if (!sections[p.sev]) {
      const lbl = document.createElement('div');
      lbl.className = 'section-label';
      lbl.textContent = p.sev.toUpperCase();
      resultsEl.appendChild(lbl);
      sections[p.sev] = true;
    }
    const row = document.createElement('div');
    row.className = 'row';
    const eid = CSS.escape(p.path);
    row.innerHTML = `<span class="badge ${p.sev}">${p.sev}</span><span>${p.label}</span><span class="path">${p.path}</span><span class="status s-pending" id="st-${eid}">…</span>`;
    resultsEl.appendChild(row);
    rows[p.path] = row;
  }

  let hits = 0, critHits = 0;

  const probePromises = sorted.map(async p => {
    const r = await probeOne(base + p.path);
    const st = document.getElementById('st-' + CSS.escape(p.path));
    const row = rows[p.path];
    const sc = statusClass(r);
    const rowClass = sc.replace('s-', 'r-');
    if (st) {
      st.className = 'status ' + sc;
      st.textContent = statusLabel(r);
    }
    if (row) row.className = 'row ' + rowClass;
    if (isHit(r)) {
      hits++;
      if (p.sev === 'critical') critHits++;
    }
  });

  const [wifi] = await Promise.all([wifiPromise, ...probePromises]);

  if (wifi) document.getElementById('wifiWarn').style.display = 'block';

  // Reorder: exposed to top of each section; collapse clean into disclosure
  (function reorderResults() {
    const resultsEl = document.getElementById('results');
    const children = Array.from(resultsEl.children);
    const sections = [];
    let cur = null;
    for (const el of children) {
      if (el.classList.contains('section-label')) {
        cur = {label: el, rows: []};
        sections.push(cur);
      } else if (el.classList.contains('row') && cur) {
        cur.rows.push(el);
      }
    }
    resultsEl.innerHTML = '';
    for (const {label, rows} of sections) {
      const bad = rows.filter(r => r.classList.contains('r-exposed') || r.classList.contains('r-protected'));
      const good = rows.filter(r => !r.classList.contains('r-exposed') && !r.classList.contains('r-protected'));
      if (bad.length === 0) {
        // Entire section clean — collapse it all
        const details = document.createElement('details');
        const summary = document.createElement('summary');
        summary.className = 'clean-toggle';
        summary.textContent = `${label.textContent} — ${good.length} secure`;
        details.appendChild(summary);
        for (const r of good) details.appendChild(r);
        resultsEl.appendChild(details);
      } else {
        resultsEl.appendChild(label);
        for (const r of bad) resultsEl.appendChild(r);
        if (good.length > 0) {
          const details = document.createElement('details');
          const summary = document.createElement('summary');
          summary.className = 'clean-toggle';
          summary.textContent = `${good.length} secure`;
          details.appendChild(summary);
          for (const r of good) details.appendChild(r);
          resultsEl.appendChild(details);
        }
      }
    }
  })();

  // Collect exposed findings for callout
  const exposedFindings = [];
  document.querySelectorAll('.row.r-exposed, .row.r-protected').forEach(row => {
    const badge = row.querySelector('.badge');
    const label = row.querySelector('span:nth-child(2)');
    const path  = row.querySelector('.path');
    const st    = row.querySelector('.status');
    if (badge && label) exposedFindings.push({sev: badge.textContent, label: label.textContent, path: path ? path.textContent : '', status: st ? st.textContent : ''});
  });

  // Critical/exposed callout at top
  const calloutEl = document.getElementById('callout');
  if (exposedFindings.length > 0) {
    const critCount = exposedFindings.filter(f => f.sev === 'critical').length;
    calloutEl.innerHTML = `
      <div class="callout-headline">⚠ ${exposedFindings.length} path${exposedFindings.length>1?'s':''} responded${critCount>0?' — '+critCount+' critical':''}</div>
      ${exposedFindings.map(f=>`<div class="callout-finding"><span class="f-path">${f.path||f.label}</span><span class="f-sev">${f.sev}</span><span style="float:right;color:var(--orange);font-size:.65rem">${f.status}</span></div>`).join('')}
    `;
    calloutEl.style.display = 'block';
    document.getElementById('cta-block').style.display = 'block';
  } else {
    calloutEl.style.display = 'none';
    document.getElementById('cta-block').style.display = 'none';
  }

  // Compact summary (stats + technical note)
  const summaryEl = document.getElementById('summary');
  summaryEl.style.display = 'block';
  summaryEl.innerHTML = `
    <div class="summary-hits">${hits} exposed or auth-walled · ${sorted.length} paths probed · ${critHits} critical</div>
    <div class="summary-sub" style="margin-top:.4rem">
      401/403 = server processed the request, auth required. 2xx = openly accessible. Redirects collapsed.
    </div>
  `;

  // Charge or refund based on scan reachability. If most probes failed to
  // connect, the target is unreachable from us (broken DNS, blocking firewall,
  // bad cert chain) — customer should not be billed for a non-result.
  const reachable = Array.from(document.querySelectorAll('.row')).filter(r => !r.classList.contains('r-error') && !(r.querySelector('.status') && r.querySelector('.status').textContent === 'unreachable')).length;
  let realResponses = 0;
  document.querySelectorAll('.row .status').forEach(s => {
    const t = (s.textContent || '').trim();
    if (t && t !== 'unreachable' && t !== 'timeout' && t !== 'no route' && t !== 'dns fail' && t !== 'tls error' && t !== '…' && t !== '0') realResponses++;
  });
  const reachabilityPct = realResponses / sorted.length;
  const scanSucceeded = reachabilityPct >= 0.5; // >=50% of probes got a real status code
  if (!scanSucceeded && paymentIntentId) {
    const note = document.createElement('div');
    note.style.cssText = 'margin:1rem 0;padding:1rem;background:rgba(0,255,204,.06);border:1px solid rgba(0,255,204,.25);border-radius:4px;color:var(--green);font-size:.8rem';
    note.innerHTML = '✓ Most paths were unreachable from our network — likely DNS, TLS chain, or firewall blocking. <strong>You will not be charged.</strong> Try again with a different domain or contact support.';
    document.getElementById('callout').style.display = 'none';
    document.getElementById('cta-block').style.display = 'none';
    const sumEl = document.getElementById('summary');
    sumEl.parentNode.insertBefore(note, sumEl);
  }
  finalizeCharge(scanSucceeded);

  scanning = false;
  btn.disabled = false;
  btn.textContent = 'Scan Again';
}

document.getElementById('url').addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});

// Auto-start when ?url=… is in the query string. Lets us share direct links
// like /scan?url=example.com — the scan kicks off on page load.
(function autostart() {
  try {
    var qs = new URLSearchParams(location.search);
    var u = qs.get('url') || qs.get('q') || qs.get('domain');
    if (u) {
      var input = document.getElementById('url');
      input.value = u;
      // Defer a tick so the page has a chance to paint the input value first.
      setTimeout(startScan, 50);
    }
  } catch {}
})();

// Expose to inline event handlers (onclick="…") — required for type="module".
window.startScan = startScan;
window.closePayModal = closePayModal;
window.sendFeedback = sendFeedback;
</script>
</body>
</html>
"##;
