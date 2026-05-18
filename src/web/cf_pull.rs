// Unlicense — public domain — whobelooking.org
//! `/api/cf/pull` — local proxy for Cloudflare Analytics GraphQL.
//!
//! The browser cannot call `api.cloudflare.com` directly — CF doesn't
//! set CORS headers on their GraphQL endpoint, so the preflight dies in
//! the browser. This handler solves it: the `/try` page calls localhost,
//! this handler makes the CF request server-side, and returns NDJSON in
//! CF JSONL format that the existing WASM parser already understands.
//!
//! **Token handling**: the token arrives in a query param, is used for
//! one or more CF GraphQL calls, and goes out of scope at the end of the
//! handler. It is never logged, stored, or written to disk.
//!
//! This route is only useful when `whobelooking serve` is running locally.
//! From a remote host the call would be a cross-origin request from the
//! browser, which the browser won't issue. That's the correct behavior —
//! the token should never transit a remote server.

use axum::{
    extract::Query,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Params {
    pub zone_id: String,
    pub token: String,
    #[serde(default = "default_hours")]
    pub hours: u64,
}

fn default_hours() -> u64 {
    24
}

pub async fn pull(Query(p): Query<Params>) -> Response {
    if p.zone_id.is_empty() || p.token.is_empty() {
        return (StatusCode::BAD_REQUEST, "zone_id and token are required").into_response();
    }
    if p.zone_id.len() != 32 || !p.zone_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            "zone_id must be a 32-character hex string",
        )
            .into_response();
    }
    let hours = p.hours.clamp(1, 168);

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("http client error: {e}"),
            )
                .into_response();
        }
    };

    let windows = time_windows(hours);
    let mut lines: Vec<String> = Vec::new();

    for (s, e) in &windows {
        let q = r#"query($zone:String!,$s:Time!,$e:Time!){
  viewer { zones(filter:{zoneTag:$zone}){
    httpRequestsAdaptiveGroups(limit:10000,
      filter:{datetime_geq:$s, datetime_leq:$e},
      orderBy:[count_DESC]){
        count
        dimensions {
          clientIP
          clientCountryName
          clientRequestPath
          clientRequestHTTPMethodName
          userAgent
          datetimeMinute
        }
    }}}}"#;

        let body = serde_json::json!({
            "query": q,
            "variables": { "zone": &p.zone_id, "s": s, "e": e }
        });

        let res = client
            .post("https://api.cloudflare.com/client/v4/graphql")
            .header("Authorization", format!("Bearer {}", p.token))
            .json(&body)
            .send()
            .await;

        let v = match res {
            Ok(r) if r.status().is_success() => match r.json::<serde_json::Value>().await {
                Ok(v) => v,
                Err(_) => continue,
            },
            Ok(r) => {
                let status = r.status();
                if status.as_u16() == 401 || status.as_u16() == 403 {
                    return (StatusCode::UNAUTHORIZED, "CF token rejected — check zone_id and token permissions (needs Analytics:Read)").into_response();
                }
                continue;
            }
            Err(_) => continue,
        };

        if let Some(errs) = v.get("errors").and_then(|x| x.as_array()) {
            if !errs.is_empty() {
                let msg = errs[0]
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown CF error");
                return (StatusCode::BAD_GATEWAY, format!("CF GraphQL error: {msg}"))
                    .into_response();
            }
        }

        let Some(groups) = v
            .pointer("/data/viewer/zones/0/httpRequestsAdaptiveGroups")
            .and_then(|x| x.as_array())
        else {
            continue;
        };

        for g in groups {
            let dim = &g["dimensions"];
            let ip = dim["clientIP"].as_str().unwrap_or("").trim().to_string();
            if ip.is_empty() {
                continue;
            }
            let path = dim["clientRequestPath"].as_str().unwrap_or("/").to_string();
            let method = dim["clientRequestHTTPMethodName"]
                .as_str()
                .unwrap_or("GET")
                .to_string();
            let country = dim["clientCountryName"].as_str().unwrap_or("").to_string();
            let ua = dim["userAgent"].as_str().unwrap_or("").to_string();
            let ts = dim["datetimeMinute"].as_str().unwrap_or(s).to_string();

            let line = serde_json::json!({
                "ClientIP": ip,
                "ClientRequestPath": path,
                "ClientRequestMethod": method,
                "ClientCountry": country,
                "EdgeStartTimestamp": ts,
                "ClientRequestUserAgent": ua,
            });
            lines.push(line.to_string());
        }
    }

    // Token use ends here — it falls out of scope with `p`.
    let count = lines.len();
    let body = lines.join("\n");

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    // Let the browser read the event count before parsing.
    if let Ok(v) = HeaderValue::from_str(&count.to_string()) {
        headers.insert("X-WBL-Events", v);
    }
    // Expose the header so the browser JS can read it (CORS simple response).
    headers.insert(
        "Access-Control-Expose-Headers",
        HeaderValue::from_static("X-WBL-Events"),
    );

    (headers, body).into_response()
}

fn time_windows(hours: u64) -> Vec<(String, String)> {
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
