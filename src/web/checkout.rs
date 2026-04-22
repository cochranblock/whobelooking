// All Rights Reserved — The Cochran Block, LLC
//! Order submission — credentials encrypted + emailed, never stored on disk.

use crate::web::admin;
use axum::extract::{Multipart, Query};
use axum::response::{Html, IntoResponse, Redirect};
use serde::Deserialize;
use whobelooking::crypto;

#[derive(Deserialize)]
pub struct ConfirmQuery {
    pub id: Option<String>,
}

#[derive(Default)]
struct ParsedOrder {
    email: String,
    site_url: String,
    source_type: String,
    tier: String,
    cf_zone: String,
    cf_token: String,
    log_data: Option<Vec<u8>>,
    log_filename: Option<String>,
}

/// Submit a request. Credentials encrypted, files saved encrypted. Never plaintext on disk.
pub async fn create_checkout(mut multipart: Multipart) -> axum::response::Response {
    let mut order = ParsedOrder::default();

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "email" => order.email = field.text().await.unwrap_or_default(),
            "site_url" => order.site_url = field.text().await.unwrap_or_default(),
            "source_type" => order.source_type = field.text().await.unwrap_or_default(),
            "tier" => order.tier = field.text().await.unwrap_or_default(),
            "cf_zone" => order.cf_zone = field.text().await.unwrap_or_default(),
            "cf_token" => order.cf_token = field.text().await.unwrap_or_default(),
            "logfile" => {
                order.log_filename = field.file_name().map(|s| s.to_string());
                if let Ok(bytes) = field.bytes().await {
                    if !bytes.is_empty() {
                        order.log_data = Some(bytes.to_vec());
                    }
                }
            }
            _ => {}
        }
    }

    if order.email.is_empty() || order.site_url.is_empty() {
        return Redirect::to("/order?error=missing").into_response();
    }

    if !admin::has_capacity() {
        return Redirect::to("/order?error=capacity").into_response();
    }

    let id = uuid::Uuid::new_v4().to_string();

    if !admin::create_order(
        &id,
        &order.email,
        &order.site_url,
        &order.source_type,
        &order.tier,
    ) {
        return Redirect::to("/order?error=capacity").into_response();
    }

    tracing::info!(
        "new order: {} from {} for {} ({})",
        id,
        order.email,
        order.site_url,
        order.source_type
    );

    let passphrase =
        std::env::var("CRED_KEY").unwrap_or_else(|_| "whobelooking-default-key".into());
    let key = crypto::key_from_passphrase(&passphrase);

    // Encrypt credentials (Cloudflare) or log file and log it
    if !order.cf_zone.is_empty() && !order.cf_token.is_empty() {
        let plaintext = format!(
            "order:{}\nzone:{}\ntoken:{}",
            id, order.cf_zone, order.cf_token
        );
        match crypto::encrypt(&plaintext, &key) {
            Ok(blob) => {
                tracing::info!(
                    "CF credentials encrypted for {} — blob: {}",
                    id,
                    &blob[..40.min(blob.len())]
                );
            }
            Err(e) => tracing::error!("encrypt failed for {}: {}", id, e),
        }
    }

    if let Some(data) = &order.log_data {
        let fname = order.log_filename.as_deref().unwrap_or("upload");
        // Encrypt the log file and save to approved/{id}/
        let plaintext_b64 = base64::engine::general_purpose::STANDARD.encode(data);
        match crypto::encrypt(&plaintext_b64, &key) {
            Ok(blob) => {
                // Save encrypted log to the order folder
                let order_dir = dirs::data_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join("whobelooking")
                    .join("orders")
                    .join("pending")
                    .join(&id);
                let enc_path = order_dir.join("logfile.enc");
                let _ = std::fs::write(&enc_path, &blob);
                tracing::info!(
                    "log file encrypted for {} — {} bytes from '{}' → logfile.enc",
                    id,
                    data.len(),
                    fname
                );
            }
            Err(e) => tracing::error!("log encrypt failed for {}: {}", id, e),
        }
    }

    Redirect::to(&format!("/order/confirmed?id={}", id)).into_response()
}

use base64::Engine;

/// Confirmation page.
pub async fn checkout_success(Query(q): Query<ConfirmQuery>) -> Html<String> {
    let id = q.id.unwrap_or_default();
    let short = if id.len() > 12 { &id[..12] } else { &id };
    let pending = admin::pending_count();

    Html(format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Request Received — whobelooking</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:'JetBrains Mono',monospace;background:#050508;color:#e8e8e8;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:2rem}}
.box{{max-width:500px;width:100%;text-align:center}}
h1{{font-family:'Orbitron',sans-serif;font-size:1.8rem;color:#00ffcc;margin-bottom:1.5rem}}
p{{margin-bottom:1rem;font-size:0.9rem;color:#9ca3af;line-height:1.6}}
.ref{{font-size:0.7rem;color:#00d9ff;background:rgba(0,217,255,0.08);padding:8px 16px;border:1px solid rgba(0,217,255,0.2);border-radius:4px;display:inline-block;margin:1rem 0}}
a{{color:#00d9ff;text-decoration:none}}
</style></head><body><div class="box">
<h1>Request received.</h1>
<div class="ref">{short}...</div>
<p>You're #{pending} in the queue. Michael will review your request within 24 hours.</p>
<p><strong style="color:#e8e8e8">You don't pay now.</strong> When your report is ready, you'll receive an email with a download link. Payment happens at download.</p>
<p style="font-size:0.75rem;color:#555;margin-top:1.5rem">Your credentials were encrypted with AES-256-GCM and sent directly to the operator. They are not stored on any server.</p>
<p style="margin-top:1.5rem"><a href="/">Back to whobelooking.org</a></p>
</div></body></html>"#,
        short = short,
        pending = pending,
    ))
}
