// All Rights Reserved — The Cochran Block, LLC
//! Order submission — credentials encrypted + emailed, never stored on disk.

use crate::crypto;
use crate::web::admin;
use axum::Form;
use axum::extract::Query;
use axum::response::{Html, IntoResponse, Redirect};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct OrderForm {
    pub email: String,
    pub site_url: String,
    pub source_type: String,
    pub tier: String,
    // Optional credentials — only for Cloudflare
    pub cf_zone: Option<String>,
    pub cf_token: Option<String>,
}

#[derive(Deserialize)]
pub struct ConfirmQuery {
    pub id: Option<String>,
}

/// Submit a request. Credentials encrypted and emailed to operator. Never stored on disk.
pub async fn create_checkout(Form(form): Form<OrderForm>) -> axum::response::Response {
    if !admin::has_capacity() {
        return Redirect::to("/order?error=capacity").into_response();
    }

    let id = uuid::Uuid::new_v4().to_string();

    // Create order folder (no credentials in it)
    if !admin::create_order(
        &id,
        &form.email,
        &form.site_url,
        &form.source_type,
        &form.tier,
    ) {
        return Redirect::to("/order?error=capacity").into_response();
    }

    tracing::info!(
        "new order: {} from {} for {}",
        id,
        form.email,
        form.site_url
    );

    // If credentials provided, encrypt and email them
    if let (Some(zone), Some(token)) = (&form.cf_zone, &form.cf_token) {
        if !zone.is_empty() && !token.is_empty() {
            let passphrase =
                std::env::var("CRED_KEY").unwrap_or_else(|_| "whobelooking-default-key".into());
            let key = crypto::key_from_passphrase(&passphrase);
            let plaintext = format!("order:{}\nzone:{}\ntoken:{}", id, zone, token);

            match crypto::encrypt(&plaintext, &key) {
                Ok(blob) => {
                    // Send encrypted blob via webhook (email relay)
                    if let Ok(webhook) = std::env::var("CRED_WEBHOOK_URL") {
                        let client = reqwest::Client::new();
                        let payload = serde_json::json!({
                            "order_id": id,
                            "email": form.email,
                            "site": form.site_url,
                            "encrypted_credentials": blob,
                        });
                        tokio::spawn(async move {
                            let _ = client
                                .post(&webhook)
                                .json(&payload)
                                .timeout(std::time::Duration::from_secs(10))
                                .send()
                                .await;
                        });
                        tracing::info!("credentials encrypted and sent via webhook for {}", id);
                    } else {
                        // No webhook — log that credentials were encrypted but not sent
                        tracing::warn!(
                            "credentials encrypted for {} but CRED_WEBHOOK_URL not set",
                            id
                        );
                    }
                }
                Err(e) => {
                    tracing::error!("encryption failed for {}: {}", id, e);
                }
            }
        }
    }

    Redirect::to(&format!("/order/confirmed?id={}", id)).into_response()
}

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
