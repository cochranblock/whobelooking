// All Rights Reserved — The Cochran Block, LLC
//! Stripe Checkout integration — create session, redirect customer, handle success.

use axum::extract::Query;
use axum::response::{Html, Redirect};
use axum::Form;
use serde::Deserialize;
use crate::queue::{self, SourceType, Tier};

#[derive(Deserialize)]
pub struct OrderForm {
    pub email: String,
    pub site_url: String,
    pub source_type: String,
    pub tier: String,
}

#[derive(Deserialize)]
pub struct SuccessQuery {
    pub session_id: Option<String>,
}

/// Create a Stripe Checkout Session and redirect the customer.
pub async fn create_checkout(Form(form): Form<OrderForm>) -> axum::response::Response {
    let tier = match form.tier.as_str() {
        "starter" => Tier::Starter,
        "growth" => Tier::Growth,
        "scale" => Tier::Scale,
        "custom" => Tier::Custom,
        _ => Tier::Starter,
    };

    let source_type = match form.source_type.as_str() {
        "cloudflare" => SourceType::Cloudflare { zone: String::new(), token: String::new() },
        "accesslog" => SourceType::AccessLog,
        "csv" => SourceType::Csv,
        "json" => SourceType::Json,
        _ => SourceType::AccessLog,
    };

    let stripe_key = match std::env::var("STRIPE_SECRET_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            tracing::warn!("STRIPE_SECRET_KEY not set — creating job without payment");
            // Fallback: create job directly without Stripe
            match queue::create_job(&form.email, source_type, tier) {
                Ok(id) => return Redirect::to(&format!("/order/confirmed?id={}", id)).into_response(),
                Err(e) => {
                    tracing::error!("job creation failed: {}", e);
                    return Redirect::to("/order?error=1").into_response();
                }
            }
        }
    };

    let price_cents = tier.price_cents();
    let client = reqwest::Client::new();

    let params = [
        ("payment_method_types[]", "card"),
        ("mode", "payment"),
        ("customer_email", &form.email),
        ("line_items[0][price_data][currency]", "usd"),
        ("line_items[0][price_data][unit_amount]", &price_cents.to_string()),
        ("line_items[0][price_data][product_data][name]", &format!("whobelooking {} Report", tier.label())),
        ("line_items[0][price_data][product_data][description]", &format!("Visitor intelligence report for {}", form.site_url)),
        ("line_items[0][quantity]", "1"),
        ("success_url", &format!("https://whobelooking.org/order/confirmed?session_id={{CHECKOUT_SESSION_ID}}")),
        ("cancel_url", "https://whobelooking.org/order?cancelled=1"),
        ("metadata[site_url]", &form.site_url),
        ("metadata[source_type]", &form.source_type),
        ("metadata[tier]", &form.tier),
    ];

    match client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .header("Authorization", format!("Bearer {}", stripe_key))
        .form(&params)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.json::<serde_json::Value>().await {
                    Ok(body) => {
                        if let Some(url) = body["url"].as_str() {
                            // Create job in queue as Paid
                            let _ = queue::create_job(&form.email, source_type, tier);
                            Redirect::to(url).into_response()
                        } else {
                            tracing::error!("stripe response missing url: {:?}", body);
                            Redirect::to("/order?error=stripe").into_response()
                        }
                    }
                    Err(e) => {
                        tracing::error!("stripe parse error: {}", e);
                        Redirect::to("/order?error=stripe").into_response()
                    }
                }
            } else {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                tracing::error!("stripe error {}: {}", status, body);
                Redirect::to("/order?error=stripe").into_response()
            }
        }
        Err(e) => {
            tracing::error!("stripe request failed: {}", e);
            Redirect::to("/order?error=network").into_response()
        }
    }
}

/// Success page after Stripe checkout.
pub async fn checkout_success(Query(q): Query<SuccessQuery>) -> Html<String> {
    let session_id = q.session_id.unwrap_or_default();
    let short_id = if session_id.len() > 20 { &session_id[..20] } else { &session_id };

    Html(format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Order Confirmed — whobelooking</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700&family=Rajdhani:wght@400;600&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:'JetBrains Mono',monospace;background:#050508;color:#e8e8e8;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:2rem}}
.box{{max-width:500px;width:100%;text-align:center}}
h1{{font-family:'Orbitron',sans-serif;font-size:1.8rem;color:#00ffcc;margin-bottom:1.5rem}}
p{{margin-bottom:1rem;font-size:0.9rem;color:#9ca3af;line-height:1.6}}
strong{{color:#e8e8e8}}
.ref{{font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#00d9ff;background:rgba(0,217,255,0.08);padding:8px 16px;border:1px solid rgba(0,217,255,0.2);border-radius:4px;display:inline-block;margin:1rem 0}}
a{{color:#00d9ff;text-decoration:none;border-bottom:1px solid rgba(0,217,255,0.3)}}
a:hover{{border-color:#00d9ff}}
</style></head><body><div class="box">
<h1>You're in the queue.</h1>
<p>Your visitor intelligence report is being prepared.</p>
<div class="ref">{short_id}...</div>
<p><strong>What happens next:</strong></p>
<p>Michael will review your traffic data, run the enrichment pipeline, and deliver a PDF report within 48 hours. You'll receive it at the email you provided.</p>
<p>Every IP gets reverse DNS, /24 neighbor scanning, RDAP whois, and company identification. Every report is manually reviewed by a USCYBERCOM operator.</p>
<p style="margin-top:2rem"><a href="/">Back to whobelooking.org</a></p>
</div></body></html>"#))
}

/// Use IntoResponse for flexibility
use axum::response::IntoResponse;
