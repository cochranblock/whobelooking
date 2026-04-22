// All Rights Reserved — The Cochran Block, LLC
//! Stripe Checkout — create session, redirect, handle success.

use axum::extract::Query;
use axum::response::{Html, IntoResponse, Redirect};
use axum::Form;
use serde::Deserialize;
use crate::web::admin;
use whobelooking::queue_types::Tier;

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
    pub id: Option<String>,
}

fn parse_tier(s: &str) -> Tier {
    match s {
        "starter" => Tier::Starter,
        "growth" => Tier::Growth,
        "scale" => Tier::Scale,
        "custom" => Tier::Custom,
        _ => Tier::Starter,
    }
}

pub async fn create_checkout(Form(form): Form<OrderForm>) -> axum::response::Response {
    // Check capacity first
    if !admin::has_capacity() {
        return Redirect::to("/order?error=capacity").into_response();
    }

    let tier = parse_tier(&form.tier);
    let id = uuid::Uuid::new_v4().to_string();

    let stripe_key = std::env::var("STRIPE_SECRET_KEY").unwrap_or_default();

    if stripe_key.is_empty() {
        // No Stripe — create order directly (dev mode)
        admin::create_order(&id, &form.email, &form.site_url, &form.source_type, &form.tier);
        return Redirect::to(&format!("/order/confirmed?id={}", id)).into_response();
    }

    // Create Stripe Checkout Session
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
        ("success_url", &format!("https://whobelooking.org/order/confirmed?session_id={{CHECKOUT_SESSION_ID}}&id={}", id)),
        ("cancel_url", "https://whobelooking.org/order?cancelled=1"),
        ("metadata[order_id]", &id),
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
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<serde_json::Value>().await {
                Ok(body) => {
                    if let Some(url) = body["url"].as_str() {
                        admin::create_order(&id, &form.email, &form.site_url, &form.source_type, &form.tier);
                        Redirect::to(url).into_response()
                    } else {
                        tracing::error!("stripe missing url: {:?}", body);
                        Redirect::to("/order?error=stripe").into_response()
                    }
                }
                Err(e) => {
                    tracing::error!("stripe parse: {}", e);
                    Redirect::to("/order?error=stripe").into_response()
                }
            }
        }
        Ok(resp) => {
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("stripe error: {}", body);
            Redirect::to("/order?error=stripe").into_response()
        }
        Err(e) => {
            tracing::error!("stripe request: {}", e);
            Redirect::to("/order?error=network").into_response()
        }
    }
}

pub async fn checkout_success(Query(q): Query<SuccessQuery>) -> Html<String> {
    let ref_id = q.id.or(q.session_id).unwrap_or_default();
    let short = if ref_id.len() > 12 { &ref_id[..12] } else { &ref_id };
    let pending = admin::pending_count();

    Html(format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Order Confirmed — whobelooking</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:'JetBrains Mono',monospace;background:#050508;color:#e8e8e8;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:2rem}}
.box{{max-width:500px;width:100%;text-align:center}}
h1{{font-family:'Orbitron',sans-serif;font-size:1.8rem;color:#00ffcc;margin-bottom:1.5rem}}
p{{margin-bottom:1rem;font-size:0.9rem;color:#9ca3af;line-height:1.6}}
.ref{{font-size:0.7rem;color:#00d9ff;background:rgba(0,217,255,0.08);padding:8px 16px;border:1px solid rgba(0,217,255,0.2);border-radius:4px;display:inline-block;margin:1rem 0}}
a{{color:#00d9ff;text-decoration:none}}
</style></head><body><div class="box">
<h1>You're in.</h1>
<div class="ref">{short}...</div>
<p>Your request is #{pending} in the queue. Michael will review it and follow up within 24 hours.</p>
<p>If approved, you'll receive a Stripe payment link and your report within 48 hours of payment.</p>
<p style="margin-top:2rem;font-size:0.8rem;color:#555">Every report is manually reviewed by a USCYBERCOM operator.</p>
<p style="margin-top:1.5rem"><a href="/">Back to whobelooking.org</a></p>
</div></body></html>"#,
        short = short,
        pending = pending,
    ))
}
