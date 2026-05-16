// Unlicense — public domain — whobelooking.org
//! "Did it work?" feedback box on /scan. POSTs JSON {message, url?, scanned_url?},
//! emails the operator via Gmail SMTP (same env as cochranblock/ireducefraud).
//!
//! Env (inherited from cochranblock.env via watchdog-all.sh):
//!   SMTP_HOST = smtp.gmail.com (default)
//!   SMTP_PORT = 465 (default — implicit TLS)
//!   SMTP_USER = mcochran@cochranblock.org
//!   SMTP_PASS = <16-char gmail app password>
//!   FEEDBACK_NOTIFY_TO = mcochran@cochranblock.org (defaults to SMTP_USER)
//!
//! Spam guard: same per-IP rate-limit bucket as scan probes (7500/min) + max
//! 2KB message body. No auth — anyone can submit, that's the point.

use axum::{Json, http::HeaderMap, http::StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct FeedbackBody {
    pub message: String,
    #[serde(default)]
    pub scanned_url: String,
    #[serde(default)]
    pub email: String,
}

#[derive(Serialize)]
pub struct FeedbackResponse {
    ok: bool,
}

const MAX_LEN: usize = 2048;

pub async fn submit(
    headers: HeaderMap,
    Json(body): Json<FeedbackBody>,
) -> Result<Json<FeedbackResponse>, (StatusCode, &'static str)> {
    let ip = crate::web::visits::client_ip(&headers);

    let msg = body.message.trim();
    if msg.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "empty message"));
    }
    if msg.len() > MAX_LEN {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "message too long"));
    }

    // Fire on a blocking thread — lettre is sync. Don't block the request.
    let scanned_url = body.scanned_url.chars().take(256).collect::<String>();
    let email = body.email.chars().take(254).collect::<String>();
    let message = msg.to_string();
    let ip_for_log = ip.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = send_feedback(&message, &scanned_url, &email, &ip_for_log) {
            tracing::warn!("scan-feedback email failed: {}", e);
        } else {
            tracing::info!(
                "scan-feedback sent (ip={}, scanned={})",
                ip_for_log,
                scanned_url
            );
        }
    });

    Ok(Json(FeedbackResponse { ok: true }))
}

#[cfg(feature = "serve")]
fn send_feedback(message: &str, scanned_url: &str, email: &str, ip: &str) -> Result<(), String> {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};

    let host = std::env::var("SMTP_HOST").unwrap_or_else(|_| "smtp.gmail.com".into());
    let port: u16 = std::env::var("SMTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(465);
    let user = std::env::var("SMTP_USER").map_err(|_| "SMTP_USER unset".to_string())?;
    let pass = std::env::var("SMTP_PASS").map_err(|_| "SMTP_PASS unset".to_string())?;
    let to = std::env::var("FEEDBACK_NOTIFY_TO").unwrap_or_else(|_| user.clone());

    let scanned_label = if scanned_url.is_empty() {
        "(none)".to_string()
    } else {
        scanned_url.to_string()
    };
    let email_label = if email.is_empty() {
        "(anonymous)".to_string()
    } else {
        email.to_string()
    };

    let subject = format!(
        "[whobelooking/feedback] {}",
        message
            .lines()
            .next()
            .unwrap_or("(empty first line)")
            .chars()
            .take(70)
            .collect::<String>()
    );
    let body = format!(
        "Did-it-work feedback from whobelooking.cochranblock.org/scan\n\
         \n\
         From:        {}\n\
         IP:          {}\n\
         Scanned URL: {}\n\
         \n\
         ---\n\
         {}\n",
        email_label, ip, scanned_label, message
    );

    let from_mbox = format!("whobelooking feedback <{}>", user);
    let mut builder = Message::builder()
        .from(
            from_mbox
                .parse()
                .map_err(|e| format!("from parse: {}", e))?,
        )
        .to(to.parse().map_err(|e| format!("to parse: {}", e))?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN);

    // If user supplied an email, set Reply-To so a click-reply goes back to them.
    if !email.is_empty() && email.contains('@') {
        if let Ok(rt) = email.parse() {
            builder = builder.reply_to(rt);
        }
    }

    let msg = builder
        .body(body)
        .map_err(|e| format!("body build: {}", e))?;

    let creds = Credentials::new(user, pass);
    let mailer = SmtpTransport::relay(&host)
        .map_err(|e| format!("smtp relay: {}", e))?
        .port(port)
        .credentials(creds)
        .build();

    mailer.send(&msg).map_err(|e| format!("smtp send: {}", e))?;
    Ok(())
}
