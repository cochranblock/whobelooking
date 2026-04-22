// All Rights Reserved — The Cochran Block, LLC
//! Admin — filesystem-based queue. Orders are directories.
//! pending/ → approved/ or rejected/. You move them. That's it.

use axum::extract::Query;
use axum::response::Html;
use serde::Deserialize;

const MAX_PENDING: usize = 5;

#[derive(Deserialize)]
pub struct AdminQuery {
    pub token: Option<String>,
}

fn check_token(q: &AdminQuery) -> bool {
    let expected = std::env::var("ADMIN_TOKEN").unwrap_or_else(|_| "changeme".into());
    q.token.as_deref() == Some(&expected)
}

fn orders_dir() -> std::path::PathBuf {
    let dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("whobelooking")
        .join("orders");
    let _ = std::fs::create_dir_all(dir.join("pending"));
    let _ = std::fs::create_dir_all(dir.join("approved"));
    let _ = std::fs::create_dir_all(dir.join("rejected"));
    let _ = std::fs::create_dir_all(dir.join("ready"));
    dir
}

pub fn pending_count() -> usize {
    let dir = orders_dir().join("pending");
    std::fs::read_dir(dir)
        .map(|r| r.filter(|e| e.as_ref().map(|e| e.path().is_dir()).unwrap_or(false)).count())
        .unwrap_or(0)
}

pub fn has_capacity() -> bool {
    pending_count() < MAX_PENDING
}

pub fn create_order(id: &str, email: &str, site_url: &str, source_type: &str, tier: &str) -> bool {
    if !has_capacity() {
        return false;
    }
    let dir = orders_dir().join("pending").join(id);
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let content = format!(
        "id: {}\nemail: {}\nsite: {}\nsource: {}\ntier: {}\ncreated: {}\n",
        id, email, site_url, source_type, tier,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    std::fs::write(dir.join("order.txt"), content).is_ok()
}

pub async fn dashboard(Query(q): Query<AdminQuery>) -> Html<String> {
    if !check_token(&q) {
        return Html("<h1 style='color:#ff6b35;font-family:monospace;background:#050508;height:100vh;display:flex;align-items:center;justify-content:center;margin:0'>unauthorized</h1>".into());
    }

    let base = orders_dir();
    let mut rows = String::new();

    for folder in ["pending", "approved", "rejected", "ready"] {
        let dir = base.join(folder);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    let id = entry.file_name().to_string_lossy().to_string();
                    let order_txt = std::fs::read_to_string(entry.path().join("order.txt")).unwrap_or_default();
                    let has_report = entry.path().join("report.pdf").exists();
                    let color = match folder {
                        "pending" => "#00d9ff",
                        "approved" => "#00ffcc",
                        "rejected" => "#ff6b35",
                        _ => "#555",
                    };
                    let email = order_txt.lines()
                        .find(|l| l.starts_with("email:"))
                        .map(|l| l.trim_start_matches("email:").trim())
                        .unwrap_or("?");
                    let tier = order_txt.lines()
                        .find(|l| l.starts_with("tier:"))
                        .map(|l| l.trim_start_matches("tier:").trim())
                        .unwrap_or("?");
                    let report_badge = if has_report { "<span style='color:#00ffcc'>PDF</span>" } else { "" };

                    rows.push_str(&format!(
                        "<tr><td style='color:{color}'>{folder}</td><td style='font-size:10px;color:#555'>{short_id}</td><td>{email}</td><td>{tier}</td><td>{report_badge}</td></tr>\n",
                        color = color,
                        folder = folder,
                        short_id = &id[..std::cmp::min(id.len(), 8)],
                        email = email,
                        tier = tier,
                        report_badge = report_badge,
                    ));
                }
            }
        }
    }

    if rows.is_empty() {
        rows = "<tr><td colspan='5' style='color:#555;text-align:center;padding:2rem'>No orders</td></tr>".into();
    }

    let pending = pending_count();

    Html(format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — whobelooking</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'JetBrains Mono',monospace;background:#050508;color:#e8e8e8;padding:2rem;font-size:13px}}
h1{{font-family:'Orbitron',sans-serif;font-size:1.4rem;color:#00d9ff;margin-bottom:0.5rem}}
.meta{{font-size:0.75rem;color:#9ca3af;margin-bottom:2rem}}
table{{width:100%;border-collapse:collapse}}
th{{background:#0d0d14;color:#00d9ff;padding:8px;text-align:left;font-size:9px;letter-spacing:0.1em;text-transform:uppercase;border-bottom:1px solid rgba(0,217,255,0.15)}}
td{{padding:8px;border-bottom:1px solid rgba(0,217,255,0.08);font-size:11px}}
code{{font-size:0.7rem;color:#9ca3af;background:#0d0d14;padding:2px 6px;border-radius:2px}}
</style></head><body>
<h1>Orders</h1>
<div class="meta">{pending} of {max} pending slots filled</div>
<table>
<tr><th>Status</th><th>ID</th><th>Email</th><th>Tier</th><th>Report</th></tr>
{rows}
</table>
<p style="margin-top:2rem;font-size:0.7rem;color:#555">
Workflow: <code>ls ~/.local/share/whobelooking/orders/pending/</code><br>
Approve: <code>mv pending/{{id}} approved/</code><br>
Reject: <code>mv pending/{{id}} rejected/</code><br>
Upload report: <code>cp report.pdf approved/{{id}}/report.pdf</code>
</p>
</body></html>"#,
        pending = pending,
        max = MAX_PENDING,
        rows = rows,
    ))
}

// Remove upload/done/deliver handlers — filesystem handles it
pub async fn mark_done() -> &'static str { "use filesystem" }
pub async fn mark_delivered() -> &'static str { "use filesystem" }
pub async fn upload_report() -> &'static str { "use filesystem" }
