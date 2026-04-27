// All Rights Reserved — The Cochran Block, LLC
//! Admin — sled-backed atomic order queue.
//!
//! Order metadata + state transitions are handled by `crate::orders::Store`.
//! Blobs (uploaded logfiles, generated PDFs) live at
//! `~/.local/share/whobelooking/orders/blobs/{id}/`.
//!
//! State machine: `Pending → Approved → Ready` (with `Rejected` terminal at
//! any non-terminal state). Every transition is journaled to the `audit/`
//! tree so a restart can reconstruct the timeline.

use crate::orders::{MAX_PENDING, OrderState, Store};
use axum::extract::Query;
use axum::response::Html;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct AdminQuery {
    pub token: Option<String>,
}

fn check_token(q: &AdminQuery) -> bool {
    let expected = std::env::var("ADMIN_TOKEN").unwrap_or_else(|_| "changeme".into());
    q.token.as_deref() == Some(&expected)
}

fn store() -> Option<Store> {
    match Store::open() {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::error!("orders store unavailable: {}", e);
            None
        }
    }
}

pub fn pending_count() -> usize {
    store().map(|s| s.pending_count()).unwrap_or(0)
}

pub fn has_capacity() -> bool {
    pending_count() < MAX_PENDING
}

pub fn create_order(
    id: &str,
    email: &str,
    site_url: &str,
    source_type: &str,
    tier: &str,
    client_ip: &str,
) -> bool {
    let Some(s) = store() else {
        crate::web::metrics::ORDER_CREATES_REJECTED
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return false;
    };
    match s.create(id, email, site_url, source_type, tier, client_ip, "web") {
        Ok(_) => {
            crate::web::metrics::ORDER_CREATES_OK
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            true
        }
        Err(e) => {
            tracing::warn!("create_order({}) failed: {}", id, e);
            crate::web::metrics::ORDER_CREATES_REJECTED
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        }
    }
}

pub async fn dashboard(Query(q): Query<AdminQuery>) -> Html<String> {
    if !check_token(&q) {
        return Html("<h1 style='color:#ff6b35;font-family:monospace;background:#050508;height:100vh;display:flex;align-items:center;justify-content:center;margin:0'>unauthorized</h1>".into());
    }

    let mut rows = String::new();
    let store_opt = store();
    let pending = store_opt.as_ref().map(|s| s.pending_count()).unwrap_or(0);

    if let Some(s) = &store_opt {
        if let Ok(orders) = s.list_all() {
            for o in orders {
                let color = match o.state {
                    OrderState::Pending => "#00d9ff",
                    OrderState::Approved => "#00ffcc",
                    OrderState::Rejected => "#ff6b35",
                    OrderState::Ready => "#9d4edd",
                };
                let has_report = crate::orders::blobs_dir(&o.id).join("report.pdf").exists();
                let report_badge = if has_report {
                    "<span style='color:#00ffcc'>PDF</span>"
                } else {
                    ""
                };
                rows.push_str(&format!(
                    "<tr><td style='color:{color}'>{state}</td><td style='font-size:10px;color:#555'>{short_id}</td><td>{email}</td><td>{tier}</td><td>{report_badge}</td></tr>\n",
                    color = color,
                    state = o.state.name(),
                    short_id = &o.id[..o.id.len().min(8)],
                    email = o.email,
                    tier = o.tier,
                    report_badge = report_badge,
                ));
            }
        }
    }

    if rows.is_empty() {
        rows = "<tr><td colspan='5' style='color:#555;text-align:center;padding:2rem'>No orders</td></tr>".into();
    }

    Html(format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
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
Workflow (atomic, audited):<br>
List: <code>whobelooking order list</code><br>
Approve: <code>whobelooking order approve {{id}}</code><br>
Reject: <code>whobelooking order reject {{id}}</code><br>
Upload report: <code>cp report.pdf ~/.local/share/whobelooking/orders/blobs/{{id}}/report.pdf &amp;&amp; whobelooking order ready {{id}}</code><br>
History: <code>whobelooking order audit [id]</code>
</p>
</body></html>"#,
        pending = pending,
        max = MAX_PENDING,
        rows = rows,
    ))
}

// Operator data (visits, corpus) is no longer served over HTTP — see src/ipc.rs
// and the `whobelooking visits` / `whobelooking corpus` CLI subcommands which
// route over the local Unix socket. File-mode 0600 on the socket is the auth.
