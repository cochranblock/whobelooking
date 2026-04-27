// All Rights Reserved — The Cochran Block, LLC
//! IPC dispatcher — operator data over the Unix socket. No HTTP, no tokens.
//!
//! Op surface (versioned at v=1, see kova-ipc::PROTO_VERSION):
//!   "ping"               → "pong" + server pid + uptime hint
//!   "queue"              → list_jobs() output as JSON
//!   "visits"             → { days_ago: u64 } → list_for_date rows
//!   "corpus"             → { min_hits: u64, attack_only: bool } → [(path, hits), ...]
//!
//! Adding a new op = one match arm. No HTTP routing, no auth wiring.

use kova_ipc::{Reply, Request};
use serde::Deserialize;

const PROJECT: &str = "whobelooking";

pub fn socket_path() -> std::path::PathBuf {
    kova_ipc::default_socket_path(PROJECT)
}

/// Spawn the IPC listener as a background task on the running tokio runtime.
/// Called from inside Cmd::Serve, alongside the public Axum bind.
pub async fn spawn() -> anyhow::Result<()> {
    let path = socket_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let server = kova_ipc::Server::bind(&path)
        .await
        .map_err(|e| anyhow::anyhow!("ipc bind {}: {}", path.display(), e))?;
    tracing::info!("ipc listening at {}", server.path().display());
    tokio::spawn(server.serve(|req: Request| async move { dispatch(req).await }));
    Ok(())
}

async fn dispatch(req: Request) -> Reply {
    match req.op.as_str() {
        "ping" => Reply::ok(serde_json::json!({
            "pong": true,
            "pid": std::process::id(),
        })),
        "queue" => match crate::queue::list_jobs() {
            Ok(jobs) => Reply::ok(serde_json::to_value(&jobs).unwrap_or(serde_json::Value::Null)),
            Err(e) => Reply::error(format!("queue: {e}")),
        },
        "visits" => {
            #[derive(Deserialize)]
            struct Args {
                #[serde(default)]
                days_ago: u64,
            }
            let args: Args = match serde_json::from_value(req.args) {
                Ok(a) => a,
                Err(e) => return Reply::error(format!("bad args: {e}")),
            };
            let today = crate::web::visits::today();
            let d = today.saturating_sub(args.days_ago);
            let rows = crate::web::visits::list_for_date(d);
            Reply::ok(serde_json::json!({
                "date_days": d, "today_minus": args.days_ago,
                "rows": rows.iter().map(|(ip, path, count, first, last)| {
                    serde_json::json!({"ip":ip,"path":path,"count":count,"first":first,"last":last})
                }).collect::<Vec<_>>(),
            }))
        }
        "corpus" => {
            #[derive(Deserialize)]
            struct Args {
                #[serde(default = "one")]
                min_hits: u64,
                #[serde(default)]
                attack_only: bool,
            }
            fn one() -> u64 {
                1
            }
            let args: Args = match serde_json::from_value(req.args) {
                Ok(a) => a,
                Err(e) => return Reply::error(format!("bad args: {e}")),
            };
            let paths = crate::web::visits::corpus_paths(args.min_hits, args.attack_only);
            Reply::ok(serde_json::to_value(&paths).unwrap_or(serde_json::Value::Null))
        }
        other => Reply::error(format!("unknown op: {other}")),
    }
}

/// Convenience for CLI subcommands: run a request against the local socket.
/// Returns Err if the server isn't listening — caller decides whether to
/// fall through to direct DB access or to bail.
pub async fn call(op: &str, args: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let path = socket_path();
    let client = kova_ipc::Client::connect(&path)
        .await
        .map_err(|e| anyhow::anyhow!("connect {}: {}", path.display(), e))?;
    let val = client
        .call(op, args)
        .await
        .map_err(|e| anyhow::anyhow!("ipc call: {}", e))?;
    Ok(val)
}
