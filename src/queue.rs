// All Rights Reserved — The Cochran Block, LLC
//! Job queue backed by redb. Capacity-limited. Manual review by default.

pub use whobelooking::queue_types::*;

use redb::{Database, TableDefinition};

const QUEUE_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("queue");

fn open_db() -> anyhow::Result<Database> {
    let dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("whobelooking");
    let _ = std::fs::create_dir_all(&dir);
    Database::create(dir.join("queue.redb")).map_err(|e| anyhow::anyhow!("redb open: {}", e))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn iso_week() -> String {
    let secs = now();
    let days = secs / 86400;
    let week = days / 7;
    format!("{}", week)
}

fn compress(data: &[u8]) -> Vec<u8> {
    zstd::encode_all(data, 3).unwrap_or_else(|_| data.to_vec())
}

fn decompress(data: &[u8]) -> Vec<u8> {
    zstd::decode_all(data).unwrap_or_else(|_| data.to_vec())
}

fn db_get(db: &Database, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    let read_txn = db.begin_read()?;
    let table = match read_txn.open_table(QUEUE_TABLE) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(table.get(key)?.map(|g| g.value().to_vec()))
}

fn db_insert(db: &Database, key: &[u8], val: &[u8]) -> anyhow::Result<()> {
    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(QUEUE_TABLE)?;
        table.insert(key, val)?;
    }
    write_txn.commit()?;
    Ok(())
}

/// Create a new job in the queue. Reserved for Phase 2 redb-backed persistence.
#[allow(dead_code)] // Phase 2: filesystem orders migrate to redb
pub fn create_job(email: &str, source_type: SourceType, tier: Tier) -> anyhow::Result<String> {
    let db = open_db()?;
    let id = uuid::Uuid::new_v4().to_string();
    let job = Job {
        id: id.clone(),
        customer_email: email.to_string(),
        source_type,
        tier,
        status: JobStatus::Paid,
        estimated_hours: tier.estimated_hours(),
        created_at: now(),
        started_at: None,
        completed_at: None,
        report_path: None,
        notes: None,
    };
    let data = serde_json::to_vec(&job)?;
    db_insert(
        &db,
        format!("queue:job:{}", id).as_bytes(),
        &compress(&data),
    )?;

    let week_key = format!("queue:week:{}", iso_week());
    let current: f32 = db_get(&db, week_key.as_bytes())?
        .map(|v| {
            let s = String::from_utf8_lossy(&v);
            s.parse().unwrap_or(0.0)
        })
        .unwrap_or(0.0);
    db_insert(
        &db,
        week_key.as_bytes(),
        format!("{}", current + tier.estimated_hours()).as_bytes(),
    )?;
    Ok(id)
}

/// Get a job by ID.
#[cfg(feature = "serve")]
pub fn get_job(id: &str) -> anyhow::Result<Option<Job>> {
    let db = open_db()?;
    match db_get(&db, format!("queue:job:{}", id).as_bytes())? {
        Some(data) => {
            let raw = decompress(&data);
            Ok(Some(serde_json::from_slice(&raw)?))
        }
        None => Ok(None),
    }
}

fn scan_prefix(db: &Database, prefix: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    let read_txn = db.begin_read()?;
    let table = match read_txn.open_table(QUEUE_TABLE) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for entry in table.range(prefix..)? {
        let (k, v) = entry?;
        if !k.value().starts_with(prefix) {
            break;
        }
        out.push(v.value().to_vec());
    }
    Ok(out)
}

/// List all jobs.
pub fn list_jobs() -> anyhow::Result<Vec<Job>> {
    let db = open_db()?;
    let mut jobs = Vec::new();
    for data in scan_prefix(&db, b"queue:job:")? {
        let raw = decompress(&data);
        if let Ok(job) = serde_json::from_slice::<Job>(&raw) {
            jobs.push(job);
        }
    }
    jobs.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(jobs)
}

/// Pop next pending job (oldest first).
pub fn pop_job() -> anyhow::Result<Option<Job>> {
    let db = open_db()?;
    let mut oldest: Option<Job> = None;
    for data in scan_prefix(&db, b"queue:job:")? {
        let raw = decompress(&data);
        if let Ok(job) = serde_json::from_slice::<Job>(&raw) {
            if (job.status == JobStatus::Paid || job.status == JobStatus::Pending)
                && oldest
                    .as_ref()
                    .is_none_or(|o| job.created_at < o.created_at)
            {
                oldest = Some(job);
            }
        }
    }
    if let Some(mut job) = oldest {
        job.status = JobStatus::InProgress;
        job.started_at = Some(now());
        let data = serde_json::to_vec(&job)?;
        db_insert(
            &db,
            format!("queue:job:{}", job.id).as_bytes(),
            &compress(&data),
        )?;
        Ok(Some(job))
    } else {
        Ok(None)
    }
}

/// Mark job as complete.
pub fn complete_job(id: &str, report_path: Option<String>) -> anyhow::Result<()> {
    let db = open_db()?;
    let key = format!("queue:job:{}", id);
    match db_get(&db, key.as_bytes())? {
        Some(data) => {
            let raw = decompress(&data);
            let mut job: Job = serde_json::from_slice(&raw)?;
            job.status = JobStatus::Complete;
            job.completed_at = Some(now());
            job.report_path = report_path;
            let data = serde_json::to_vec(&job)?;
            db_insert(&db, key.as_bytes(), &compress(&data))?;
            Ok(())
        }
        None => anyhow::bail!("job not found: {}", id),
    }
}

/// Mark job as delivered.
pub fn deliver_job(id: &str) -> anyhow::Result<()> {
    let db = open_db()?;
    let key = format!("queue:job:{}", id);
    match db_get(&db, key.as_bytes())? {
        Some(data) => {
            let raw = decompress(&data);
            let mut job: Job = serde_json::from_slice(&raw)?;
            job.status = JobStatus::Delivered;
            let data = serde_json::to_vec(&job)?;
            db_insert(&db, key.as_bytes(), &compress(&data))?;
            Ok(())
        }
        None => anyhow::bail!("job not found: {}", id),
    }
}

/// Get hours committed this week.
pub fn hours_this_week() -> f32 {
    let Ok(db) = open_db() else {
        return 0.0;
    };
    let week_key = format!("queue:week:{}", iso_week());
    db_get(&db, week_key.as_bytes())
        .ok()
        .flatten()
        .map(|v| {
            let s = String::from_utf8_lossy(&v);
            s.parse().unwrap_or(0.0)
        })
        .unwrap_or(0.0)
}

/// Enrichment cache stats. Returns `(0, 0)` if the DB can't be opened.
#[cfg(feature = "serve")]
pub fn enrichment_stats() -> (u64, u64) {
    let Ok(db) = open_db() else {
        return (0, 0);
    };
    let ips = scan_prefix(&db, b"enrich:rdns:")
        .map(|v| v.len() as u64)
        .unwrap_or(0);
    let companies = scan_prefix(&db, b"enrich:company:")
        .map(|v| v.len() as u64)
        .unwrap_or(0);
    (ips, companies)
}
