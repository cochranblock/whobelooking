// All Rights Reserved — The Cochran Block, LLC
//! Job queue backed by sled. Capacity-limited. Manual review by default.

use serde::{Deserialize, Serialize};

const HOURS_PER_WEEK: f32 = 12.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    Paid,
    Pending,
    InProgress,
    Complete,
    Delivered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    Starter,
    Growth,
    Scale,
    Custom,
}

impl Tier {
    pub fn estimated_hours(&self) -> f32 {
        match self {
            Tier::Starter => 1.5,
            Tier::Growth => 3.0,
            Tier::Scale => 6.0,
            Tier::Custom => 8.0,
        }
    }

    pub fn price_cents(&self) -> u32 {
        match self {
            Tier::Starter => 15000,  // $150
            Tier::Growth => 35000,   // $350
            Tier::Scale => 75000,    // $750
            Tier::Custom => 150000,  // $1,500
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Tier::Starter => "Starter (<500 IPs)",
            Tier::Growth => "Growth (500-2K IPs)",
            Tier::Scale => "Scale (2K-10K IPs)",
            Tier::Custom => "Custom (10K+ IPs)",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SourceType {
    Cloudflare { zone: String, token: String },
    AccessLog,
    Csv,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub customer_email: String,
    pub source_type: SourceType,
    pub tier: Tier,
    pub status: JobStatus,
    pub estimated_hours: f32,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub report_path: Option<String>,
    pub notes: Option<String>,
}

fn open_db() -> sled::Db {
    let dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("whobelooking");
    sled::open(dir).expect("sled open")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
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

/// Create a new job in the queue.
pub fn create_job(email: &str, source_type: SourceType, tier: Tier) -> anyhow::Result<String> {
    let db = open_db();
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
    db.insert(format!("queue:job:{}", id).as_bytes(), compress(&data))?;

    // Increment week counter
    let week_key = format!("queue:week:{}", iso_week());
    let current: f32 = db
        .get(week_key.as_bytes())?
        .map(|v| {
            let s = String::from_utf8_lossy(&v);
            s.parse().unwrap_or(0.0)
        })
        .unwrap_or(0.0);
    db.insert(
        week_key.as_bytes(),
        format!("{}", current + tier.estimated_hours()).as_bytes(),
    )?;

    db.flush()?;
    Ok(id)
}

/// Get a job by ID.
pub fn get_job(id: &str) -> anyhow::Result<Option<Job>> {
    let db = open_db();
    match db.get(format!("queue:job:{}", id).as_bytes())? {
        Some(data) => {
            let raw = decompress(&data);
            Ok(Some(serde_json::from_slice(&raw)?))
        }
        None => Ok(None),
    }
}

/// List all jobs.
pub fn list_jobs() -> anyhow::Result<Vec<Job>> {
    let db = open_db();
    let mut jobs = Vec::new();
    for item in db.scan_prefix(b"queue:job:") {
        let (_, v) = item?;
        let raw = decompress(&v);
        if let Ok(job) = serde_json::from_slice::<Job>(&raw) {
            jobs.push(job);
        }
    }
    jobs.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(jobs)
}

/// Pop next pending job (oldest first).
pub fn pop_job() -> anyhow::Result<Option<Job>> {
    let db = open_db();
    let mut oldest: Option<Job> = None;
    for item in db.scan_prefix(b"queue:job:") {
        let (_, v) = item?;
        let raw = decompress(&v);
        if let Ok(job) = serde_json::from_slice::<Job>(&raw) {
            if job.status == JobStatus::Paid || job.status == JobStatus::Pending {
                if oldest.is_none() || job.created_at < oldest.as_ref().unwrap().created_at {
                    oldest = Some(job);
                }
            }
        }
    }
    if let Some(mut job) = oldest {
        job.status = JobStatus::InProgress;
        job.started_at = Some(now());
        let data = serde_json::to_vec(&job)?;
        db.insert(
            format!("queue:job:{}", job.id).as_bytes(),
            compress(&data),
        )?;
        db.flush()?;
        Ok(Some(job))
    } else {
        Ok(None)
    }
}

/// Mark job as complete.
pub fn complete_job(id: &str, report_path: Option<String>) -> anyhow::Result<()> {
    let db = open_db();
    let key = format!("queue:job:{}", id);
    match db.get(key.as_bytes())? {
        Some(data) => {
            let raw = decompress(&data);
            let mut job: Job = serde_json::from_slice(&raw)?;
            job.status = JobStatus::Complete;
            job.completed_at = Some(now());
            job.report_path = report_path;
            let data = serde_json::to_vec(&job)?;
            db.insert(key.as_bytes(), compress(&data))?;
            db.flush()?;
            Ok(())
        }
        None => anyhow::bail!("job not found: {}", id),
    }
}

/// Mark job as delivered.
pub fn deliver_job(id: &str) -> anyhow::Result<()> {
    let db = open_db();
    let key = format!("queue:job:{}", id);
    match db.get(key.as_bytes())? {
        Some(data) => {
            let raw = decompress(&data);
            let mut job: Job = serde_json::from_slice(&raw)?;
            job.status = JobStatus::Delivered;
            let data = serde_json::to_vec(&job)?;
            db.insert(key.as_bytes(), compress(&data))?;
            db.flush()?;
            Ok(())
        }
        None => anyhow::bail!("job not found: {}", id),
    }
}

/// Get hours committed this week.
pub fn hours_this_week() -> f32 {
    let db = open_db();
    let week_key = format!("queue:week:{}", iso_week());
    db.get(week_key.as_bytes())
        .ok()
        .flatten()
        .map(|v| {
            let s = String::from_utf8_lossy(&v);
            s.parse().unwrap_or(0.0)
        })
        .unwrap_or(0.0)
}

/// Check if capacity is available.
pub fn has_capacity(tier: &Tier) -> bool {
    hours_this_week() + tier.estimated_hours() <= HOURS_PER_WEEK
}

/// Enrichment cache stats.
pub fn enrichment_stats() -> (u64, u64) {
    let db = open_db();
    let mut ips = 0u64;
    let mut companies = 0u64;
    for item in db.scan_prefix(b"enrich:rdns:") {
        if item.is_ok() {
            ips += 1;
        }
    }
    for item in db.scan_prefix(b"enrich:company:") {
        if item.is_ok() {
            companies += 1;
        }
    }
    (ips, companies)
}
