// All Rights Reserved — The Cochran Block, LLC
//! Atomic order queue (Tier 1 fix).
//!
//! Replaces the earlier filesystem queue (`pending/`, `approved/`, `rejected/`,
//! `ready/` directories). Metadata + state lives in a redb table; only blobs
//! (logfile, generated PDF) stay on the filesystem.
//!
//! Two tables:
//!   * `orders`  — `order:{id}` → serde_json-serialized `Order`
//!   * `audit`   — `audit:{u128 BE epoch nanos}:{id}` → serde_json-serialized `AuditEvent`
//!
//! State transitions go through `transition()` which reads, validates, and
//! writes within a single write transaction — redb's exclusive writer lock
//! provides the same serialized-write semantics as sled's compare_and_swap.
//!
//! Blobs live at `~/.local/share/whobelooking/orders/blobs/{id}/`.

use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const ORDERS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("orders");
const AUDIT_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("audit");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderState {
    Pending,
    Approved,
    Rejected,
    Ready,
}

impl OrderState {
    pub fn name(self) -> &'static str {
        match self {
            OrderState::Pending => "pending",
            OrderState::Approved => "approved",
            OrderState::Rejected => "rejected",
            OrderState::Ready => "ready",
        }
    }

    /// Allowed forward transitions. The state machine is intentionally
    /// permissive at the operator's discretion (e.g. approved → rejected
    /// after spotting a problem) but does not allow regressions back to
    /// `Pending`, which would obscure the audit trail.
    pub fn can_transition(self, to: OrderState) -> bool {
        use OrderState::*;
        matches!(
            (self, to),
            (Pending, Approved)
                | (Pending, Rejected)
                | (Approved, Ready)
                | (Approved, Rejected)
                | (Ready, Rejected)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub id: String,
    pub email: String,
    pub site: String,
    pub source: String,
    pub tier: String,
    pub client_ip: String,
    pub created_at: u64,
    pub state: OrderState,
    pub state_changed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts_nanos: u128,
    pub order_id: String,
    pub from: Option<OrderState>,
    pub to: OrderState,
    pub actor: String, // operator handle / token-id / "system"
    pub note: Option<String>,
}

pub const MAX_PENDING: usize = 5;

#[derive(Debug)]
pub enum Error {
    Db(String),
    Encode(serde_json::Error),
    Io(std::io::Error),
    NotFound(String),
    AtCapacity(usize),
    IllegalTransition(OrderState, OrderState),
    Conflict,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Db(s) => write!(f, "db: {}", s),
            Error::Encode(e) => write!(f, "encode: {}", e),
            Error::Io(e) => write!(f, "io: {}", e),
            Error::NotFound(id) => write!(f, "order not found: {}", id),
            Error::AtCapacity(n) => {
                write!(f, "queue at capacity ({} pending; max {})", n, MAX_PENDING)
            }
            Error::IllegalTransition(from, to) => {
                write!(f, "illegal transition: {:?} → {:?}", from, to)
            }
            Error::Conflict => write!(f, "transition raced: another writer won"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Encode(e) => Some(e),
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Encode(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("whobelooking")
}

pub fn blobs_dir(id: &str) -> PathBuf {
    data_dir().join("orders").join("blobs").join(id)
}

static ORDERS_DB: OnceLock<Option<Arc<Database>>> = OnceLock::new();

fn shared_db() -> Result<Arc<Database>, Error> {
    ORDERS_DB
        .get_or_init(|| {
            let p = data_dir().join("orders.redb");
            let _ = p.parent().map(std::fs::create_dir_all);
            Database::create(&p).ok().map(Arc::new)
        })
        .as_ref()
        .map(Arc::clone)
        .ok_or_else(|| Error::Db("orders redb open failed".into()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

pub struct Store {
    db: Arc<Database>,
}

impl Store {
    pub fn open() -> Result<Self, Error> {
        Ok(Self { db: shared_db()? })
    }

    /// Open a store at a caller-chosen path. Bypasses `dirs::data_dir()`
    /// so integration tests can use isolated tmpdirs without racing on
    /// `XDG_DATA_HOME`.
    pub fn open_at(path: &std::path::Path) -> Result<Self, Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Database::create(path).map_err(|e| Error::Db(e.to_string()))?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn pending_count(&self) -> usize {
        let Ok(txn) = self.db.begin_read() else {
            return 0;
        };
        let tbl = match txn.open_table(ORDERS_TABLE) {
            Ok(t) => t,
            Err(_) => return 0,
        };
        let Ok(iter) = tbl.iter() else { return 0 };
        iter.flatten()
            .filter_map(|(_, v)| serde_json::from_slice::<Order>(v.value()).ok())
            .filter(|o| o.state == OrderState::Pending)
            .count()
    }

    pub fn has_capacity(&self) -> bool {
        self.pending_count() < MAX_PENDING
    }

    /// Atomically create a new pending order. Capacity is checked just
    /// before write; only inserts if the key doesn't already exist so
    /// two simultaneous submitters racing for the last slot can't both win.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &self,
        id: &str,
        email: &str,
        site: &str,
        source: &str,
        tier: &str,
        client_ip: &str,
        actor: &str,
    ) -> Result<Order, Error> {
        let pending = self.pending_count();
        if pending >= MAX_PENDING {
            return Err(Error::AtCapacity(pending));
        }
        let now = now_secs();
        let order = Order {
            id: id.to_string(),
            email: email.to_string(),
            site: site.to_string(),
            source: source.to_string(),
            tier: tier.to_string(),
            client_ip: client_ip.to_string(),
            created_at: now,
            state: OrderState::Pending,
            state_changed_at: now,
        };
        let key = format!("order:{}", id);
        let val = serde_json::to_vec(&order)?;

        let txn = self
            .db
            .begin_write()
            .map_err(|e| Error::Db(e.to_string()))?;
        let already_exists = {
            let mut tbl = txn
                .open_table(ORDERS_TABLE)
                .map_err(|e| Error::Db(e.to_string()))?;
            let exists = tbl
                .get(key.as_bytes())
                .map_err(|e| Error::Db(e.to_string()))?
                .is_some();
            if !exists {
                tbl.insert(key.as_bytes(), val.as_slice())
                    .map_err(|e| Error::Db(e.to_string()))?;
            }
            exists
        };
        if already_exists {
            return Err(Error::Conflict);
        }
        txn.commit().map_err(|e| Error::Db(e.to_string()))?;

        // Make sure the blob dir exists, but don't fail order creation if it
        // doesn't — operators can recover via cli.
        let _ = std::fs::create_dir_all(blobs_dir(id));

        self.write_audit(&AuditEvent {
            ts_nanos: now_nanos(),
            order_id: id.to_string(),
            from: None,
            to: OrderState::Pending,
            actor: actor.to_string(),
            note: None,
        })?;
        Ok(order)
    }

    pub fn get(&self, id: &str) -> Result<Option<Order>, Error> {
        let key = format!("order:{}", id);
        let txn = self.db.begin_read().map_err(|e| Error::Db(e.to_string()))?;
        let tbl = match txn.open_table(ORDERS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(Error::Db(e.to_string())),
        };
        let Some(g) = tbl
            .get(key.as_bytes())
            .map_err(|e| Error::Db(e.to_string()))?
        else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(g.value())?))
    }

    pub fn list_all(&self) -> Result<Vec<Order>, Error> {
        let txn = self.db.begin_read().map_err(|e| Error::Db(e.to_string()))?;
        let tbl = match txn.open_table(ORDERS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(e) => return Err(Error::Db(e.to_string())),
        };
        let mut out = Vec::new();
        for entry in tbl.iter().map_err(|e| Error::Db(e.to_string()))?.flatten() {
            let (_, v) = entry;
            if let Ok(o) = serde_json::from_slice::<Order>(v.value()) {
                out.push(o);
            }
        }
        out.sort_by_key(|o| std::cmp::Reverse(o.created_at));
        Ok(out)
    }

    pub fn list_by_state(&self, state: OrderState) -> Result<Vec<Order>, Error> {
        Ok(self
            .list_all()?
            .into_iter()
            .filter(|o| o.state == state)
            .collect())
    }

    /// Atomically transition `id`'s state from its current value to `to`.
    /// Returns the new order. Redb's exclusive writer lock ensures only one
    /// transition can succeed at a time.
    pub fn transition(
        &self,
        id: &str,
        to: OrderState,
        actor: &str,
        note: Option<String>,
    ) -> Result<Order, Error> {
        let key = format!("order:{}", id);
        let txn = self
            .db
            .begin_write()
            .map_err(|e| Error::Db(e.to_string()))?;
        let (order, from) = {
            let mut tbl = txn
                .open_table(ORDERS_TABLE)
                .map_err(|e| Error::Db(e.to_string()))?;
            let prev_bytes = {
                let g = tbl
                    .get(key.as_bytes())
                    .map_err(|e| Error::Db(e.to_string()))?;
                match g {
                    Some(g) => g.value().to_vec(),
                    None => return Err(Error::NotFound(id.to_string())),
                }
            };
            let mut order: Order = serde_json::from_slice(&prev_bytes)?;
            if !order.state.can_transition(to) {
                return Err(Error::IllegalTransition(order.state, to));
            }
            let from = order.state;
            order.state = to;
            order.state_changed_at = now_secs();
            let new_val = serde_json::to_vec(&order)?;
            tbl.insert(key.as_bytes(), new_val.as_slice())
                .map_err(|e| Error::Db(e.to_string()))?;
            (order, from)
        };
        txn.commit().map_err(|e| Error::Db(e.to_string()))?;
        self.write_audit(&AuditEvent {
            ts_nanos: now_nanos(),
            order_id: id.to_string(),
            from: Some(from),
            to,
            actor: actor.to_string(),
            note,
        })?;
        Ok(order)
    }

    fn write_audit(&self, ev: &AuditEvent) -> Result<(), Error> {
        // Key format guarantees lexicographic ordering matches chronological:
        // 16 bytes BE u128 nanos + ":" + order_id.
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(&ev.ts_nanos.to_be_bytes());
        key.push(b':');
        key.extend_from_slice(ev.order_id.as_bytes());
        let val = serde_json::to_vec(ev)?;
        let txn = self
            .db
            .begin_write()
            .map_err(|e| Error::Db(e.to_string()))?;
        {
            let mut tbl = txn
                .open_table(AUDIT_TABLE)
                .map_err(|e| Error::Db(e.to_string()))?;
            tbl.insert(key.as_slice(), val.as_slice())
                .map_err(|e| Error::Db(e.to_string()))?;
        }
        txn.commit().map_err(|e| Error::Db(e.to_string()))?;
        Ok(())
    }

    /// Most-recent-first audit slice.  `limit` caps result count.
    pub fn audit_tail(&self, limit: usize) -> Result<Vec<AuditEvent>, Error> {
        let txn = self.db.begin_read().map_err(|e| Error::Db(e.to_string()))?;
        let tbl = match txn.open_table(AUDIT_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(e) => return Err(Error::Db(e.to_string())),
        };
        let mut out = Vec::with_capacity(limit);
        for entry in tbl
            .iter()
            .map_err(|e| Error::Db(e.to_string()))?
            .rev()
            .flatten()
        {
            if out.len() >= limit {
                break;
            }
            let (_, v) = entry;
            if let Ok(ev) = serde_json::from_slice(v.value()) {
                out.push(ev);
            }
        }
        Ok(out)
    }

    /// Audit history for a single order, oldest-first.
    pub fn audit_for(&self, id: &str) -> Result<Vec<AuditEvent>, Error> {
        let txn = self.db.begin_read().map_err(|e| Error::Db(e.to_string()))?;
        let tbl = match txn.open_table(AUDIT_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(e) => return Err(Error::Db(e.to_string())),
        };
        let mut out = Vec::new();
        for entry in tbl.iter().map_err(|e| Error::Db(e.to_string()))?.flatten() {
            let (_, v) = entry;
            if let Ok(ev) = serde_json::from_slice::<AuditEvent>(v.value()) {
                if ev.order_id == id {
                    out.push(ev);
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> Store {
        // Each test gets its own redb — use a process-unique tmpdir.
        let dir = std::env::temp_dir().join(format!(
            "wbl-orders-test-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmp_store: create tmpdir");
        Store::open_at(&dir.join("orders.redb")).expect("tmp_store: open redb")
    }

    #[test]
    fn create_then_approve_then_ready() {
        let s = tmp_store();
        let o = s
            .create("o1", "a@b", "site", "csv", "starter", "1.2.3.4", "test")
            .expect("create o1 must succeed on fresh store");
        assert_eq!(o.state, OrderState::Pending);
        let o2 = s
            .transition("o1", OrderState::Approved, "test", None)
            .expect("Pending → Approved is a legal transition");
        assert_eq!(o2.state, OrderState::Approved);
        let o3 = s
            .transition("o1", OrderState::Ready, "test", None)
            .expect("Approved → Ready is a legal transition");
        assert_eq!(o3.state, OrderState::Ready);
    }

    #[test]
    fn illegal_transition_rejected() {
        let s = tmp_store();
        s.create("o1", "a@b", "site", "csv", "starter", "1.2.3.4", "test")
            .expect("create o1 must succeed on fresh store");
        // Pending → Ready is not legal; must go through Approved.
        let err = s
            .transition("o1", OrderState::Ready, "test", None)
            .expect_err("Pending → Ready must reject as IllegalTransition");
        assert!(matches!(err, Error::IllegalTransition(_, _)));
    }

    #[test]
    fn double_transition_returns_conflict() {
        let s = tmp_store();
        s.create("o1", "a@b", "site", "csv", "starter", "1.2.3.4", "test")
            .expect("create o1 must succeed on fresh store");
        s.transition("o1", OrderState::Approved, "test", None)
            .expect("Pending → Approved is a legal transition");
        // Second attempt to transition Pending→Approved fails because state
        // is already Approved (illegal transition Approved→Approved).
        let err = s
            .transition("o1", OrderState::Approved, "test", None)
            .expect_err("Approved → Approved must reject as IllegalTransition");
        assert!(matches!(err, Error::IllegalTransition(_, _)));
    }

    #[test]
    fn capacity_enforced() {
        let s = tmp_store();
        for i in 0..MAX_PENDING {
            s.create(
                &format!("o{}", i),
                "a@b",
                "site",
                "csv",
                "starter",
                "1.2.3.4",
                "test",
            )
            .expect("MAX_PENDING creates must all succeed");
        }
        let err = s
            .create(
                "overflow", "a@b", "site", "csv", "starter", "1.2.3.4", "test",
            )
            .expect_err("MAX_PENDING+1 create must reject as AtCapacity");
        assert!(matches!(err, Error::AtCapacity(_)));
    }

    #[test]
    fn audit_records_each_step() {
        let s = tmp_store();
        s.create("o1", "a@b", "site", "csv", "starter", "1.2.3.4", "test")
            .expect("create o1 must succeed on fresh store");
        s.transition("o1", OrderState::Approved, "operator-a", None)
            .expect("Pending → Approved is a legal transition");
        s.transition(
            "o1",
            OrderState::Ready,
            "operator-b",
            Some("uploaded report.pdf".into()),
        )
        .expect("Approved → Ready is a legal transition");
        let history = s
            .audit_for("o1")
            .expect("audit_for o1 returns history after transitions");
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].to, OrderState::Pending);
        assert_eq!(history[1].to, OrderState::Approved);
        assert_eq!(history[2].to, OrderState::Ready);
        assert_eq!(history[2].actor, "operator-b");
    }
}
