// All Rights Reserved — The Cochran Block, LLC
//! Integration test: sled-backed order queue end-to-end.
//!
//! Stands up a real `Store` against a process-isolated tmpdir, drives the
//! full order lifecycle (create → approve → ready → audit), and asserts
//! the sled state matches expectations after each step. This is the
//! coverage gap the SEAL Team 6 audit flagged — every prior test was a
//! pure-function unit test.

use std::path::PathBuf;
use whobelooking::orders::{Error, OrderState, Store};

/// Each test gets its own tmpdir + sled DB. No env-var fiddling, no shared
/// state, fully parallel-safe.
fn fresh_store() -> (Store, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "wbl-it-orders-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let db_path = dir.join("orders.db");
    let store = Store::open_at(&db_path).expect("store open");
    (store, db_path)
}

#[test]
fn full_lifecycle_pending_to_ready() {
    let (s, db_path) = fresh_store();
    let id = "it-lifecycle-001";
    let o = s
        .create(
            id,
            "buyer@co.com",
            "https://co.com",
            "csv",
            "growth",
            "1.2.3.4",
            "web",
        )
        .expect("create");
    assert_eq!(o.state, OrderState::Pending);
    assert_eq!(o.tier, "growth");

    let approved = s
        .transition(id, OrderState::Approved, "operator-mc", None)
        .expect("approve");
    assert_eq!(approved.state, OrderState::Approved);

    let ready = s
        .transition(
            id,
            OrderState::Ready,
            "operator-mc",
            Some("uploaded report".into()),
        )
        .expect("ready");
    assert_eq!(ready.state, OrderState::Ready);

    let history = s.audit_for(id).expect("audit");
    assert_eq!(
        history.len(),
        3,
        "audit should record create + 2 transitions"
    );
    assert_eq!(history[0].to, OrderState::Pending);
    assert_eq!(history[0].actor, "web");
    assert_eq!(history[1].to, OrderState::Approved);
    assert_eq!(history[1].actor, "operator-mc");
    assert_eq!(history[2].to, OrderState::Ready);
    assert_eq!(history[2].note.as_deref(), Some("uploaded report"));

    // Persistence check: re-open the same DB and the order is still there.
    drop(s);
    let s2 = Store::open_at(&db_path).expect("reopen");
    let again = s2.get(id).expect("get").expect("found");
    assert_eq!(again.state, OrderState::Ready);
    assert_eq!(s2.audit_for(id).expect("audit").len(), 3);
}

#[test]
fn rejection_at_any_state_is_terminal() {
    let (s, _) = fresh_store();
    s.create(
        "it-reject-pending",
        "a@b",
        "site",
        "csv",
        "starter",
        "1.2.3.4",
        "web",
    )
    .unwrap();
    let r1 = s
        .transition("it-reject-pending", OrderState::Rejected, "op", None)
        .unwrap();
    assert_eq!(r1.state, OrderState::Rejected);
    // Rejected → anything else must fail.
    let err = s
        .transition("it-reject-pending", OrderState::Approved, "op", None)
        .unwrap_err();
    assert!(matches!(err, Error::IllegalTransition(_, _)));
}

#[test]
fn pending_capacity_holds() {
    let (s, _) = fresh_store();
    for i in 0..whobelooking::orders::MAX_PENDING {
        s.create(
            &format!("it-cap-{}", i),
            "a@b",
            "site",
            "csv",
            "starter",
            "1.2.3.4",
            "web",
        )
        .unwrap();
    }
    let err = s
        .create(
            "it-cap-overflow",
            "a@b",
            "site",
            "csv",
            "starter",
            "1.2.3.4",
            "web",
        )
        .unwrap_err();
    assert!(matches!(err, Error::AtCapacity(_)));

    // Approve one and capacity opens up immediately.
    s.transition("it-cap-0", OrderState::Approved, "op", None)
        .unwrap();
    assert!(
        s.create(
            "it-cap-after-approve",
            "a@b",
            "site",
            "csv",
            "starter",
            "1.2.3.4",
            "web"
        )
        .is_ok(),
        "approving an order should free a pending slot"
    );
}

#[test]
fn list_by_state_filters_correctly() {
    let (s, _) = fresh_store();
    for i in 0..3 {
        s.create(
            &format!("it-filter-{}", i),
            "a@b",
            "site",
            "csv",
            "starter",
            "1.2.3.4",
            "web",
        )
        .unwrap();
    }
    s.transition("it-filter-0", OrderState::Approved, "op", None)
        .unwrap();
    s.transition("it-filter-1", OrderState::Rejected, "op", None)
        .unwrap();

    let pending = s.list_by_state(OrderState::Pending).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, "it-filter-2");

    let approved = s.list_by_state(OrderState::Approved).unwrap();
    assert_eq!(approved.len(), 1);
    assert_eq!(approved[0].id, "it-filter-0");

    let rejected = s.list_by_state(OrderState::Rejected).unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].id, "it-filter-1");
}
