//! Integration tests: single node, restart, three-node membership growth and leader failover.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use torngat_store::testnet::TestNet;
use torngat_store::{Key, Node, NodeId, Precondition, Prefix, Store, StoreError, default_config};

fn key(name: &str) -> Key {
    Key::new("compute", ["orgs", "acme", "instances", name]).unwrap()
}

async fn open(net: &TestNet, dir: &TempDir, id: NodeId) -> Store {
    let s = Store::open(dir.path(), id, default_config(), net.factory(id))
        .await
        .unwrap();
    net.register(id, s.raft().clone());
    s
}

async fn wait_leader(stores: &[&Store], exclude: Option<NodeId>) -> NodeId {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        for s in stores {
            if Some(s.id()) == exclude {
                continue;
            }
            if let Some(l) = s.raft().current_leader().await
                && Some(l) != exclude
                && s.raft().is_leader() == (l == s.id())
            {
                return l;
            }
        }
        assert!(Instant::now() < deadline, "no leader elected");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn members(ids: &[NodeId]) -> BTreeMap<NodeId, Node> {
    ids.iter().map(|i| (*i, Node::default())).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_node_crud_cas_list_watch() {
    let net = TestNet::default();
    let dir = TempDir::new().unwrap();
    let s = open(&net, &dir, 1).await;
    s.initialize(members(&[1])).await.unwrap();
    wait_leader(&[&s], None).await;

    let mut watch = s.watch(Prefix::new("compute", ["orgs", "acme"]).unwrap());

    // Create, and create again must fail.
    let r1 = s
        .put(key("a"), b"v1".to_vec(), Precondition::Absent)
        .await
        .unwrap();
    let err = s
        .put(key("a"), b"x".to_vec(), Precondition::Absent)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::PreconditionFailed { current: Some(r) } if r == r1));

    // Compare-and-swap: stale revision fails, current succeeds.
    let r2 = s
        .put(key("a"), b"v2".to_vec(), Precondition::Revision(r1))
        .await
        .unwrap();
    assert!(r2 > r1);
    assert!(matches!(
        s.put(key("a"), b"v3".to_vec(), Precondition::Revision(r1)).await,
        Err(StoreError::PreconditionFailed { current: Some(r) }) if r == r2
    ));
    let got = s.get(&key("a")).await.unwrap().unwrap();
    assert_eq!((got.revision, got.value.as_slice()), (r2, &b"v2"[..]));

    // Watch saw both writes, in order.
    let e1 = watch.next().await.unwrap();
    let e2 = watch.next().await.unwrap();
    assert_eq!((e1.revision, e2.revision), (r1, r2));

    // List respects whole-segment prefixes and pagination.
    s.put(key("b"), vec![], Precondition::None).await.unwrap();
    s.put(
        Key::new("compute", ["orgs", "acmex", "instances", "c"]).unwrap(),
        vec![],
        Precondition::None,
    )
    .await
    .unwrap();
    let p = Prefix::new("compute", ["orgs", "acme"]).unwrap();
    let all = s.list(&p, None, 100).await.unwrap();
    assert_eq!(
        all.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        vec![key("a"), key("b")]
    );
    let page2 = s.list(&p, Some(&key("a")), 100).await.unwrap();
    assert_eq!(page2.len(), 1);
    assert!(s.list(&p, None, 0).await.unwrap().is_empty());
    // A sibling whose name extends the prefix with '-' sorts inside the scan range; it must not leak.
    s.put(
        Key::new("compute", ["orgs", "acme-x", "instances", "z"]).unwrap(),
        vec![],
        Precondition::None,
    )
    .await
    .unwrap();
    assert_eq!(s.list(&p, None, 100).await.unwrap().len(), 2);

    // Delete with a stale revision fails; with the current one succeeds; missing key is a no-op.
    assert!(
        s.delete(key("a"), Precondition::Revision(r1))
            .await
            .is_err()
    );
    s.delete(key("a"), Precondition::Revision(r2))
        .await
        .unwrap();
    assert!(s.get(&key("a")).await.unwrap().is_none());
    s.delete(key("a"), Precondition::None).await.unwrap();
    assert!(matches!(
        s.delete(key("a"), Precondition::Revision(r2)).await,
        Err(StoreError::PreconditionFailed { current: None })
    ));

    // Oversized values are refused before reaching Raft.
    assert!(matches!(
        s.put(
            key("big"),
            vec![0; torngat_store::MAX_VALUE_LEN + 1],
            Precondition::None
        )
        .await,
        Err(StoreError::ValueTooLarge)
    ));

    // Shutdown wakes watchers instead of leaving them blocked.
    let mut w = s.watch(Prefix::new("compute", []).unwrap());
    s.shutdown().await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(5), w.next()).await;
    assert!(matches!(r, Ok(Err(StoreError::Closed))), "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_survives_restart() {
    let dir = TempDir::new().unwrap();
    let rev = {
        let net = TestNet::default();
        let s = open(&net, &dir, 1).await;
        s.initialize(members(&[1])).await.unwrap();
        wait_leader(&[&s], None).await;
        let r = s
            .put(key("persist"), b"yes".to_vec(), Precondition::Absent)
            .await
            .unwrap();
        s.shutdown().await.unwrap();
        r
    };
    // The WAL lock is released by a background thread shortly after shutdown; a real restart
    // is a new process, so retry briefly instead of failing on the stale lock.
    let net = TestNet::default();
    let deadline = Instant::now() + Duration::from_secs(10);
    let s = loop {
        match Store::open(dir.path(), 1, default_config(), net.factory(1)).await {
            Ok(s) => break s,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("reopen failed: {e}"),
        }
    };
    net.register(1, s.raft().clone());
    wait_leader(&[&s], None).await;
    let v = s.get(&key("persist")).await.unwrap().unwrap();
    assert_eq!((v.revision, v.value.as_slice()), (rev, &b"yes"[..]));
    s.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grow_to_three_and_fail_over() {
    let net = TestNet::default();
    let dirs: Vec<TempDir> = (0..3).map(|_| TempDir::new().unwrap()).collect();
    let s1 = open(&net, &dirs[0], 1).await;
    let s2 = open(&net, &dirs[1], 2).await;
    let s3 = open(&net, &dirs[2], 3).await;
    let all = [&s1, &s2, &s3];

    // Start as a single node, as `init` will.
    s1.initialize(members(&[1])).await.unwrap();
    wait_leader(&[&s1], None).await;
    let r = s1
        .put(key("before-growth"), b"1".to_vec(), Precondition::Absent)
        .await
        .unwrap();

    // Grow 1 → 3 voters.
    for id in [2, 3] {
        s1.raft()
            .add_learner(id, Node::default(), true)
            .await
            .unwrap();
    }
    s1.raft()
        .change_membership([1u64, 2, 3], false)
        .await
        .unwrap();
    assert_eq!(s1.raft().voter_ids().count(), 3);

    // Kill (isolate) the leader; the other two elect a new one and keep accepting writes.
    let old = wait_leader(&all, None).await;
    net.isolate(old);
    let new = wait_leader(&all, Some(old)).await;
    assert_ne!(new, old);
    // Right after an election a node may still step down or hand over; retry like a client.
    let deadline = Instant::now() + Duration::from_secs(15);
    let (leader, r2) = loop {
        let id = wait_leader(&all, Some(old)).await;
        let l = all.iter().find(|s| s.id() == id).unwrap();
        match l
            .put(key("after-failover"), b"2".to_vec(), Precondition::None)
            .await
        {
            Ok(r) => break (l, r),
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("write after failover failed: {e}"),
        }
    };
    let _ = new;
    assert!(r2 > r);
    // Data written before the failover is still there.
    assert!(leader.get(&key("before-growth")).await.unwrap().is_some());

    // The isolated old leader cannot serve linearizable reads.
    let isolated = all.iter().find(|s| s.id() == old).unwrap();
    let stale =
        tokio::time::timeout(Duration::from_secs(3), isolated.get(&key("after-failover"))).await;
    assert!(
        !matches!(stale, Ok(Ok(Some(_)))),
        "isolated node served a read it cannot know"
    );

    // Heal: the old leader catches up and follows.
    net.heal();
    isolated
        .raft()
        .wait(Some(Duration::from_secs(15)))
        .applied_index_at_least(Some(r2), "old leader catches up")
        .await
        .unwrap();
    for s in all {
        s.shutdown().await.unwrap();
    }
}

/// Write-budget smoke test (run with `--ignored`): how many writes/s a single fsyncing replica
/// sustains under concurrency, e.g. a boot storm creating many instances.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn write_budget_boot_storm() {
    let n: usize = std::env::var("STORM_WRITES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let net = TestNet::default();
    let dir = TempDir::new().unwrap();
    let s = open(&net, &dir, 1).await;
    s.initialize(members(&[1])).await.unwrap();
    wait_leader(&[&s], None).await;

    let value = vec![b'x'; 2048];
    let start = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    let per = n / 64;
    for t in 0..64 {
        let s = s.clone();
        let value = value.clone();
        tasks.spawn(async move {
            for i in 0..per {
                let k = Key::new("compute", ["storm", &format!("vm-{t}-{i}")]).unwrap();
                s.put(k, value.clone(), Precondition::Absent).await.unwrap();
            }
        });
    }
    while let Some(r) = tasks.join_next().await {
        r.unwrap();
    }
    let secs = start.elapsed().as_secs_f64();
    println!(
        "{} writes in {secs:.2}s = {:.0} writes/s",
        per * 64,
        (per * 64) as f64 / secs
    );
    s.shutdown().await.unwrap();
}

/// A follower that catches up through a snapshot must tell its watchers to re-list.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn snapshot_install_resets_watchers() {
    let net = TestNet::default();
    let dirs: Vec<TempDir> = (0..3).map(|_| TempDir::new().unwrap()).collect();
    let mut stores = Vec::new();
    for (i, d) in dirs.iter().enumerate() {
        let id = i as NodeId + 1;
        let cfg = torngat_store::default_config();
        let cfg = openraft::Config {
            max_in_snapshot_log_to_keep: 0,
            ..cfg
        };
        let s = Store::open(d.path(), id, cfg, net.factory(id))
            .await
            .unwrap();
        net.register(id, s.raft().clone());
        stores.push(s);
    }
    stores[0].initialize(members(&[1, 2, 3])).await.unwrap();
    let leader_id = wait_leader(&stores.iter().collect::<Vec<_>>(), None).await;
    let leader = stores.iter().find(|s| s.id() == leader_id).unwrap();
    let follower = stores.iter().find(|s| s.id() != leader_id).unwrap();

    let mut w = follower.watch(Prefix::new("compute", []).unwrap());
    net.isolate(follower.id());
    let mut last = 0;
    for i in 0..50 {
        last = leader
            .put(
                Key::new("compute", ["snap", &format!("k{i}")]).unwrap(),
                vec![1],
                Precondition::None,
            )
            .await
            .unwrap();
    }
    // Compact the leader's log past what the isolated follower has.
    leader.raft().trigger().snapshot().await.unwrap();
    leader
        .raft()
        .wait(Some(Duration::from_secs(10)))
        .metrics(
            |m| m.snapshot.map(|l| l.index) >= Some(last),
            "snapshot built",
        )
        .await
        .unwrap();
    leader.raft().trigger().purge_log(last).await.unwrap();
    leader
        .raft()
        .wait(Some(Duration::from_secs(10)))
        .metrics(|m| m.purged.map(|l| l.index) >= Some(last), "log purged")
        .await
        .unwrap();
    net.heal();

    let r = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            match w.next().await {
                Ok(_) => continue,
                Err(e) => return e,
            }
        }
    })
    .await;
    assert!(matches!(r, Ok(StoreError::WatchLagged)), "{r:?}");
    for s in &stores {
        s.shutdown().await.unwrap();
    }
}
