//! Seeded simulation of the replicated store under faults.
//!
//! Each seed builds a 3- or 5-voter cluster on a paused-time runtime, drives it with concurrent
//! clients (compare-and-swap counters and blind writes) while a nemesis partitions, isolates,
//! crashes and restarts nodes and injects message loss and delay, then heals and checks the
//! invariants listed on [`check`]. Upstream Raft is fuzzed elsewhere; this exercises our
//! integration: preconditions, revisions, state machine, snapshots, watches and restarts.
//!
//! Run `TORNGAT_SIM_SEEDS=N` for seeds `0..N` (default 8) or `TORNGAT_SIM_SEED=x` for one seed;
//! `TORNGAT_SIM_DETERMINISM=1` additionally runs the first selected seed twice and prints how
//! much of the schedule and history repeated. See docs/TESTING.md.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use openraft::async_runtime::WatchReceiver;
use openraft::{Config, SnapshotPolicy};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use torngat_store::testnet::{SplitMix64, TestNet};
use torngat_store::{Key, Node, NodeId, Precondition, Prefix, Store, StoreError};

/// Virtual time a client waits for a write or read before calling the outcome unknown.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(2);
/// Real-time bound on every wait for the cluster to settle; failure means a hang.
const SETTLE_LIMIT: Duration = Duration::from_secs(120);
/// Virtual time added to the clock per tick, and the real time one tick takes.
const TICK: Duration = Duration::from_millis(5);
const TICK_REAL: Duration = Duration::from_micros(500);
const COUNTERS: usize = 3;
const BLIND_KEYS: usize = 6;
const CLIENT_OPS: usize = 80;
const NEMESIS_STEPS: usize = 24;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

macro_rules! ensure {
    ($seed:expr, $cond:expr, $($arg:tt)+) => {
        if !$cond {
            panic!("sim seed {}: invariant violated: {}", $seed, format!($($arg)+));
        }
    };
}

fn key(name: &str) -> Key {
    Key::new("sim", [name]).unwrap()
}

fn counter_name(i: usize) -> String {
    format!("ctr-{i}")
}

fn blind_name(i: usize) -> String {
    format!("blind-{i}")
}

fn sim_config() -> Config {
    Config {
        cluster_name: "sim".into(),
        heartbeat_interval: 50,
        election_timeout_min: 200,
        election_timeout_max: 400,
        snapshot_policy: SnapshotPolicy::LogsSinceLast(20),
        max_in_snapshot_log_to_keep: 0,
        replication_lag_threshold: 30,
        ..Default::default()
    }
}

// ---------------------------------------------------------------- history

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Kind {
    /// CAS counter increment writing this new value.
    Incr(u64),
    Put(Vec<u8>),
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Outcome {
    /// Acknowledged at this revision.
    Acked(u64),
    /// Definitely not applied (precondition failed, or refused by a non-leader).
    Failed,
    /// May or may not have been applied (timeout, Raft error, shutdown).
    Unknown,
}

#[derive(Debug, Clone)]
struct Write {
    key: String,
    kind: Kind,
    /// Logical clock readings just before the call and just after it returned.
    invoke: u64,
    done: u64,
    outcome: Outcome,
}

#[derive(Debug, Clone)]
struct Read {
    key: String,
    invoke: u64,
    /// Revision and, for counters, value that the linearizable read returned.
    seen: Option<(u64, Vec<u8>)>,
}

#[derive(Debug, Default)]
struct History {
    writes: Vec<Write>,
    reads: Vec<Read>,
}

/// What a replica's watcher saw.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Event {
        revision: u64,
        key: String,
        value: Option<Vec<u8>>,
    },
    /// The stream restarted: lagged, snapshot installed, or the replica restarted.
    Reset,
}

type Nodes = Arc<Mutex<BTreeMap<NodeId, Option<Store>>>>;

// ---------------------------------------------------------------- cluster

struct Sim {
    voters: Vec<NodeId>,
    net: TestNet,
    nodes: Nodes,
    dirs: BTreeMap<NodeId, TempDir>,
    logs: BTreeMap<NodeId, Arc<Mutex<Vec<Item>>>>,
    watchers: Mutex<Vec<JoinHandle<()>>>,
    hist: Mutex<History>,
    /// Logical clock ordering invocations and completions across clients.
    clock: AtomicU64,
    schedule: Mutex<Vec<String>>,
    crashes: AtomicU64,
}

impl Sim {
    fn tick(&self) -> u64 {
        self.clock.fetch_add(1, Ordering::SeqCst)
    }

    fn store(&self, id: NodeId) -> Option<Store> {
        lock(&self.nodes).get(&id).cloned().flatten()
    }

    fn live(&self) -> Vec<Store> {
        lock(&self.nodes).values().flatten().cloned().collect()
    }

    /// Opens replica `id` in its directory, starts its watcher and makes it reachable.
    async fn start_node(&self, id: NodeId) {
        // The log's lock is released by a background thread shortly after shutdown, as it would
        // be by process exit; retry on the real clock instead of failing on the stale lock.
        let deadline = Instant::now() + Duration::from_secs(30);
        let store = loop {
            match Store::open(
                self.dirs[&id].path(),
                id,
                sim_config(),
                self.net.factory(id),
            )
            .await
            {
                Ok(s) => break s,
                Err(e) => {
                    assert!(Instant::now() < deadline, "reopen of node {id} failed: {e}");
                    std::thread::sleep(Duration::from_millis(5));
                    tokio::task::yield_now().await;
                }
            }
        };
        // Subscribe before the node is reachable so no applied entry can be missed.
        let mut watch = store.watch(Prefix::new("sim", []).unwrap());
        let log = self.logs[&id].clone();
        lock(&log).push(Item::Reset);
        let handle = tokio::spawn(async move {
            loop {
                let item = match watch.next().await {
                    Ok(e) => Item::Event {
                        revision: e.revision,
                        key: e.key.to_string(),
                        value: e.value.map(|v| v.as_ref().clone()),
                    },
                    Err(StoreError::WatchLagged) => Item::Reset,
                    Err(StoreError::Closed) => break,
                    Err(e) => panic!("watch: {e}"),
                };
                lock(&log).push(item);
            }
        });
        lock(&self.watchers).push(handle);
        self.net.register(id, store.raft().clone());
        lock(&self.nodes).insert(id, Some(store));
    }

    /// Graceful stop, pause, restart from the same directory.
    async fn crash_restart(&self, id: NodeId, down: Duration) {
        let Some(old) = lock(&self.nodes).insert(id, None).flatten() else {
            return;
        };
        self.net.unregister(id);
        // An already-stopped node reports an error; nothing else to do either way.
        let _ = old.shutdown().await;
        drop(old);
        tokio::time::sleep(down).await;
        self.start_node(id).await;
        self.crashes.fetch_add(1, Ordering::Relaxed);
    }

    async fn leader(&self) -> Option<NodeId> {
        for s in self.live() {
            if let Some(l) = s.raft().current_leader().await {
                return Some(l);
            }
        }
        None
    }

    fn note(&self, line: String) {
        lock(&self.schedule).push(line);
    }
}

/// Polls `cond` (virtual 20 ms apart) until it holds; panics after [`SETTLE_LIMIT`] real time.
async fn settle<F, Fut>(what: &str, seed: u64, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + SETTLE_LIMIT;
    while !cond().await {
        assert!(
            Instant::now() < deadline,
            "sim seed {seed}: timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Drives the paused clock at a fixed rate against real time.
///
/// Plain auto-advance is useless here: whenever the runtime idles waiting for a log fsync (done
/// by a thread tokio does not know about), the clock jumps to the next timer, so election
/// timeouts fire before any fsync returns and the cluster livelocks in elections. A blocking
/// task in flight inhibits auto-advance, so each tick waits in one and then advances the clock
/// by [`TICK`] by hand: virtual time runs a few times faster than real time, and a replica's
/// fsyncs cost a realistic number of virtual milliseconds.
async fn clock_driver(stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        tokio::task::spawn_blocking(|| std::thread::sleep(TICK_REAL))
            .await
            .unwrap();
        tokio::time::advance(TICK).await;
    }
}

// ---------------------------------------------------------------- clients

struct Client {
    id: u64,
    /// Routing and backoff choices; they depend on outcomes, so they get their own stream.
    rng: SplitMix64,
    /// What to do next. Never consumed by outcome-dependent code, so a seed fixes it.
    plan: SplitMix64,
    sim: Arc<Sim>,
    hint: NodeId,
    unique: u64,
    /// Operation intents, hashed to measure reproducibility.
    intents: Vec<String>,
}

impl Client {
    fn pick_node(&mut self) -> NodeId {
        if self.rng.below(10) == 0 {
            let n = self.sim.voters.len() as u64;
            self.sim.voters[self.rng.below(n) as usize]
        } else {
            self.hint
        }
    }

    fn random_node(&mut self) -> NodeId {
        let n = self.sim.voters.len() as u64;
        self.sim.voters[self.rng.below(n) as usize]
    }

    async fn backoff(&mut self) {
        let ms = 10 + self.rng.below(50);
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    /// One write attempt on the believed leader. `None` if the chosen node is down (nothing was
    /// sent). Failed attempts are recorded too.
    async fn write(
        &mut self,
        name: &str,
        kind: Kind,
        precondition: Precondition,
    ) -> Option<Outcome> {
        let node = self.pick_node();
        let Some(store) = self.sim.store(node) else {
            self.hint = self.random_node();
            return None;
        };
        let k = key(name);
        let invoke = self.sim.tick();
        let call = async {
            match &kind {
                Kind::Incr(v) => store.put(k, v.to_string().into_bytes(), precondition).await,
                Kind::Put(v) => store.put(k, v.clone(), precondition).await,
                Kind::Delete => store.delete(k, precondition).await,
            }
        };
        let result = tokio::time::timeout(CLIENT_TIMEOUT, call).await;
        let done = self.sim.tick();
        let outcome = match result {
            Ok(Ok(rev)) => Outcome::Acked(rev),
            Ok(Err(StoreError::PreconditionFailed { .. })) => Outcome::Failed,
            // A ForwardToLeader error is returned before anything is appended.
            Ok(Err(StoreError::NotLeader { leader })) => {
                self.hint = match leader {
                    Some(l) => l,
                    None => self.random_node(),
                };
                Outcome::Failed
            }
            Ok(Err(StoreError::ValueTooLarge)) => unreachable!("sim values are small"),
            Ok(Err(_)) | Err(_) => {
                self.hint = self.random_node();
                Outcome::Unknown
            }
        };
        lock(&self.sim.hist).writes.push(Write {
            key: name.to_owned(),
            kind,
            invoke,
            done,
            outcome,
        });
        Some(outcome)
    }

    /// Linearizable read on the believed leader, recorded. `None` if it did not succeed.
    async fn read(&mut self, name: &str) -> Option<Option<(u64, Vec<u8>)>> {
        let node = self.pick_node();
        let Some(store) = self.sim.store(node) else {
            self.hint = self.random_node();
            return None;
        };
        let invoke = self.sim.tick();
        let result = tokio::time::timeout(CLIENT_TIMEOUT, store.get(&key(name))).await;
        match result {
            Ok(Ok(v)) => {
                let seen = v.map(|v| (v.revision, v.value));
                lock(&self.sim.hist).reads.push(Read {
                    key: name.to_owned(),
                    invoke,
                    seen: seen.clone(),
                });
                Some(seen)
            }
            Ok(Err(StoreError::NotLeader { leader })) => {
                self.hint = match leader {
                    Some(l) => l,
                    None => self.random_node(),
                };
                None
            }
            _ => {
                self.hint = self.random_node();
                None
            }
        }
    }

    /// Reads the counter and writes value+1 conditioned on the revision read. Retries until the
    /// attempt is acknowledged or unknown (a client that does not know stops, as a real one
    /// would not blindly retry an increment).
    async fn increment(&mut self, idx: usize) {
        let name = counter_name(idx);
        for _ in 0..10 {
            let Some(seen) = self.read(&name).await else {
                self.backoff().await;
                continue;
            };
            let (current, precondition) = match seen {
                Some((rev, value)) => {
                    let text = String::from_utf8(value).expect("counter value is text");
                    (
                        text.parse::<u64>().expect("counter value is a number"),
                        Precondition::Revision(rev),
                    )
                }
                None => (0, Precondition::Absent),
            };
            match self
                .write(&name, Kind::Incr(current + 1), precondition)
                .await
            {
                Some(Outcome::Acked(_) | Outcome::Unknown) => return,
                _ => self.backoff().await,
            }
        }
    }

    async fn run(mut self) -> Vec<String> {
        for _ in 0..CLIENT_OPS {
            let roll = self.plan.below(10);
            let key_idx = self.plan.below(BLIND_KEYS as u64) as usize;
            let ctr_idx = self.plan.below(COUNTERS as u64) as usize;
            self.unique += 1;
            let value = format!("c{}-{}", self.id, self.unique).into_bytes();
            let name = blind_name(key_idx);
            match roll {
                0..=4 => {
                    self.intents.push(format!("incr {ctr_idx}"));
                    self.increment(ctr_idx).await;
                }
                5 | 6 => {
                    self.intents.push(format!("put {name} {roll}"));
                    self.write(&name, Kind::Put(value), Precondition::None)
                        .await;
                }
                7 => {
                    self.intents.push(format!("create {name}"));
                    self.write(&name, Kind::Put(value), Precondition::Absent)
                        .await;
                }
                8 => {
                    self.intents.push(format!("delete {name}"));
                    self.write(&name, Kind::Delete, Precondition::None).await;
                }
                _ => {
                    self.intents.push(format!("get {name}"));
                    self.read(&name).await;
                }
            }
            let think = 5 + self.plan.below(80);
            tokio::time::sleep(Duration::from_millis(think)).await;
        }
        self.intents
    }
}

// ---------------------------------------------------------------- nemesis

async fn nemesis(sim: Arc<Sim>, mut rng: SplitMix64) {
    let n = sim.voters.len() as u64;
    let mut cut_steps = 0;
    for step in 0..NEMESIS_STEPS {
        let pause = 200 + rng.below(300);
        tokio::time::sleep(Duration::from_millis(pause)).await;
        // Always draw the same number of values per step so the schedule depends on the seed only.
        let (roll, a, b, c) = (
            rng.below(100),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
        );
        let pick = |x: u64| sim.voters[(x % n) as usize];
        // Cuts never last more than a few steps: a majority must be able to talk eventually.
        let roll = if cut_steps >= 4 { 35 } else { roll };
        let line = match roll {
            0..=19 => {
                let target = if a % 2 == 0 {
                    sim.leader().await.unwrap_or_else(|| pick(b))
                } else {
                    pick(b)
                };
                sim.net.isolate(target);
                cut_steps += 1;
                format!("{step} isolate {target}")
            }
            20..=34 => {
                let mut order = sim.voters.clone();
                let mut r = SplitMix64::new(a);
                for i in (1..order.len()).rev() {
                    order.swap(i, r.below(i as u64 + 1) as usize);
                }
                let split = 1 + (b % (n - 1)) as usize;
                let (left, right) = order.split_at(split);
                sim.net.partition(&[left, right]);
                cut_steps += 1;
                format!("{step} partition {left:?} | {right:?}")
            }
            35..=49 => {
                sim.net.heal();
                cut_steps = 0;
                format!("{step} heal")
            }
            50..=64 => {
                let target = pick(a);
                let down = Duration::from_millis(100 + b % 900);
                sim.crash_restart(target, down).await;
                format!("{step} restart {target} down {}ms", down.as_millis())
            }
            65..=84 => {
                let drop = (a % 51) as u32;
                let delay = Duration::from_millis(b % 51);
                sim.net.set_faults(drop, delay, c);
                format!(
                    "{step} faults drop {drop}/1000 delay {}ms",
                    delay.as_millis()
                )
            }
            _ => format!("{step} nothing"),
        };
        sim.note(line);
    }
}

// ---------------------------------------------------------------- run + report

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Report {
    seed: u64,
    voters: usize,
    acked: usize,
    failed: usize,
    unknown: usize,
    reads: usize,
    schedule_hash: u64,
    intents_hash: u64,
    history_hash: u64,
    schedule: Vec<String>,
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

async fn run_seed(seed: u64) -> Report {
    let voters: Vec<NodeId> = (1..=if seed.is_multiple_of(2) { 3 } else { 5 }).collect();
    let virtual_start = tokio::time::Instant::now();
    let stop_clock = Arc::new(AtomicBool::new(false));
    let clock = tokio::spawn(clock_driver(stop_clock.clone()));
    let net = TestNet::default();
    let sim = Arc::new(Sim {
        voters: voters.clone(),
        net: net.clone(),
        nodes: Nodes::default(),
        dirs: voters
            .iter()
            .map(|v| (*v, TempDir::new().unwrap()))
            .collect(),
        logs: voters.iter().map(|v| (*v, Arc::default())).collect(),
        watchers: Mutex::default(),
        hist: Mutex::default(),
        clock: AtomicU64::new(1),
        schedule: Mutex::default(),
        crashes: AtomicU64::new(0),
    });
    for v in &voters {
        sim.start_node(*v).await;
    }
    sim.store(voters[0])
        .unwrap()
        .initialize(voters.iter().map(|v| (*v, Node::default())).collect())
        .await
        .unwrap();
    settle("initial leader", seed, || async {
        sim.leader().await.is_some()
    })
    .await;

    // Faults start only once the cluster has a leader; seeds fix everything after this point.
    let mut master = SplitMix64::new(seed);
    let mut seeded = || master.next_u64();
    let nemesis_seed = seeded();
    let client_count = 2 + (seeded() % 3);
    let client_seeds: Vec<u64> = (0..client_count).map(|_| seeded()).collect();

    let nemesis_task = tokio::spawn(nemesis(sim.clone(), SplitMix64::new(nemesis_seed)));
    let client_tasks: Vec<JoinHandle<Vec<String>>> = client_seeds
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mut rng = SplitMix64::new(*s);
            let hint = voters[rng.below(voters.len() as u64) as usize];
            tokio::spawn(
                Client {
                    id: i as u64,
                    rng,
                    plan: SplitMix64::new(*s ^ 0x5EED),
                    sim: sim.clone(),
                    hint,
                    unique: 0,
                    intents: Vec::new(),
                }
                .run(),
            )
        })
        .collect();
    let mut intents = Vec::new();
    for t in client_tasks {
        intents.push(t.await.unwrap());
    }
    nemesis_task.await.unwrap();

    // Heal everything and let the cluster converge.
    net.heal();
    net.set_faults(0, Duration::ZERO, 0);
    settle("leader after heal", seed, || async {
        sim.leader().await.is_some()
    })
    .await;
    // A final acknowledged write proves a leader commits in its own term, so every replica
    // can reach the same applied index.
    let mut barrier = Client {
        id: 99,
        rng: SplitMix64::new(seed ^ 0xB0B),
        plan: SplitMix64::new(0),
        sim: sim.clone(),
        hint: voters[0],
        unique: 0,
        intents: Vec::new(),
    };
    let barrier_rev = loop {
        match barrier
            .write("barrier", Kind::Put(b"end".to_vec()), Precondition::None)
            .await
        {
            Some(Outcome::Acked(r)) => break r,
            _ => barrier.backoff().await,
        }
    };
    settle("replicas to converge", seed, || async {
        let applied: Vec<Option<u64>> = sim
            .live()
            .iter()
            .map(|s| s.local_applied_index().unwrap())
            .collect();
        applied.len() == voters.len()
            && applied.iter().all(|a| *a == applied[0])
            && applied[0] >= Some(barrier_rev)
    })
    .await;

    let mut dumps = BTreeMap::new();
    let mut metrics = Vec::new();
    for s in sim.live() {
        dumps.insert(s.id(), s.local_dump().unwrap());
        let m = s.raft().metrics().borrow_watched().clone();
        metrics.push((
            s.id(),
            m.current_term,
            m.snapshot.map(|l| l.index),
            m.purged.map(|l| l.index),
        ));
    }
    for s in sim.live() {
        let _ = s.shutdown().await;
    }
    let watchers: Vec<_> = std::mem::take(&mut *lock(&sim.watchers));
    for w in watchers {
        w.await.unwrap();
    }

    stop_clock.store(true, Ordering::Relaxed);
    clock.await.unwrap();

    let logs: BTreeMap<NodeId, Vec<Item>> = sim
        .logs
        .iter()
        .map(|(id, l)| (*id, lock(l).clone()))
        .collect();
    let hist = lock(&sim.hist);
    check(seed, &hist, &dumps, &logs);

    let schedule = lock(&sim.schedule).clone();
    let (mut acked, mut failed, mut unknown) = (0, 0, 0);
    for w in &hist.writes {
        match w.outcome {
            Outcome::Acked(_) => acked += 1,
            Outcome::Failed => failed += 1,
            Outcome::Unknown => unknown += 1,
        }
    }
    let resets: usize = logs
        .values()
        .map(|l| l.iter().filter(|i| **i == Item::Reset).count())
        .sum::<usize>()
        - voters.len()
        - usize::try_from(sim.crashes.load(Ordering::Relaxed)).unwrap();
    let stats = net.fault_stats();
    let max_term = metrics.iter().map(|m| m.1).max().unwrap_or_default();
    let snapshots: Vec<_> = metrics.iter().map(|m| m.2.unwrap_or(0)).collect();
    eprintln!(
        "sim seed {seed}: {} voters, {:.1}s virtual, writes acked {acked} failed {failed} unknown {unknown}, \
         reads {}, restarts {}, watch resets (snapshot/lag) {resets}, last term {max_term}, \
         snapshot index per node {snapshots:?}, rpc dropped {} delayed {} refused {}, \
         last revision {barrier_rev}",
        voters.len(),
        virtual_start.elapsed().as_secs_f64(),
        hist.reads.len(),
        sim.crashes.load(Ordering::Relaxed),
        stats.dropped,
        stats.delayed,
        stats.refused,
    );

    let history_hash = hash_of(
        &hist
            .writes
            .iter()
            .map(|w| (w.key.clone(), w.kind.clone(), w.outcome))
            .collect::<Vec<_>>(),
    );
    Report {
        seed,
        voters: voters.len(),
        acked,
        failed,
        unknown,
        reads: hist.reads.len(),
        schedule_hash: hash_of(&schedule),
        intents_hash: hash_of(&intents),
        history_hash,
        schedule,
    }
}

// ---------------------------------------------------------------- invariants

/// Revision, key name and value of one watch event.
type SegEvent<'a> = (u64, &'a str, &'a Option<Vec<u8>>);

type Dump = Vec<(Key, torngat_store::Versioned)>;

/// Verifies, panicking with the seed on the first violation:
///
/// 1. Convergence: every replica's final state is identical.
/// 2. Durability: the last acknowledged write of each key is present with its revision, or was
///    superseded by a later write or delete (acknowledged or unknown) that explains the state.
/// 3. Counters: acked <= final <= acked + unknown increments; on every watch stream values
///    between resets rise by exactly one with rising revisions; linearizable reads never see
///    fewer increments than were acknowledged before they began.
/// 4. Revisions: acknowledged revisions are unique, follow real-time order, and agree with what
///    watchers saw; every replica reports the same event for a revision.
/// 5. Watch streams: revisions strictly increase between resets, and no acknowledged put or
///    increment inside a segment's revision range is missing from it.
fn check(
    seed: u64,
    hist: &History,
    dumps: &BTreeMap<NodeId, Dump>,
    logs: &BTreeMap<NodeId, Vec<Item>>,
) {
    // 1. convergence.
    let mut finals = dumps.iter();
    let (first_id, first) = finals.next().unwrap();
    for (id, d) in finals {
        ensure!(
            seed,
            d == first,
            "replica {id} differs from replica {first_id}:\n{d:?}\nvs\n{first:?}"
        );
    }
    let fin: BTreeMap<String, (u64, Vec<u8>)> = first
        .iter()
        .map(|(k, v)| {
            let name = k.as_str().strip_prefix("sim/").unwrap().to_owned();
            (name, (v.revision, v.value.clone()))
        })
        .collect();

    let mut by_key: BTreeMap<&str, Vec<&Write>> = BTreeMap::new();
    for w in &hist.writes {
        by_key.entry(w.key.as_str()).or_default().push(w);
    }
    for name in fin.keys() {
        ensure!(
            seed,
            by_key.contains_key(name.as_str()),
            "key {name} was never written"
        );
    }

    // 2. durability.
    let value_of = |w: &Write| -> Option<Vec<u8>> {
        match &w.kind {
            Kind::Incr(v) => Some(v.to_string().into_bytes()),
            Kind::Put(v) => Some(v.clone()),
            Kind::Delete => None,
        }
    };
    for (name, ws) in &by_key {
        let last = ws
            .iter()
            .filter_map(|w| match w.outcome {
                Outcome::Acked(r) => Some((r, *w)),
                _ => None,
            })
            .max_by_key(|(r, _)| *r);
        let unknown_puts: Vec<Vec<u8>> = ws
            .iter()
            .filter(|w| w.outcome == Outcome::Unknown)
            .filter_map(|w| value_of(w))
            .collect();
        let unknown_delete = ws
            .iter()
            .any(|w| w.outcome == Outcome::Unknown && w.kind == Kind::Delete);
        let now = fin.get(*name);
        match (last, now) {
            (Some((r, w)), now) if value_of(w).is_some() => match now {
                Some((fr, fv)) if *fr == r => {
                    ensure!(
                        seed,
                        Some(fv) == value_of(w).as_ref(),
                        "{name}: acked put at {r} holds a different value"
                    );
                }
                Some((fr, fv)) => {
                    ensure!(
                        seed,
                        *fr > r,
                        "{name}: acked put at revision {r} lost, state is at {fr}"
                    );
                    ensure!(
                        seed,
                        unknown_puts.contains(fv),
                        "{name}: revision {fr} above acked {r} has no source"
                    );
                }
                None => ensure!(
                    seed,
                    unknown_delete,
                    "{name}: acked put at revision {r} lost (key absent)"
                ),
            },
            (Some((r, _)), now) => {
                if let Some((fr, fv)) = now {
                    ensure!(
                        seed,
                        *fr > r,
                        "{name}: key present at {fr} after acked delete at {r}"
                    );
                    ensure!(
                        seed,
                        unknown_puts.contains(fv),
                        "{name}: revision {fr} above acked delete {r} has no source"
                    );
                }
            }
            (None, Some((fr, fv))) => {
                ensure!(
                    seed,
                    unknown_puts.contains(fv),
                    "{name}: revision {fr} exists but no acked or unknown write explains it"
                );
            }
            (None, None) => {}
        }
    }

    // 3. counters.
    for i in 0..COUNTERS {
        let name = counter_name(i);
        let ws = by_key
            .get(name.as_str())
            .map(Vec::as_slice)
            .unwrap_or_default();
        let acked = ws
            .iter()
            .filter(|w| matches!(w.outcome, Outcome::Acked(_)))
            .count() as u64;
        let unknown = ws.iter().filter(|w| w.outcome == Outcome::Unknown).count() as u64;
        let value = fin.get(&name).map_or(0, |(_, v)| {
            String::from_utf8(v.clone())
                .unwrap()
                .parse::<u64>()
                .unwrap()
        });
        ensure!(
            seed,
            acked <= value && value <= acked + unknown,
            "{name}: final {value}, acked {acked}, unknown {unknown}"
        );
    }
    for r in &hist.reads {
        if !r.key.starts_with("ctr-") {
            continue;
        }
        let before = hist
            .writes
            .iter()
            .filter(|w| {
                w.key == r.key && w.done < r.invoke && matches!(w.outcome, Outcome::Acked(_))
            })
            .count() as u64;
        let seen = r.seen.as_ref().map_or(0, |(_, v)| {
            String::from_utf8(v.clone())
                .unwrap()
                .parse::<u64>()
                .unwrap()
        });
        ensure!(
            seed,
            seen >= before,
            "stale read of {}: saw {seen}, {before} increments acknowledged before the read began",
            r.key
        );
    }
    // Reads never go behind an acknowledged write that completed before they began.
    for r in &hist.reads {
        let Some((rev, _)) = &r.seen else { continue };
        for w in hist
            .writes
            .iter()
            .filter(|w| w.key == r.key && w.done < r.invoke)
        {
            if let Outcome::Acked(wr) = w.outcome {
                ensure!(
                    seed,
                    *rev >= wr,
                    "stale read of {}: revision {rev} after acked write at {wr}",
                    r.key
                );
            }
        }
    }

    // 4. revisions.
    let acked: Vec<(&Write, u64)> = hist
        .writes
        .iter()
        .filter_map(|w| match w.outcome {
            Outcome::Acked(r) => Some((w, r)),
            _ => None,
        })
        .collect();
    let mut seen_revs = BTreeSet::new();
    for (w, r) in &acked {
        ensure!(
            seed,
            seen_revs.insert(*r),
            "revision {r} acknowledged twice (second: {w:?})"
        );
    }
    for (a, ra) in &acked {
        for (b, rb) in &acked {
            if a.done < b.invoke {
                ensure!(
                    seed,
                    ra < rb,
                    "real-time order broken: {a:?} (rev {ra}) finished before {b:?} (rev {rb}) began"
                );
            }
        }
    }
    let acked_by_rev: BTreeMap<u64, &Write> = acked.iter().map(|(w, r)| (*r, *w)).collect();

    // 4/5. watch streams.
    let mut by_rev: BTreeMap<u64, (String, Option<Vec<u8>>)> = BTreeMap::new();
    for (id, log) in logs {
        let mut segments: Vec<Vec<SegEvent>> = vec![Vec::new()];
        for item in log {
            match item {
                Item::Reset => segments.push(Vec::new()),
                Item::Event {
                    revision,
                    key,
                    value,
                } => {
                    segments.last_mut().unwrap().push((
                        *revision,
                        key.strip_prefix("sim/").unwrap(),
                        value,
                    ));
                    let entry = (key.clone(), value.clone());
                    let prev = by_rev.entry(*revision).or_insert_with(|| entry.clone());
                    ensure!(
                        seed,
                        *prev == entry,
                        "replicas disagree about revision {revision} (replica {id}): {prev:?} vs {entry:?}"
                    );
                    if let Some(w) = acked_by_rev.get(revision) {
                        ensure!(
                            seed,
                            key.strip_prefix("sim/") == Some(w.key.as_str()),
                            "acked write {w:?} at {revision} appeared on {key}"
                        );
                        ensure!(
                            seed,
                            *value == value_of(w),
                            "acked write {w:?} at {revision} appeared with value {value:?}"
                        );
                    }
                }
            }
        }
        for seg in segments.iter().filter(|s| !s.is_empty()) {
            let mut last_rev = 0;
            let mut counters: BTreeMap<&str, u64> = BTreeMap::new();
            for (rev, name, value) in seg {
                ensure!(
                    seed,
                    *rev > last_rev,
                    "replica {id}: revision {rev} after {last_rev} on the watch stream"
                );
                last_rev = *rev;
                if name.starts_with("ctr-") {
                    let v: u64 = String::from_utf8(Option::clone(value).unwrap())
                        .unwrap()
                        .parse()
                        .unwrap();
                    if let Some(prev) = counters.insert(name, v) {
                        ensure!(
                            seed,
                            v == prev + 1,
                            "replica {id}: counter {name} went {prev} -> {v} (lost or doubled update)"
                        );
                    }
                }
            }
            let (lo, hi) = (seg[0].0, seg[seg.len() - 1].0);
            let present: BTreeSet<u64> = seg.iter().map(|e| e.0).collect();
            for (w, r) in &acked {
                if *r > lo && *r < hi && !matches!(w.kind, Kind::Delete) {
                    ensure!(
                        seed,
                        present.contains(r),
                        "replica {id}: acked write {w:?} at {r} missing from a watch segment {lo}..{hi}"
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------- entry points

fn run_in_runtime(seed: u64) -> Report {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap()
        .block_on(run_seed(seed))
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

fn selected_seeds() -> Vec<u64> {
    match (env_u64("TORNGAT_SIM_SEED"), env_u64("TORNGAT_SIM_SEEDS")) {
        (Some(s), _) => vec![s],
        (None, Some(n)) => (0..n).collect(),
        (None, None) => (0..8).collect(),
    }
}

#[test]
fn simulation() {
    let started = Instant::now();
    let mut failed = Vec::new();
    for seed in selected_seeds() {
        let t = Instant::now();
        match catch_unwind(AssertUnwindSafe(|| run_in_runtime(seed))) {
            Ok(_) => eprintln!("sim seed {seed}: ok in {:.1}s", t.elapsed().as_secs_f64()),
            Err(_) => failed.push(seed),
        }
    }
    eprintln!("sim: total {:.1}s", started.elapsed().as_secs_f64());
    assert!(
        failed.is_empty(),
        "failed seeds: {failed:?} (rerun with TORNGAT_SIM_SEED=<seed>)"
    );

    if std::env::var_os("TORNGAT_SIM_DETERMINISM").is_some() {
        let seed = selected_seeds()[0];
        let (a, b) = (run_in_runtime(seed), run_in_runtime(seed));
        let common = a
            .schedule
            .iter()
            .zip(&b.schedule)
            .take_while(|(x, y)| x == y)
            .count();
        eprintln!(
            "determinism seed {seed}: schedule steps equal for the first {common} of {}/{}; \
             schedule hash equal {}, client intents hash equal {}, history hash equal {}; \
             run A acked/failed/unknown {}/{}/{}, run B {}/{}/{}",
            a.schedule.len(),
            b.schedule.len(),
            a.schedule_hash == b.schedule_hash,
            a.intents_hash == b.intents_hash,
            a.history_hash == b.history_hash,
            a.acked,
            a.failed,
            a.unknown,
            b.acked,
            b.failed,
            b.unknown,
        );
    }
}
