//! Seeded simulation of the replicated store under faults.
//!
//! Each seed builds a 3- or 5-voter cluster on a paused-time runtime, drives it with concurrent
//! clients (compare-and-swap counters and blind writes) while a nemesis partitions, isolates,
//! crashes and restarts nodes and injects message loss and delay, then heals and checks the
//! invariants listed on [`check`]. Upstream Raft is fuzzed elsewhere; this exercises our
//! integration: preconditions, revisions, state machine, snapshots, watches and restarts.
//!
//! Environment: `TORNGAT_SIM_SEEDS=N` runs seeds `0..N` (default 8), `TORNGAT_SIM_SEED=x` runs
//! one seed, `TORNGAT_SIM_THREADS=n` caps how many seeds run in parallel (default: one per CPU),
//! and `TORNGAT_SIM_DETERMINISM=1` additionally runs the first selected seed twice and prints how
//! much of the schedule and history repeated. See docs/TESTING.md.
//!
//! Reproducibility: a seed fixes the cluster size, every client's plan, the nemesis schedule and
//! the fault decisions. It does not fix interleavings: the clock is tied to wall time (see
//! [`clock_driver`]) and fsyncs take real time, so a run replays its schedule, not its history.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use common::{current_leader, members, open_unregistered, wait_leader};
use openraft::async_runtime::WatchReceiver;
use openraft::{Config, SnapshotPolicy};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use torngat_store::testnet::{SplitMix64, TestNet};
use torngat_store::{Key, NodeId, Precondition, Prefix, Store, StoreError, Versioned};

/// Virtual time a client waits for a write or read before calling the outcome unknown.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(2);
/// Virtual time to wait for all replicas to apply the final write once the cluster is healed.
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(60);
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

fn is_counter(name: &str) -> bool {
    name.starts_with("ctr-")
}

/// Counter values are decimal text.
fn parse_ctr(value: &[u8]) -> u64 {
    std::str::from_utf8(value)
        .expect("counter value is text")
        .parse()
        .expect("counter value is a number")
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
    /// The value written; `None` is a delete. Counter increments write the new count.
    value: Option<Vec<u8>>,
    /// Logical clock readings just before the call and just after it returned.
    invoke: u64,
    done: u64,
    outcome: Outcome,
}

#[derive(Debug, Clone)]
struct Read {
    key: String,
    invoke: u64,
    /// Revision and value the linearizable read returned (`None`: key absent).
    seen: Option<(u64, Vec<u8>)>,
}

#[derive(Debug, Default)]
struct History {
    writes: Vec<Write>,
    reads: Vec<Read>,
}

/// A change a replica's watcher saw.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ev {
    revision: u64,
    key: String,
    value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Event(Ev),
    /// The stream restarted: lagged, snapshot installed, or the replica restarted.
    Reset,
}

// ---------------------------------------------------------------- cluster

struct Sim {
    voters: Vec<NodeId>,
    net: TestNet,
    nodes: Mutex<BTreeMap<NodeId, Option<Store>>>,
    dirs: BTreeMap<NodeId, TempDir>,
    logs: BTreeMap<NodeId, Arc<Mutex<Vec<Item>>>>,
    watchers: Mutex<Vec<JoinHandle<()>>>,
    hist: Mutex<History>,
    /// Logical clock ordering invocations and completions across clients.
    clock: AtomicU64,
    schedule: Mutex<Vec<String>>,
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

    async fn leader(&self) -> Option<NodeId> {
        let live = self.live();
        current_leader(&live.iter().collect::<Vec<_>>(), None).await
    }

    async fn wait_leader(&self) -> NodeId {
        let live = self.live();
        wait_leader(&live.iter().collect::<Vec<_>>(), None).await
    }

    /// Opens replica `id` in its directory, starts its watcher and makes it reachable.
    async fn start_node(&self, id: NodeId) {
        let store = open_unregistered(&self.net, self.dirs[&id].path(), id, sim_config()).await;
        // Subscribe before the node is reachable so no applied entry can be missed.
        let mut watch = store.watch(Prefix::new("sim", []).unwrap());
        let log = self.logs[&id].clone();
        lock(&log).push(Item::Reset);
        let handle = tokio::spawn(async move {
            loop {
                let item = match watch.next().await {
                    Ok(e) => Item::Event(Ev {
                        revision: e.revision,
                        key: e.key.as_str().strip_prefix("sim/").unwrap().to_owned(),
                        value: e.value.map(|v| v.as_ref().clone()),
                    }),
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
        old.shutdown().await.unwrap();
        tokio::time::sleep(down).await;
        self.start_node(id).await;
    }

    fn note(&self, line: String) {
        lock(&self.schedule).push(line);
    }
}

/// Drives the paused clock at a fixed rate against real time.
///
/// Plain auto-advance is useless here: whenever the runtime idles waiting for a log fsync (done
/// by a thread tokio does not know about), the clock jumps to the next timer, so election
/// timeouts fire before any fsync returns and the cluster livelocks in elections. A blocking
/// task in flight inhibits auto-advance, so each tick waits in one and then advances the clock
/// by [`TICK`] by hand: virtual time runs a few times faster than real time, and an fsync costs
/// a realistic number of virtual milliseconds. The price is that virtual time now depends on
/// wall time, so task interleavings (and with them histories) are not reproducible.
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
    /// Operation intents, hashed to measure reproducibility.
    intents: Vec<String>,
}

impl Client {
    fn new(id: u64, seed: u64, sim: Arc<Sim>) -> Self {
        let mut rng = SplitMix64::new(seed);
        let hint = sim.voters[rng.below(sim.voters.len() as u64) as usize];
        Self {
            id,
            rng,
            plan: SplitMix64::new(seed ^ 0x5EED),
            sim,
            hint,
            intents: Vec::new(),
        }
    }

    fn random_node(&mut self) -> NodeId {
        self.sim.voters[self.rng.below(self.sim.voters.len() as u64) as usize]
    }

    /// Follows a leader hint, or tries anywhere when there is none.
    fn reroute(&mut self, leader: Option<NodeId>) {
        self.hint = leader.unwrap_or_else(|| self.random_node());
    }

    /// The node to try: usually the believed leader, sometimes any node. `None` if it is down.
    fn target(&mut self) -> Option<Store> {
        let node = if self.rng.below(10) == 0 {
            self.random_node()
        } else {
            self.hint
        };
        let store = self.sim.store(node);
        if store.is_none() {
            self.reroute(None);
        }
        store
    }

    async fn backoff(&mut self) {
        let ms = 10 + self.rng.below(50);
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    /// One write attempt (a delete if `value` is `None`). `None` if the chosen node is down and
    /// nothing was sent. Failed attempts are recorded too.
    async fn write(
        &mut self,
        name: &str,
        value: Option<Vec<u8>>,
        precondition: Precondition,
    ) -> Option<Outcome> {
        let store = self.target()?;
        let invoke = self.sim.tick();
        let call = async {
            match &value {
                Some(v) => store.put(key(name), v.clone(), precondition).await,
                None => store.delete(key(name), precondition).await,
            }
        };
        let result = tokio::time::timeout(CLIENT_TIMEOUT, call).await;
        let done = self.sim.tick();
        let outcome = match result {
            Ok(Ok(rev)) => Outcome::Acked(rev),
            Ok(Err(StoreError::PreconditionFailed { .. })) => Outcome::Failed,
            // A ForwardToLeader error is returned before anything is appended.
            Ok(Err(StoreError::NotLeader { leader })) => {
                self.reroute(leader);
                Outcome::Failed
            }
            Ok(Err(StoreError::ValueTooLarge)) => unreachable!("sim values are small"),
            Ok(Err(_)) | Err(_) => {
                self.reroute(None);
                Outcome::Unknown
            }
        };
        lock(&self.sim.hist).writes.push(Write {
            key: name.to_owned(),
            value,
            invoke,
            done,
            outcome,
        });
        Some(outcome)
    }

    /// Linearizable read, recorded. `None` if it did not succeed.
    async fn read(&mut self, name: &str) -> Option<Option<(u64, Vec<u8>)>> {
        let store = self.target()?;
        let invoke = self.sim.tick();
        match tokio::time::timeout(CLIENT_TIMEOUT, store.get(&key(name))).await {
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
                self.reroute(leader);
                None
            }
            _ => {
                self.reroute(None);
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
            if let Some(seen) = self.read(&name).await {
                let (next, precondition) = match seen {
                    Some((rev, value)) => (parse_ctr(&value) + 1, Precondition::Revision(rev)),
                    None => (1, Precondition::Absent),
                };
                let value = Some(next.to_string().into_bytes());
                if let Some(Outcome::Acked(_) | Outcome::Unknown) =
                    self.write(&name, value, precondition).await
                {
                    return;
                }
            }
            self.backoff().await;
        }
    }

    async fn run(mut self) -> Vec<String> {
        for i in 0..CLIENT_OPS {
            let roll = self.plan.below(10);
            let name = blind_name(self.plan.below(BLIND_KEYS as u64) as usize);
            let ctr = self.plan.below(COUNTERS as u64) as usize;
            let think = 5 + self.plan.below(80);
            let unique = Some(format!("c{}-{i}", self.id).into_bytes());
            match roll {
                0..=4 => {
                    self.intents.push(format!("incr {ctr}"));
                    self.increment(ctr).await;
                }
                5 | 6 => {
                    self.intents.push(format!("put {name}"));
                    self.write(&name, unique, Precondition::None).await;
                }
                7 => {
                    self.intents.push(format!("create {name}"));
                    self.write(&name, unique, Precondition::Absent).await;
                }
                8 => {
                    self.intents.push(format!("delete {name}"));
                    self.write(&name, None, Precondition::None).await;
                }
                _ => {
                    self.intents.push(format!("get {name}"));
                    self.read(&name).await;
                }
            }
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
                let target = match sim.leader().await {
                    Some(l) if a % 2 == 0 => l,
                    _ => pick(b),
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

/// What a run leaves behind for the determinism measurement.
#[derive(Debug, Default, Clone)]
struct Report {
    acked: usize,
    failed: usize,
    unknown: usize,
    schedule: Vec<String>,
    intents_hash: u64,
    history_hash: u64,
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

async fn run_seed(seed: u64) -> Report {
    let virtual_start = tokio::time::Instant::now();
    let stop_clock = Arc::new(AtomicBool::new(false));
    let clock = tokio::spawn(clock_driver(stop_clock.clone()));
    let voters: Vec<NodeId> = (1..=if seed.is_multiple_of(2) { 3 } else { 5 }).collect();
    let net = TestNet::default();
    let sim = Arc::new(Sim {
        voters: voters.clone(),
        net: net.clone(),
        nodes: Mutex::default(),
        dirs: voters
            .iter()
            .map(|v| (*v, TempDir::new().unwrap()))
            .collect(),
        logs: voters.iter().map(|v| (*v, Arc::default())).collect(),
        watchers: Mutex::default(),
        hist: Mutex::default(),
        clock: AtomicU64::new(1),
        schedule: Mutex::default(),
    });
    for v in &voters {
        sim.start_node(*v).await;
    }
    sim.store(voters[0])
        .unwrap()
        .initialize(members(&voters))
        .await
        .unwrap();
    sim.wait_leader().await;

    // Faults start only once the cluster has a leader; seeds fix everything after this point.
    let mut master = SplitMix64::new(seed);
    let nemesis_seed = master.next_u64();
    let client_count = 2 + master.below(3);
    let nemesis_task = tokio::spawn(nemesis(sim.clone(), SplitMix64::new(nemesis_seed)));
    let client_tasks: Vec<_> = (0..client_count)
        .map(|i| tokio::spawn(Client::new(i, master.next_u64(), sim.clone()).run()))
        .collect();
    let mut intents = Vec::new();
    for t in client_tasks {
        intents.push(t.await.unwrap());
    }
    nemesis_task.await.unwrap();

    // Heal everything. A final acknowledged write proves a leader commits in its own term, so
    // every replica can reach the same applied index.
    net.heal();
    net.clear_faults();
    sim.wait_leader().await;
    let mut barrier = Client::new(99, seed ^ 0xB0B, sim.clone());
    let barrier_deadline = Instant::now() + Duration::from_secs(120);
    let barrier_rev = loop {
        assert!(
            Instant::now() < barrier_deadline,
            "sim seed {seed}: final write was never acknowledged"
        );
        match barrier
            .write("barrier", Some(b"end".to_vec()), Precondition::None)
            .await
        {
            Some(Outcome::Acked(r)) => break r,
            _ => barrier.backoff().await,
        }
    };
    // These timeouts run on the virtual clock.
    let mut dumps = BTreeMap::new();
    let mut term = 0;
    let mut snapshots = Vec::new();
    assert_eq!(sim.live().len(), voters.len(), "a node is still down");
    for s in sim.live() {
        s.raft()
            .wait(Some(CONVERGE_TIMEOUT))
            .applied_index_at_least(Some(barrier_rev), "final write applied")
            .await
            .unwrap_or_else(|e| panic!("sim seed {seed}: node {} did not converge: {e}", s.id()));
        dumps.insert(s.id(), s.local_dump().unwrap());
        let m = s.raft().metrics().borrow_watched().clone();
        term = term.max(m.current_term);
        snapshots.push(m.snapshot.map_or(0, |l| l.index));
    }
    for s in sim.live() {
        s.shutdown().await.unwrap();
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
    let count = |f: fn(&Outcome) -> bool| hist.writes.iter().filter(|w| f(&w.outcome)).count();
    let acked = count(|o| matches!(o, Outcome::Acked(_)));
    let failed = count(|o| *o == Outcome::Failed);
    let unknown = count(|o| *o == Outcome::Unknown);
    let resets = logs
        .values()
        .flatten()
        .filter(|i| **i == Item::Reset)
        .count();
    let restarts = schedule.iter().filter(|l| l.contains(" restart ")).count();
    eprintln!(
        "sim seed {seed}: {} voters, {:.1}s virtual, writes acked {acked} failed {failed} \
         unknown {unknown}, reads {}, restarts {restarts}, watch streams/resets {resets}, \
         last term {term}, snapshot index per node {snapshots:?}, last revision {barrier_rev}",
        voters.len(),
        virtual_start.elapsed().as_secs_f64(),
        hist.reads.len(),
    );
    Report {
        acked,
        failed,
        unknown,
        schedule,
        intents_hash: hash_of(&intents),
        history_hash: hash_of(
            &hist
                .writes
                .iter()
                .map(|w| (&w.key, &w.value, w.outcome))
                .collect::<Vec<_>>(),
        ),
    }
}

// ---------------------------------------------------------------- invariants

type Dump = Vec<(Key, Versioned)>;

/// Acknowledged writes ordered by completion, answering "what had completed before time t".
struct Completed {
    done: Vec<u64>,
    /// Running maximum of (revision, is_delete) over the writes up to each position.
    best: Vec<(u64, bool)>,
}

impl Completed {
    fn new<'a>(acked: impl Iterator<Item = (&'a Write, u64)>) -> Self {
        let mut v: Vec<(u64, u64, bool)> = acked
            .map(|(w, rev)| (w.done, rev, w.value.is_none()))
            .collect();
        v.sort_unstable();
        let mut best: Vec<(u64, bool)> = Vec::with_capacity(v.len());
        for (_, rev, del) in &v {
            let top = best.last().copied().filter(|(r, _)| r > rev);
            best.push(top.unwrap_or((*rev, *del)));
        }
        Self {
            done: v.iter().map(|e| e.0).collect(),
            best,
        }
    }

    /// The highest-revision write that completed before `t`.
    fn before(&self, t: u64) -> Option<(u64, bool)> {
        let n = self.done.partition_point(|d| *d < t);
        n.checked_sub(1).map(|i| self.best[i])
    }
}

/// Verifies, panicking with the seed on the first violation:
///
/// 1. Convergence: every replica's final state is identical.
/// 2. Durability: the last acknowledged write of every key is present at its revision, or was
///    superseded by a later write or delete (acknowledged or unknown) that explains the state.
/// 3. Counters: acked increments <= final value <= acked + unknown; on each replica's watch
///    stream values between resets rise by exactly one.
/// 4. Revisions: acknowledged revisions are unique and follow real-time order; linearizable
///    reads never go behind an acknowledged write that completed before they began; watchers
///    saw each acknowledged write at its revision, and replicas agree on every revision's event.
/// 5. Watch streams: revisions strictly increase between resets, and no acknowledged write
///    inside a segment's revision range is missing from it.
fn check(
    seed: u64,
    hist: &History,
    dumps: &BTreeMap<NodeId, Dump>,
    logs: &BTreeMap<NodeId, Vec<Item>>,
) {
    // 1. Convergence.
    let mut finals = dumps.iter();
    let (first_id, first) = finals.next().unwrap();
    for (id, d) in finals {
        ensure!(
            seed,
            d == first,
            "replica {id} differs from replica {first_id}:\n{d:?}\nvs\n{first:?}"
        );
    }
    let fin: BTreeMap<String, (u64, &Vec<u8>)> = first
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().strip_prefix("sim/").unwrap().to_owned(),
                (v.revision, &v.value),
            )
        })
        .collect();

    let mut by_key: BTreeMap<&str, Vec<&Write>> = BTreeMap::new();
    for w in &hist.writes {
        by_key.entry(w.key.as_str()).or_default().push(w);
    }
    let acked: Vec<(&Write, u64)> = hist
        .writes
        .iter()
        .filter_map(|w| match w.outcome {
            Outcome::Acked(r) => Some((w, r)),
            _ => None,
        })
        .collect();

    // 2. Durability. The state of a key must be one of: the last acked write (same revision and
    // value); a newer unknown put; absent after an acked delete, never written, or a possible
    // unknown delete.
    for name in fin.keys() {
        ensure!(
            seed,
            by_key.contains_key(name.as_str()),
            "key {name} was never written"
        );
    }
    for (name, ws) in &by_key {
        let last = ws
            .iter()
            .filter_map(|w| match w.outcome {
                Outcome::Acked(r) => Some((r, *w)),
                _ => None,
            })
            .max_by_key(|(r, _)| *r);
        let unknown: Vec<&Option<Vec<u8>>> = ws
            .iter()
            .filter(|w| w.outcome == Outcome::Unknown)
            .map(|w| &w.value)
            .collect();
        let explained = match (fin.get(*name), last) {
            (Some((fr, fv)), Some((r, w))) if *fr == r => w.value.as_ref() == Some(*fv),
            (Some((fr, fv)), last) => {
                last.is_none_or(|(r, _)| *fr > r) && unknown.iter().any(|v| v.as_ref() == Some(*fv))
            }
            (None, last) => {
                last.is_none_or(|(_, w)| w.value.is_none()) || unknown.iter().any(|v| v.is_none())
            }
        };
        ensure!(
            seed,
            explained,
            "{name}: final state {:?} contradicts last acked write {last:?} (unknown writes: {unknown:?})",
            fin.get(*name)
        );
    }

    // 3. Counters.
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
        let value = fin.get(&name).map_or(0, |(_, v)| parse_ctr(v));
        ensure!(
            seed,
            acked <= value && value <= acked + unknown,
            "{name}: final {value}, acked {acked}, unknown {unknown}"
        );
    }

    // 4. Revisions.
    let mut seen_revs = BTreeSet::new();
    for (w, r) in &acked {
        ensure!(
            seed,
            seen_revs.insert(*r),
            "revision {r} acknowledged twice (second: {w:?})"
        );
    }
    let all = Completed::new(acked.iter().copied());
    for (w, r) in &acked {
        if let Some((prev, _)) = all.before(w.invoke) {
            ensure!(
                seed,
                prev < *r,
                "real-time order broken: revision {prev} completed before {w:?} began but {r} is not above it"
            );
        }
    }
    let per_key: BTreeMap<&str, Completed> = by_key
        .iter()
        .map(|(k, ws)| {
            let own = ws.iter().filter_map(|w| match w.outcome {
                Outcome::Acked(r) => Some((*w, r)),
                _ => None,
            });
            (*k, Completed::new(own))
        })
        .collect();
    for r in &hist.reads {
        // A value read at a revision was written by an acked write at that revision, or by an
        // unknown write (whose revision we never learned) with that value.
        if let Some((seen, value)) = &r.seen {
            let written = by_key.get(r.key.as_str()).is_some_and(|ws| {
                ws.iter().any(|w| {
                    w.value.as_ref() == Some(value)
                        && match w.outcome {
                            Outcome::Acked(rev) => rev == *seen,
                            Outcome::Unknown => true,
                            Outcome::Failed => false,
                        }
                })
            });
            ensure!(
                seed,
                written,
                "read of {} returned {value:?} at revision {seen}, which no write explains",
                r.key
            );
        }
        let Some((rev, del)) = per_key.get(r.key.as_str()).and_then(|c| c.before(r.invoke)) else {
            continue;
        };
        let ok = match &r.seen {
            Some((seen, _)) => *seen >= rev,
            // Absent: fine after a delete, or if a delete could have followed the last write.
            None => {
                del || by_key[r.key.as_str()].iter().any(|w| {
                    w.value.is_none()
                        && match w.outcome {
                            Outcome::Unknown => true,
                            Outcome::Acked(dr) => dr > rev,
                            Outcome::Failed => false,
                        }
                })
            }
        };
        ensure!(
            seed,
            ok,
            "stale read of {}: saw {:?} after an acknowledged write at revision {rev} completed",
            r.key,
            r.seen
        );
    }
    let acked_by_rev: BTreeMap<u64, &Write> = acked.iter().map(|(w, r)| (*r, *w)).collect();
    let mut by_rev: BTreeMap<u64, &Ev> = BTreeMap::new();
    for (id, log) in logs {
        for item in log {
            let Item::Event(ev) = item else { continue };
            let prev = by_rev.entry(ev.revision).or_insert(ev);
            ensure!(
                seed,
                **prev == *ev,
                "replicas disagree about revision {} (replica {id}): {prev:?} vs {ev:?}",
                ev.revision
            );
            if let Some(w) = acked_by_rev.get(&ev.revision) {
                ensure!(
                    seed,
                    ev.key == w.key && ev.value == w.value,
                    "acked write {w:?} at {} appeared as {ev:?}",
                    ev.revision
                );
            }
        }
    }

    // 3 and 5. Watch streams, split into segments at every reset.
    let acked_puts: BTreeMap<u64, &Write> = acked_by_rev
        .iter()
        .filter(|(_, w)| w.value.is_some())
        .map(|(r, w)| (*r, *w))
        .collect();
    for (id, log) in logs {
        for seg in segments(log).iter().filter(|s| !s.is_empty()) {
            check_segment(seed, *id, seg, &acked_puts);
        }
    }
}

/// The events of a replica's watch stream, one slice per stretch between resets.
fn segments(log: &[Item]) -> Vec<Vec<&Ev>> {
    let mut out = vec![Vec::new()];
    for item in log {
        match item {
            Item::Reset => out.push(Vec::new()),
            Item::Event(e) => out.last_mut().unwrap().push(e),
        }
    }
    out
}

/// Checks one gap-free stretch of a replica's watch stream.
fn check_segment(seed: u64, replica: NodeId, seg: &[&Ev], acked_puts: &BTreeMap<u64, &Write>) {
    let mut last_rev = 0;
    let mut counters: BTreeMap<&str, u64> = BTreeMap::new();
    for ev in seg {
        ensure!(
            seed,
            ev.revision > last_rev,
            "replica {replica}: revision {} after {last_rev} on the watch stream",
            ev.revision
        );
        last_rev = ev.revision;
        if is_counter(&ev.key) {
            let v = parse_ctr(ev.value.as_ref().expect("counters are never deleted"));
            if let Some(prev) = counters.insert(&ev.key, v) {
                ensure!(
                    seed,
                    v == prev + 1,
                    "replica {replica}: counter {} went {prev} -> {v} (lost or doubled update)",
                    ev.key
                );
            }
        }
    }
    let (lo, hi) = (seg[0].revision, last_rev);
    let present: BTreeSet<u64> = seg.iter().map(|e| e.revision).collect();
    for (rev, w) in acked_puts.range(lo..=hi) {
        ensure!(
            seed,
            present.contains(rev),
            "replica {replica}: acked write {w:?} at {rev} missing from a watch segment {lo}..{hi}"
        );
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

fn panic_message(p: &(dyn std::any::Any + Send)) -> String {
    p.downcast_ref::<String>()
        .cloned()
        .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_else(|| "non-string panic".into())
}

#[test]
fn simulation() {
    let started = Instant::now();
    let seeds = selected_seeds();
    let threads = env_u64("TORNGAT_SIM_THREADS")
        .map(|n| n as usize)
        .or_else(|| std::thread::available_parallelism().ok().map(Into::into))
        .unwrap_or(1)
        .clamp(1, seeds.len().max(1));
    let next = AtomicUsize::new(0);
    let failed = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                while let Some(&seed) = seeds.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let t = Instant::now();
                    match catch_unwind(AssertUnwindSafe(|| run_in_runtime(seed))) {
                        Ok(_) => {
                            eprintln!("sim seed {seed}: ok in {:.1}s", t.elapsed().as_secs_f64())
                        }
                        Err(p) => {
                            eprintln!("sim seed {seed}: FAILED: {}", panic_message(&*p));
                            lock(&failed).push(seed);
                        }
                    }
                }
            });
        }
    });
    eprintln!(
        "sim: {} seeds on {threads} threads in {:.1}s",
        seeds.len(),
        started.elapsed().as_secs_f64()
    );
    let mut failed = failed.into_inner().unwrap_or_else(PoisonError::into_inner);
    failed.sort_unstable();
    assert!(
        failed.is_empty(),
        "failed seeds: {failed:?} (rerun with TORNGAT_SIM_SEED=<seed>)"
    );

    if std::env::var_os("TORNGAT_SIM_DETERMINISM").is_some() && !seeds.is_empty() {
        let seed = seeds[0];
        let (a, b) = (run_in_runtime(seed), run_in_runtime(seed));
        let common = a
            .schedule
            .iter()
            .zip(&b.schedule)
            .take_while(|(x, y)| x == y)
            .count();
        eprintln!(
            "determinism seed {seed}: schedule steps equal for the first {common} of {}/{}; \
             client intents hash equal {}, history hash equal {}; \
             run A acked/failed/unknown {}/{}/{}, run B {}/{}/{}",
            a.schedule.len(),
            b.schedule.len(),
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
