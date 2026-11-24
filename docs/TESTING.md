# Testing

## Unit and integration tests

`cargo test --workspace --all-features --locked`, or `scripts/ci-local.sh` for everything CI runs
(fmt, clippy, tests, cargo-deny).

## Store simulation

`crates/store/tests/sim.rs` is a seeded simulation of the replicated store. Upstream openraft is
fuzzed separately; this test covers our integration: preconditions, revisions, the fjall state
machine, snapshots, watches and restarts.

Per seed it starts 3 voters (even seeds) or 5 voters (odd seeds) with the log and state machine
on disk, snapshotting every 20 entries, and runs 2-4 concurrent clients against whichever node
they believe leads. Clients do compare-and-swap counter increments (read, then put value+1 on
the revision read) and blind puts, creates and deletes. A nemesis meanwhile isolates nodes (often
the leader), partitions the cluster, heals, stops and restarts nodes from their directories, and
changes message loss (0-5% of requests and responses) and delay (0-50 ms). At the end it heals, waits for all replicas to
apply the same index and checks:

1. Convergence: every replica holds identical keys, values and revisions.
2. Durability: the last acknowledged write of every key is present at its revision, or was
   superseded by a later write or delete that the history can explain.
3. Counters: acked increments <= final value <= acked + unknown; on each replica's watch stream
   counter values rise by exactly one between resets.
4. Revisions: acknowledged revisions are unique and respect real-time order; a linearizable read
   never goes behind an acknowledged write that completed before it began; watchers saw each
   acknowledged write at its revision, and replicas agree on the event at every revision.
5. Watches: revisions strictly increase between resets (lag, snapshot install or restart), and
   no acknowledged put inside a segment's revision range is missing from it.

Every write is classified as acknowledged, definitely failed (precondition failed, or refused by
a non-leader before anything was appended) or unknown (timeout, Raft error, shutdown); unknown
writes may or may not have been applied and the checks allow for both.

### Running

```sh
cargo test -p torngat-store --test sim -- --nocapture   # seeds 0..8, about 12 s on 8+ cores
TORNGAT_SIM_SEEDS=64 cargo test -p torngat-store --test sim -- --nocapture
TORNGAT_SIM_SEED=17 cargo test -p torngat-store --test sim -- --nocapture
TORNGAT_SIM_SEED=17 TORNGAT_SIM_DETERMINISM=1 cargo test -p torngat-store --test sim -- --nocapture
```

Seeds run in parallel, one per CPU; `TORNGAT_SIM_THREADS=1` runs them one after another
(about 40 s for the default seeds in a debug build).

Each seed prints a summary: operations acknowledged, failed and unknown, restarts, watch resets
(snapshot installs, lag or restarts), the last term (elections) and snapshot index per node. A failure panics with `sim seed N: invariant violated: ...`; rerun with
`TORNGAT_SIM_SEED=N`.

### Reproducing a failure

A seed fixes the cluster size, every client's plan, the nemesis schedule and the message
fault decisions. It does not make a run bit-exact: fjall and the log run background threads,
fsync takes real time, the simulated clock is tied to wall time (see below), and which message
meets which fault decision depends on task interleaving. Interleavings and histories are not
reproducible, only schedules.
A failing seed usually fails again but not always; run it several times, and a loop over a
neighbouring range of seeds finds more. `TORNGAT_SIM_DETERMINISM=1` runs the first selected seed
twice and prints how much of the schedule and history repeated. In practice the nemesis schedule
and every client's planned operations repeat exactly (an isolate aimed at "the leader" depends on
who leads at that moment), while the outcomes, and therefore the history, differ between runs.

### Time

The test runs on a current-thread tokio runtime with a paused clock, which the test advances by
hand a few times faster than real time. Plain auto-advancing paused time does not work: tokio
cannot see the log's fsync thread, so whenever the runtime waits for an fsync the clock would jump
to the next timer, and election timeouts would fire before any write completes. The clock driver
instead keeps a blocking task in flight (which inhibits auto-advance) and advances the clock one
tick per real half millisecond. That ties virtual time to wall time, which is what makes
histories irreproducible. Heavily loaded machines (for example `taskset -c 0`) still pass,
with more elections and unknown outcomes.

### Not covered

- Power loss and torn writes on disk: nodes are stopped gracefully (`Store::shutdown`) and
  restarted from the same directory; fsync is never cut short.
- Corruption of files at rest.
- Membership changes under faults (the voter set is fixed).
- Raft itself (openraft is fuzzed upstream).
