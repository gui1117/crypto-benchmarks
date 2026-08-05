//! Benchmarks for the `verifiable` ring VRF implementation across ring domain sizes.
//!
//! # How to read these numbers
//!
//! * **`open_and_create*` times `open` *and* `create` together.** The trait splits the
//!   prover in two: `open` consumes the whole member list and is meant to run online
//!   with access to chain state, while `create` needs only the secret and is meant to
//!   run on an air-gapped device. These benchmarks deliberately report the combined
//!   wallet-side cost of producing a proof from scratch. `open_at_fill_level` measures
//!   the `open` half on its own, so the `create` half is the difference between the two.
//!
//! * **Several groups are intentionally flat, and that is the point.**
//!   `finish_members_at_fill_level`, `push_one_member_at_fill_level`,
//!   `validate_at_fill_level` and `is_valid_at_fill_level` cannot vary with how full
//!   the ring is: those entry points consume fixed-size values (`Intermediate` is 848
//!   bytes, `Members` is 288 bytes), never the member list. They are kept as
//!   regression guards — if one of them ever starts to slope, an O(1) operation has
//!   become O(n). For the same reason `is_valid` must track `validate` (it is
//!   `validate` plus a 32-byte comparison), and `new_secret`, `member_from_secret`,
//!   `sign`, `verify_signature`, `alias_in_context` and `is_member_valid` must agree
//!   across all three domain columns, because none of them touch the ring.
//!
//! * **`batch_validate` comes in two flavours.** `single_ring` puts every proof
//!   against the same ring, which lets the backend build one `RingVerifier` and reuse
//!   it for the whole batch. `multi_ring` gives every proof its own ring, forcing a
//!   verifier rebuild per item. The gap between the two is the share of the batching
//!   win that comes from verifier reuse rather than from the batched pairing check.
//!
//! * **`canary_before` / `canary_after`** are one identical, fixed benchmark run at
//!   the start and at the end of each domain block. They say nothing about the
//!   library; they exist to expose CPU thermal drift. If they disagree by more than a
//!   few percent, the surrounding numbers in that block are not trustworthy: let the
//!   machine cool down, raise `BENCH_COOLDOWN_SECS`, and re-run.
//!
//! # Environment
//!
//! `ark-vrf`'s `parallel` feature is enabled (it arrives with `verifiable/std`), so the
//! ring operations are multi-threaded — deliberately so, this is meant to be a native
//! multi-threaded measurement. What is *not* left to chance is how much parallelism and
//! on which cores.
//!
//! `run-bench.sh` restricts the process to one hardware thread per performance core and
//! this pool matches the resulting affinity mask. Two reasons:
//!
//! * On a hybrid CPU (Intel P/E cores), letting rayon spread over every logical CPU
//!   mixes fast and slow cores. Work stealing across heterogeneous cores makes the
//!   result depend on how the scheduler happened to place the threads.
//! * This work is compute-bound, so SMT siblings mostly add heat rather than
//!   throughput, and heat is what makes these measurements drift.
//!
//! Override the width with `BENCH_THREADS`, or the core set with `taskset`.
//! `BENCH_COOLDOWN_SECS` (default 15) idles the CPU between the heavy groups; set it to
//! 0 to disable.

use std::{collections::BTreeMap, ops::Range, sync::OnceLock, time::Duration};

use ark_vrf::ring::SrsLookup;
use ark_vrf::suites::bandersnatch::BandersnatchSha512Ell2;
use verifiable::ring::ark_vrf;

use criterion::{
    BatchSize, BenchmarkGroup, Criterion, SamplingMode, black_box, criterion_group, criterion_main,
    measurement::WallTime,
};
use verifiable::ring::{
    RingDomainSize, StaticChunk, bandersnatch::BandersnatchVrfVerifiable,
    ring_verifier_builder_params,
};
use verifiable::{Alias, BatchProofItem, BatchProofItemFor, Entropy, GenerateVerifiable};

type Suite = BandersnatchSha512Ell2;
type VerifiableImpl = BandersnatchVrfVerifiable;
type Intermediate = <VerifiableImpl as GenerateVerifiable>::Intermediate;
type Members = <VerifiableImpl as GenerateVerifiable>::Members;
type Member = <VerifiableImpl as GenerateVerifiable>::Member;
type Secret = <VerifiableImpl as GenerateVerifiable>::Secret;
type Proof = <VerifiableImpl as GenerateVerifiable>::Proof;
type Signature = <VerifiableImpl as GenerateVerifiable>::Signature;
type Config = <VerifiableImpl as GenerateVerifiable>::Config;
type BuilderParams = ark_vrf::ring::RingBuilderPcsParams<Suite>;

const CONTEXT: &[u8] = b"verifiable-bench-context";
const MESSAGE: &[u8] = b"benchmark message for verifiable trait";
const BATCH_SIZES: [usize; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

fn domain_label(domain: RingDomainSize) -> &'static str {
    match domain {
        RingDomainSize::Domain11 => "domain11",
        RingDomainSize::Domain12 => "domain12",
        RingDomainSize::Domain16 => "domain16",
    }
}

fn entropy_from_index(idx: usize) -> Entropy {
    let mut entropy = [0u8; 32];
    entropy[0..4].copy_from_slice(&(idx as u32).to_le_bytes());
    entropy
}

/// Pin the rayon pool to a fixed width so the ring operations are measured under a
/// known amount of parallelism from run to run.
///
/// The default follows the CPU affinity mask rather than the machine's total core
/// count, so `run-bench.sh` can decide *which* cores to use (it restricts the process
/// to one hardware thread per performance core) and this just matches it.
fn init_thread_pool() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let threads = std::env::var("BENCH_THREADS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
            });
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .expect("rayon global pool is initialised exactly once");
        eprintln!("benchmark rayon threads: {threads}");
    });
}

/// Idle between the heavy groups so a thermally limited CPU can recover. Without this
/// an identical benchmark drifts by more than 2x depending on where in the run it lands.
fn cooldown() {
    let secs = std::env::var("BENCH_COOLDOWN_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(15);
    if secs > 0 {
        std::thread::sleep(Duration::from_secs(secs));
    }
}

/// Sampling for groups whose iterations cost tens of milliseconds or more.
///
/// Criterion's default of 100 samples turns a 3.5 s iteration into a 6 minute
/// benchmark; the extra samples buy very little on an operation that slow, and the
/// time spent at full load is what drags the rest of the run off-target.
fn heavy(group: &mut BenchmarkGroup<'_, WallTime>, domain: RingDomainSize) {
    let samples = match domain {
        RingDomainSize::Domain11 => 20,
        RingDomainSize::Domain12 => 15,
        RingDomainSize::Domain16 => 10,
    };
    group
        .sampling_mode(SamplingMode::Flat)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(samples);
}

/// Sampling for groups in the low-millisecond range.
fn medium(group: &mut BenchmarkGroup<'_, WallTime>) {
    group
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5))
        .sample_size(50);
}

/// Sampling for groups measured in nanoseconds or microseconds.
///
/// Criterion's default 5 s measurement window buys nothing on an 86 ns operation, and
/// there are enough of these to add minutes of full-load time to the run.
fn cheap(group: &mut BenchmarkGroup<'_, WallTime>) {
    group
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
        .sample_size(100);
}

/// Per-domain member pool, built once and shared by every benchmark for that domain.
///
/// Regenerating this is not cheap — `new_secret` alone is ~107 µs, so a domain16 pool
/// costs about 1.7 s — and it used to be rebuilt from scratch for each group.
struct DomainFixture {
    domain: RingDomainSize,
    config: Config,
    label: &'static str,
    ring_size: usize,
    builder_params: BuilderParams,
    secrets: Vec<Secret>,
    members: Vec<Member>,
}

impl DomainFixture {
    fn new(domain: RingDomainSize) -> Self {
        let config: Config = domain;
        let ring_size = domain.max_ring_size::<Suite>();
        let builder_params = ring_verifier_builder_params::<Suite>(domain);

        let secrets: Vec<Secret> = (0..ring_size)
            .map(|i| VerifiableImpl::new_secret(entropy_from_index(i)))
            .collect();
        let members: Vec<Member> = secrets
            .iter()
            .map(VerifiableImpl::member_from_secret)
            .collect();

        DomainFixture {
            domain,
            config,
            label: domain_label(domain),
            ring_size,
            builder_params,
            secrets,
            members,
        }
    }

    fn lookup(&self) -> impl Fn(Range<usize>) -> Result<Vec<StaticChunk<Suite>>, ()> + '_ {
        // `SrsLookup` is implemented for `&RingBuilderPcsParams`, not for the value.
        let params = &self.builder_params;
        move |range: Range<usize>| {
            params
                .lookup(range)
                .map(|chunks: Vec<_>| chunks.into_iter().map(|c| StaticChunk(c)).collect())
                .ok_or(())
        }
    }

    fn push(&self, intermediate: &mut Intermediate, range: Range<usize>) {
        VerifiableImpl::push_members(
            intermediate,
            self.members[range].iter().cloned(),
            self.lookup(),
        )
        .expect("fixture push_members");
    }

    /// Snapshot an `Intermediate` at each requested member count in a single pass.
    ///
    /// The counts are reached by pushing forward and cloning, so building templates for
    /// every fill level costs one traversal of the ring rather than one per level.
    fn templates(&self, counts: &[usize]) -> BTreeMap<usize, Intermediate> {
        let mut wanted: Vec<usize> = counts.to_vec();
        wanted.sort_unstable();
        wanted.dedup();

        let mut intermediate = VerifiableImpl::start_members(self.config);
        let mut pushed = 0usize;
        let mut out = BTreeMap::new();
        for count in wanted {
            if count > pushed {
                self.push(&mut intermediate, pushed..count);
                pushed = count;
            }
            out.insert(count, intermediate.clone());
        }
        out
    }

    fn commitment(&self, count: usize) -> Members {
        let mut intermediate = VerifiableImpl::start_members(self.config);
        if count > 0 {
            self.push(&mut intermediate, 0..count);
        }
        VerifiableImpl::finish_members(intermediate)
    }

    /// A proof from the member in the middle of a ring holding the first `count` members.
    fn proof(&self, count: usize, message: &[u8]) -> (Proof, Alias) {
        let target = count / 2;
        let commitment = VerifiableImpl::open(
            self.config,
            &self.members[target],
            self.members[..count].iter().cloned(),
        )
        .expect("fixture open");
        VerifiableImpl::create(commitment, &self.secrets[target], CONTEXT, message)
            .expect("fixture create")
    }
}

// ============================================================================
// Thermal canary
// ============================================================================

/// A fixed, cheap, *parallel* unit of work. Always domain11 regardless of which domain
/// block it is reported under, so all six readings in a run are directly comparable.
struct Canary {
    config: Config,
    proof: Proof,
    members: Members,
}

fn canary() -> &'static Canary {
    static CELL: OnceLock<Canary> = OnceLock::new();
    CELL.get_or_init(|| {
        let fx = DomainFixture::new(RingDomainSize::Domain11);
        let (proof, _alias) = fx.proof(fx.ring_size, MESSAGE);
        Canary {
            config: fx.config,
            proof,
            members: fx.commitment(fx.ring_size),
        }
    })
}

fn bench_canary(c: &mut Criterion, label: &str, tag: &str) {
    let canary = canary();
    let mut group = c.benchmark_group(label);
    medium(&mut group);
    group.bench_function(tag, |b| {
        b.iter(|| {
            let alias = VerifiableImpl::validate(
                black_box(canary.config),
                black_box(&canary.proof),
                black_box(&canary.members),
                black_box(CONTEXT),
                black_box(MESSAGE),
            )
            .expect("canary validate");
            black_box(alias);
        });
    });
    group.finish();
}

// ============================================================================
// Ring-independent and whole-ring operations
// ============================================================================

fn bench_verifiable_methods(c: &mut Criterion, fx: &DomainFixture) {
    // None of these read the ring size, so their three domain columns must agree.
    // Kept per-domain as a regression guard against a ring dependency creeping in.
    let mut group = c.benchmark_group(fx.label);
    cheap(&mut group);

    group.bench_function("start_members", |b| {
        b.iter(|| black_box(VerifiableImpl::start_members(black_box(fx.config))));
    });

    group.bench_function("new_secret", |b| {
        let mut index = 0usize;
        b.iter(|| {
            let entropy = entropy_from_index(index % fx.ring_size);
            index = index.wrapping_add(1);
            black_box(VerifiableImpl::new_secret(black_box(entropy)));
        });
    });

    let target = fx.ring_size / 2;
    let secret = &fx.secrets[target];
    let member = &fx.members[target];

    group.bench_function("member_from_secret", |b| {
        b.iter(|| black_box(VerifiableImpl::member_from_secret(black_box(secret))));
    });

    group.bench_function("sign", |b| {
        b.iter(|| {
            black_box(
                VerifiableImpl::sign(black_box(secret), black_box(MESSAGE)).expect("bench sign"),
            );
        });
    });

    group.bench_function("alias_in_context", |b| {
        b.iter(|| {
            black_box(
                VerifiableImpl::alias_in_context(black_box(secret), black_box(CONTEXT))
                    .expect("bench alias_in_context"),
            );
        });
    });

    let signature: Signature = VerifiableImpl::sign(secret, MESSAGE).expect("setup sign");
    group.bench_function("verify_signature", |b| {
        b.iter(|| {
            assert!(VerifiableImpl::verify_signature(
                black_box(&signature),
                black_box(MESSAGE),
                black_box(member),
            ));
        });
    });

    group.bench_function("is_member_valid", |b| {
        b.iter(|| assert!(VerifiableImpl::is_member_valid(black_box(member))));
    });

    group.finish();

    // Pushing the whole ring in one call reaches seconds at domain16, so it needs its
    // own sampling. Re-opening the group keeps the reported id unprefixed.
    let empty = VerifiableImpl::start_members(fx.config);
    let mut group = c.benchmark_group(fx.label);
    heavy(&mut group, fx.domain);
    group.bench_function("push_all_members_in_one_time", |b| {
        b.iter_batched_ref(
            || empty.clone(),
            |intermediate| {
                VerifiableImpl::push_members(
                    intermediate,
                    fx.members.iter().cloned(),
                    fx.lookup(),
                )
                .expect("bench push_members");
                black_box(&*intermediate);
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

// ============================================================================
// Ring fill levels
// ============================================================================

/// Everything needed to exercise the verifier side at one fill level.
struct FillLevel {
    count: usize,
    label: &'static str,
    commitment: Members,
    proof: Proof,
    alias: Alias,
}

fn bench_ring_fill_levels(c: &mut Criterion, fx: &DomainFixture) {
    let ring_size = fx.ring_size;

    let fill_levels: [(usize, &'static str); 5] = [
        (1.max(ring_size / 100), "nearly_empty"),
        (ring_size / 4, "quarter"),
        (ring_size / 2, "half"),
        (ring_size * 3 / 4, "three_quarters"),
        (ring_size, "full"),
    ];
    let push_levels: [(usize, &'static str); 5] = [
        (0, "empty"),
        (ring_size / 4, "quarter"),
        (ring_size / 2, "half"),
        (ring_size * 3 / 4, "three_quarters"),
        (ring_size - 1, "full_minus_one"),
    ];

    // One traversal of the ring produces every template both groups need.
    let template_counts: Vec<usize> = fill_levels
        .iter()
        .chain(push_levels.iter())
        .map(|(count, _)| *count)
        .collect();
    let templates = fx.templates(&template_counts);

    let levels: Vec<FillLevel> = fill_levels
        .iter()
        .map(|(count, label)| {
            let (proof, alias) = fx.proof(*count, MESSAGE);
            FillLevel {
                count: *count,
                label,
                commitment: VerifiableImpl::finish_members(templates[count].clone()),
                proof,
                alias,
            }
        })
        .collect();

    // --- push one member -----------------------------------------------------
    // Flat by construction: `Intermediate` is a fixed 848-byte accumulator, so this
    // is O(1) in the fill level. Guards against it becoming O(n).
    let mut group = c.benchmark_group(format!("{}/push_one_member_at_fill_level", fx.label));
    cheap(&mut group);
    for (fill_count, label) in push_levels.iter() {
        let template = &templates[fill_count];
        let next = &fx.members[*fill_count];
        group.bench_function(*label, |b| {
            b.iter_batched_ref(
                || template.clone(),
                |intermediate| {
                    VerifiableImpl::push_members(
                        intermediate,
                        std::iter::once(next.clone()),
                        fx.lookup(),
                    )
                    .expect("bench push_members");
                    black_box(&*intermediate);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();

    // --- finish members ------------------------------------------------------
    // Also flat by construction: `finish_members` just finalises the fixed-size
    // accumulator and reads the commitment out of it.
    let mut group = c.benchmark_group(format!("{}/finish_members_at_fill_level", fx.label));
    cheap(&mut group);
    for level in levels.iter() {
        let template = &templates[&level.count];
        group.bench_function(level.label, |b| {
            b.iter_batched(
                || template.clone(),
                |intermediate| {
                    black_box(VerifiableImpl::finish_members(black_box(intermediate)));
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();

    // --- validate ------------------------------------------------------------
    // Flat by construction: `validate` reads the 288-byte commitment, never the
    // member list. Only the domain size can move it.
    let mut group = c.benchmark_group(format!("{}/validate_at_fill_level", fx.label));
    medium(&mut group);
    for level in levels.iter() {
        group.bench_function(level.label, |b| {
            b.iter(|| {
                let alias = VerifiableImpl::validate(
                    black_box(fx.config),
                    black_box(&level.proof),
                    black_box(&level.commitment),
                    black_box(CONTEXT),
                    black_box(MESSAGE),
                )
                .expect("bench validate");
                black_box(alias);
            });
        });
    }
    group.finish();

    // --- is_valid ------------------------------------------------------------
    // `is_valid` is the default trait method: `validate` plus a 32-byte comparison.
    // Benchmarked to catch it diverging from `validate_at_fill_level`.
    let mut group = c.benchmark_group(format!("{}/is_valid_at_fill_level", fx.label));
    medium(&mut group);
    for level in levels.iter() {
        group.bench_function(level.label, |b| {
            b.iter(|| {
                assert!(VerifiableImpl::is_valid(
                    black_box(fx.config),
                    black_box(&level.proof),
                    black_box(&level.commitment),
                    black_box(CONTEXT),
                    black_box(&level.alias),
                    black_box(MESSAGE),
                ));
            });
        });
    }
    group.finish();

    cooldown();

    // --- open ----------------------------------------------------------------
    // The online half of the prover, and one of the two groups here that genuinely
    // scales with the fill level.
    let mut group = c.benchmark_group(format!("{}/open_at_fill_level", fx.label));
    heavy(&mut group, fx.domain);
    for level in levels.iter() {
        let members = &fx.members[..level.count];
        let target = &fx.members[level.count / 2];
        group.bench_function(level.label, |b| {
            b.iter(|| {
                black_box(
                    VerifiableImpl::open(
                        black_box(fx.config),
                        black_box(target),
                        black_box(members).iter().cloned(),
                    )
                    .expect("bench open"),
                );
            });
        });
    }
    group.finish();

    cooldown();

    // --- open + create -------------------------------------------------------
    // The full wallet-side cost of producing a proof. Subtract `open_at_fill_level`
    // to recover the air-gapped `create` half on its own.
    let mut group = c.benchmark_group(format!("{}/open_and_create_at_fill_level", fx.label));
    heavy(&mut group, fx.domain);
    for level in levels.iter() {
        let members = &fx.members[..level.count];
        let target_idx = level.count / 2;
        group.bench_function(level.label, |b| {
            b.iter(|| {
                let commitment = VerifiableImpl::open(
                    black_box(fx.config),
                    black_box(&fx.members[target_idx]),
                    black_box(members).iter().cloned(),
                )
                .expect("bench open");
                black_box(
                    VerifiableImpl::create(
                        black_box(commitment),
                        black_box(&fx.secrets[target_idx]),
                        black_box(CONTEXT),
                        black_box(MESSAGE),
                    )
                    .expect("bench create"),
                );
            });
        });
    }
    group.finish();
}

// ============================================================================
// Batch validation
// ============================================================================

/// Every proof against the *same* ring.
///
/// `batch_validate` reuses its `RingVerifier` across consecutive items that share a
/// ring, so this builds one verifier for the whole batch — the best case.
fn single_ring_items(fx: &DomainFixture, count: usize) -> Vec<BatchProofItemFor<VerifiableImpl>> {
    let ring_size = fx.ring_size;
    let commitment = fx.commitment(ring_size);

    (0..count)
        .map(|i| {
            // Spread the provers over the ring and give each proof its own message so
            // no two items in the batch are identical.
            let member_idx = (i * ring_size / count) % ring_size;
            let message = format!("batch message {i}").into_bytes();
            let opened = VerifiableImpl::open(
                fx.config,
                &fx.members[member_idx],
                fx.members.iter().cloned(),
            )
            .expect("single_ring open");
            let (proof, _alias) =
                VerifiableImpl::create(opened, &fx.secrets[member_idx], CONTEXT, &message)
                    .expect("single_ring create");
            BatchProofItem {
                proof,
                config: fx.config,
                members: commitment.clone(),
                context: CONTEXT.to_vec(),
                message,
            }
        })
        .collect()
}

/// Every proof against a *different* ring, forcing a verifier rebuild per item.
///
/// The rings differ in how many members they hold, which is the cheapest way to get
/// distinct commitments: verifier construction cost depends on the domain, not on the
/// member count, so this isolates the rebuild without changing anything else. The
/// commitments come from a single traversal of the member pool.
fn multi_ring_items(fx: &DomainFixture, count: usize) -> Vec<BatchProofItemFor<VerifiableImpl>> {
    let ring_size = fx.ring_size;
    // Strictly increasing, always >= 2 members, spread across the whole ring.
    let counts: Vec<usize> = (0..count)
        .map(|i| 2 + (i * (ring_size - 2)) / count)
        .collect();

    let mut intermediate = VerifiableImpl::start_members(fx.config);
    let mut pushed = 0usize;
    let mut items = Vec::with_capacity(count);

    for (i, &ring_count) in counts.iter().enumerate() {
        if ring_count > pushed {
            fx.push(&mut intermediate, pushed..ring_count);
            pushed = ring_count;
        }
        let commitment = VerifiableImpl::finish_members(intermediate.clone());

        let member_idx = ring_count / 2;
        let message = format!("batch message {i}").into_bytes();
        let opened = VerifiableImpl::open(
            fx.config,
            &fx.members[member_idx],
            fx.members[..ring_count].iter().cloned(),
        )
        .expect("multi_ring open");
        let (proof, _alias) =
            VerifiableImpl::create(opened, &fx.secrets[member_idx], CONTEXT, &message)
                .expect("multi_ring create");

        items.push(BatchProofItem {
            proof,
            config: fx.config,
            members: commitment,
            context: CONTEXT.to_vec(),
            message,
        });
    }
    items
}

type ItemsFn = fn(&DomainFixture, usize) -> Vec<BatchProofItemFor<VerifiableImpl>>;

fn bench_batch_validate(c: &mut Criterion, fx: &DomainFixture) {
    let max_batch = *BATCH_SIZES.last().expect("BATCH_SIZES is not empty");

    for (flavour, build_items) in [
        ("single_ring", single_ring_items as ItemsFn),
        ("multi_ring", multi_ring_items as ItemsFn),
    ] {
        // Built one flavour at a time, and cooled down afterwards: generating 128
        // proofs is itself minutes of full-load `open`/`create` at domain16, so doing
        // both up front would leave the CPU hot for the measurements that follow.
        let items = build_items(fx, max_batch);
        cooldown();

        let mut group =
            c.benchmark_group(format!("{}/batch_validate/{flavour}", fx.label));
        heavy(&mut group, fx.domain);
        for &batch_size in &BATCH_SIZES {
            let batch = &items[..batch_size];
            group.bench_function(format!("{batch_size}"), |b| {
                b.iter(|| {
                    let aliases = VerifiableImpl::batch_validate(black_box(batch))
                        .expect("bench batch_validate");
                    black_box(aliases);
                });
            });
        }
        group.finish();
    }
}

// ============================================================================
// Entry points
// ============================================================================

/// Criterion's name filter only skips the *measurement*, not the fixture building that
/// precedes it — and at domain16 that fixture work runs into minutes. `BENCH_DOMAINS`
/// (comma-separated, e.g. `BENCH_DOMAINS=domain11`) skips whole domains up front.
fn domain_selected(label: &str) -> bool {
    match std::env::var("BENCH_DOMAINS") {
        Ok(value) => value.split(',').map(str::trim).any(|d| d == label),
        Err(_) => true,
    }
}

fn bench_domain(c: &mut Criterion, domain: RingDomainSize) {
    let label = domain_label(domain);
    if !domain_selected(label) {
        return;
    }
    init_thread_pool();

    bench_canary(c, label, "canary_before");
    cooldown();

    let fx = DomainFixture::new(domain);
    bench_verifiable_methods(c, &fx);
    bench_ring_fill_levels(c, &fx);
    bench_batch_validate(c, &fx);

    cooldown();
    bench_canary(c, label, "canary_after");
}

fn bench_domain11(c: &mut Criterion) {
    bench_domain(c, RingDomainSize::Domain11);
}

fn bench_domain12(c: &mut Criterion) {
    bench_domain(c, RingDomainSize::Domain12);
}

fn bench_domain16(c: &mut Criterion) {
    bench_domain(c, RingDomainSize::Domain16);
}

criterion_group!(benches, bench_domain11, bench_domain12, bench_domain16);
criterion_main!(benches);
