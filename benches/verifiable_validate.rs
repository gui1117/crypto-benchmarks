use std::{ops::Range, sync::Arc};

use verifiable::ring::ark_vrf;
use ark_vrf::ring::SrsLookup;
use ark_vrf::suites::bandersnatch::BandersnatchSha512Ell2;

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
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

fn domain_label(domain: RingDomainSize) -> &'static str {
    match domain {
        RingDomainSize::Domain11 => "domain11",
        RingDomainSize::Domain12 => "domain12",
        RingDomainSize::Domain16 => "domain16",
    }
}

struct MethodBenchContext {
    config: Config,
    ring_size: usize,
    builder_params: Arc<BuilderParams>,
    empty_intermediate: Intermediate,
    members_template: Intermediate,
    members_commitment: Members,
    members: Vec<Member>,
    entropies: Vec<Entropy>,
    context_bytes: Vec<u8>,
    message_bytes: Vec<u8>,
    target_secret: Secret,
    target_member: Member,
    proof: Proof,
    alias: Alias,
    signature: Signature,
}

impl MethodBenchContext {
    fn new(domain: RingDomainSize) -> Self {
        let config: Config = domain;
        let ring_size = domain.max_ring_size::<Suite>();
        let builder_params = Arc::new(ring_verifier_builder_params::<Suite>(domain));

        let entropies = (0..ring_size)
            .map(entropy_from_index)
            .collect::<Vec<Entropy>>();

        let secrets = entropies
            .iter()
            .map(|&entropy| VerifiableImpl::new_secret(entropy))
            .collect::<Vec<Secret>>();

        let members = secrets
            .iter()
            .map(VerifiableImpl::member_from_secret)
            .collect::<Vec<Member>>();

        let empty_intermediate = VerifiableImpl::start_members(config);
        let mut members_filled = empty_intermediate.clone();
        {
            let setup_builder_params = Arc::clone(&builder_params);
            VerifiableImpl::push_members(
                &mut members_filled,
                members.iter().cloned(),
                move |range: Range<usize>| {
                    setup_builder_params
                        .as_ref()
                        .lookup(range)
                        .map(|chunks: Vec<_>| chunks.into_iter().map(|c| StaticChunk(c)).collect())
                        .ok_or(())
                },
            )
            .expect("context setup push_members");
        }
        let members_template = members_filled.clone();
        let members_commitment = VerifiableImpl::finish_members(members_filled);

        let target_index = ring_size / 2;
        let target_secret = secrets[target_index].clone();
        let target_member = members[target_index].clone();

        let commitment =
            VerifiableImpl::open(config, &target_member, members.iter().cloned())
                .expect("context open");

        let context_bytes = b"verifiable-bench-context".to_vec();
        let message_bytes = b"benchmark message for verifiable trait".to_vec();

        let (proof, alias) = VerifiableImpl::create(
            commitment,
            &target_secret,
            context_bytes.as_slice(),
            message_bytes.as_slice(),
        )
        .expect("context create");

        let signature =
            VerifiableImpl::sign(&target_secret, message_bytes.as_slice()).expect("context sign");

        MethodBenchContext {
            config,
            ring_size,
            builder_params,
            empty_intermediate,
            members_template,
            members_commitment,
            members,
            entropies,
            context_bytes,
            message_bytes,
            target_secret,
            target_member,
            proof,
            alias,
            signature,
        }
    }
}

fn entropy_from_index(idx: usize) -> Entropy {
    let mut entropy = [0u8; 32];
    entropy[0..4].copy_from_slice(&(idx as u32).to_le_bytes());
    entropy
}

fn build_members_template_with_size(
    ring_size: usize,
    builder_params: &BuilderParams,
    config: Config,
) -> Intermediate {
    let mut intermediate = VerifiableImpl::start_members(config);
    VerifiableImpl::push_members(
        &mut intermediate,
        (0..ring_size).map(|i| {
            let secret = VerifiableImpl::new_secret(entropy_from_index(i));
            VerifiableImpl::member_from_secret(&secret)
        }),
        |range: Range<usize>| {
            builder_params
                .lookup(range)
                .map(|chunks: Vec<_>| chunks.into_iter().map(|c| StaticChunk(c)).collect())
                .ok_or(())
        },
    )
    .expect("build_members_template_with_size push_members");
    intermediate
}

fn bench_verifiable_methods(c: &mut Criterion, domain: RingDomainSize) {
    let label = domain_label(domain);
    let ctx = MethodBenchContext::new(domain);
    let ring_size = ctx.ring_size;

    {
        let config = ctx.config;
        c.bench_function(&format!("{label}/start_members"), move |b| {
            b.iter(|| black_box(VerifiableImpl::start_members(black_box(config))));
        });
    }

    // Push many members into a fresh intermediate
    {
        let builder_params = Arc::clone(&ctx.builder_params);
        let members = ctx.members.clone();
        let empty_intermediate = ctx.empty_intermediate.clone();
        c.bench_function(
            &format!("{label}/push_all_members_in_one_time"),
            move |b| {
                b.iter_batched_ref(
                    || empty_intermediate.clone(),
                    |intermediate| {
                        VerifiableImpl::push_members(
                            intermediate,
                            members.iter().cloned(),
                            |range: Range<usize>| {
                                builder_params
                                    .as_ref()
                                    .lookup(range)
                                    .map(|chunks| {
                                        chunks.into_iter().map(|c| StaticChunk(c)).collect()
                                    })
                                    .ok_or(())
                            },
                        )
                        .expect("bench push_members");
                        black_box(&*intermediate);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    // Push 1 member into an almost-full intermediate
    {
        let builder_params = Arc::clone(&ctx.builder_params);
        let members = Arc::new(ctx.members.clone());
        let config = ctx.config;
        let full_minus_one_template = {
            let mut intermediate = VerifiableImpl::start_members(config);
            VerifiableImpl::push_members(
                &mut intermediate,
                (0..ring_size - 1).map(|i| members[i].clone()),
                |range: Range<usize>| {
                    builder_params
                        .as_ref()
                        .lookup(range)
                        .map(|chunks: Vec<_>| chunks.into_iter().map(|c| StaticChunk(c)).collect())
                        .ok_or(())
                },
            )
            .expect("build full_minus_one_template push_members");
            intermediate
        };
        let builder_params = Arc::clone(&ctx.builder_params);
        let bench_template = Arc::new(full_minus_one_template);
        c.bench_function(
            &format!("{label}/push_one_member_in_almost_full"),
            move |b| {
                let members = Arc::clone(&members);
                let builder_params = Arc::clone(&builder_params);
                let bench_template = Arc::clone(&bench_template);
                b.iter_batched_ref(
                    || bench_template.as_ref().clone(),
                    |intermediate| {
                        VerifiableImpl::push_members(
                            intermediate,
                            std::iter::once(members[ring_size - 1].clone()),
                            |range: Range<usize>| {
                                builder_params
                                    .as_ref()
                                    .lookup(range)
                                    .map(|chunks| {
                                        chunks.into_iter().map(|c| StaticChunk(c)).collect()
                                    })
                                    .ok_or(())
                            },
                        )
                        .expect("bench push_members");
                        black_box(&*intermediate);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    // Finish a prepared template
    {
        let members_template = ctx.members_template.clone();
        c.bench_function(&format!("{label}/finish_members"), move |b| {
            b.iter_batched(
                || members_template.clone(),
                |intermediate| {
                    let members = VerifiableImpl::finish_members(black_box(intermediate));
                    black_box(members);
                },
                BatchSize::SmallInput,
            );
        });
    }

    // Finish a fully prepared (full) template
    {
        let builder_params = Arc::clone(&ctx.builder_params);
        let config = ctx.config;
        let full = Arc::new(build_members_template_with_size(
            ring_size,
            builder_params.as_ref(),
            config,
        ));
        c.bench_function(&format!("{label}/finish_members_full"), move |b| {
            let bench_template = Arc::clone(&full);
            b.iter_batched(
                || bench_template.as_ref().clone(),
                |intermediate| {
                    let members = VerifiableImpl::finish_members(black_box(intermediate));
                    black_box(members);
                },
                BatchSize::SmallInput,
            );
        });
    }

    // Secret generation
    {
        let entropies = ctx.entropies.clone();
        c.bench_function(&format!("{label}/new_secret"), move |b| {
            let mut index = 0usize;
            b.iter(|| {
                let entropy = entropies[index % entropies.len()];
                index = index.wrapping_add(1);
                let secret = VerifiableImpl::new_secret(black_box(entropy));
                black_box(secret);
            });
        });
    }

    // Member from secret
    {
        let secret = ctx.target_secret.clone();
        c.bench_function(&format!("{label}/member_from_secret"), move |b| {
            b.iter(|| {
                let member = VerifiableImpl::member_from_secret(black_box(&secret));
                black_box(member);
            });
        });
    }

    // Open commitment
    {
        let members = ctx.members.clone();
        let target_member = ctx.target_member.clone();
        let config = ctx.config;
        c.bench_function(&format!("{label}/open"), move |b| {
            b.iter(|| {
                let commitment = VerifiableImpl::open(
                    black_box(config),
                    black_box(&target_member),
                    black_box(&members).iter().cloned(),
                )
                .expect("bench open");
                black_box(commitment);
            });
        });
    }

    // Create proof
    {
        let target_secret = ctx.target_secret.clone();
        let context_bytes = ctx.context_bytes.clone();
        let message_bytes = ctx.message_bytes.clone();
        let members = ctx.members.clone();
        let target_member = ctx.target_member.clone();
        let config = ctx.config;
        c.bench_function(&format!("{label}/create"), move |b| {
            b.iter(|| {
                let commitment = VerifiableImpl::open(
                    black_box(config),
                    black_box(&target_member),
                    black_box(&members).iter().cloned(),
                )
                .expect("bench create open");
                let result = VerifiableImpl::create(
                    black_box(commitment),
                    black_box(&target_secret),
                    black_box(context_bytes.as_slice()),
                    black_box(message_bytes.as_slice()),
                )
                .expect("bench create");
                black_box(result);
            });
        });
    }

    // Sign
    {
        let target_secret = ctx.target_secret.clone();
        let message_bytes = ctx.message_bytes.clone();
        c.bench_function(&format!("{label}/sign"), move |b| {
            b.iter(|| {
                let signature = VerifiableImpl::sign(
                    black_box(&target_secret),
                    black_box(message_bytes.as_slice()),
                )
                .expect("bench sign");
                black_box(signature);
            });
        });
    }

    // Alias in context
    {
        let target_secret = ctx.target_secret.clone();
        let context_bytes = ctx.context_bytes.clone();
        c.bench_function(&format!("{label}/alias_in_context"), move |b| {
            b.iter(|| {
                let alias = VerifiableImpl::alias_in_context(
                    black_box(&target_secret),
                    black_box(context_bytes.as_slice()),
                )
                .expect("bench alias_in_context");
                black_box(alias);
            });
        });
    }

    // Validate proof
    {
        let proof = ctx.proof.clone();
        let members_commitment = ctx.members_commitment.clone();
        let context_bytes = ctx.context_bytes.clone();
        let message_bytes = ctx.message_bytes.clone();
        let config = ctx.config;
        c.bench_function(&format!("{label}/validate"), move |b| {
            b.iter(|| {
                let alias = VerifiableImpl::validate(
                    black_box(config),
                    black_box(&proof),
                    black_box(&members_commitment),
                    black_box(context_bytes.as_slice()),
                    black_box(message_bytes.as_slice()),
                )
                .expect("bench validate");
                black_box(alias);
            });
        });
    }

    // Is valid?
    {
        let proof = ctx.proof.clone();
        let members_commitment = ctx.members_commitment.clone();
        let alias = ctx.alias;
        let context_bytes = ctx.context_bytes.clone();
        let message_bytes = ctx.message_bytes.clone();
        let config = ctx.config;
        c.bench_function(&format!("{label}/is_valid"), move |b| {
            b.iter(|| {
                let valid = VerifiableImpl::is_valid(
                    black_box(config),
                    black_box(&proof),
                    black_box(&members_commitment),
                    black_box(context_bytes.as_slice()),
                    black_box(&alias),
                    black_box(message_bytes.as_slice()),
                );
                assert!(valid);
            });
        });
    }

    // Verify signature
    {
        let signature = ctx.signature.clone();
        let message_bytes = ctx.message_bytes.clone();
        let member = ctx.target_member.clone();
        c.bench_function(&format!("{label}/verify_signature"), move |b| {
            b.iter(|| {
                let valid = VerifiableImpl::verify_signature(
                    black_box(&signature),
                    black_box(message_bytes.as_slice()),
                    black_box(&member),
                );
                assert!(valid);
            });
        });
    }

    // Member validity
    {
        let member = ctx.target_member.clone();
        c.bench_function(&format!("{label}/is_member_valid"), move |b| {
            b.iter(|| {
                let valid = VerifiableImpl::is_member_valid(black_box(&member));
                assert!(valid);
            });
        });
    }
}

/// Context for benchmarking at a specific ring fill level
struct FillLevelContext {
    config: Config,
    fill_count: usize,
    label: &'static str,
    members: Vec<Member>,
    members_commitment: Members,
    target_secret: Secret,
    target_member: Member,
    proof: Proof,
    alias: Alias,
    context_bytes: Vec<u8>,
    message_bytes: Vec<u8>,
}

impl FillLevelContext {
    fn new(
        fill_count: usize,
        label: &'static str,
        builder_params: &BuilderParams,
        config: Config,
    ) -> Self {
        let entropies: Vec<Entropy> = (0..fill_count).map(entropy_from_index).collect();

        let secrets: Vec<Secret> = entropies
            .iter()
            .map(|&e| VerifiableImpl::new_secret(e))
            .collect();

        let members: Vec<Member> = secrets
            .iter()
            .map(VerifiableImpl::member_from_secret)
            .collect();

        // Build the intermediate and finish it to get members_commitment
        let mut intermediate = VerifiableImpl::start_members(config);
        VerifiableImpl::push_members(
            &mut intermediate,
            members.iter().cloned(),
            |range: Range<usize>| {
                builder_params
                    .lookup(range)
                    .map(|chunks: Vec<_>| chunks.into_iter().map(|c| StaticChunk(c)).collect())
                    .ok_or(())
            },
        )
        .expect("fill level context setup");
        let members_commitment = VerifiableImpl::finish_members(intermediate);

        // Target is in the middle of the ring
        let target_index = fill_count / 2;
        let target_secret = secrets[target_index].clone();
        let target_member = members[target_index].clone();

        let context_bytes = b"verifiable-bench-context".to_vec();
        let message_bytes = b"benchmark message for verifiable trait".to_vec();

        // Create proof for this fill level
        let commitment =
            VerifiableImpl::open(config, &target_member, members.iter().cloned())
                .expect("context open");
        let (proof, alias) = VerifiableImpl::create(
            commitment,
            &target_secret,
            context_bytes.as_slice(),
            message_bytes.as_slice(),
        )
        .expect("context create");

        FillLevelContext {
            config,
            fill_count,
            label,
            members,
            members_commitment,
            target_secret,
            target_member,
            proof,
            alias,
            context_bytes,
            message_bytes,
        }
    }
}

fn bench_ring_fill_levels(c: &mut Criterion, domain: RingDomainSize) {
    let dlabel = domain_label(domain);
    let config: Config = domain;
    let ring_size = domain.max_ring_size::<Suite>();
    let builder_params = Arc::new(ring_verifier_builder_params::<Suite>(domain));

    // Define fill levels (must have at least 1 member for most operations)
    let fill_levels: &[(usize, &'static str)] = &[
        (1.max(ring_size / 100), "nearly_empty"),
        (ring_size / 4, "quarter"),
        (ring_size / 2, "half"),
        (ring_size * 3 / 4, "three_quarters"),
        (ring_size, "full"),
    ];

    // Pre-build contexts for each fill level
    let contexts: Vec<FillLevelContext> = fill_levels
        .iter()
        .map(|(count, label)| {
            FillLevelContext::new(*count, label, builder_params.as_ref(), config)
        })
        .collect();

    // Generate all members for push benchmarks
    let all_members: Vec<Member> = (0..ring_size)
        .map(|i| {
            let secret = VerifiableImpl::new_secret(entropy_from_index(i));
            VerifiableImpl::member_from_secret(&secret)
        })
        .collect();

    // ===== push_one_member benchmarks =====
    let push_fill_levels = [
        (0, "empty"),
        (ring_size / 4, "quarter"),
        (ring_size / 2, "half"),
        (ring_size * 3 / 4, "three_quarters"),
        (ring_size - 1, "full_minus_one"),
    ];

    let mut group = c.benchmark_group(format!("{dlabel}/push_one_member_at_fill_level"));
    for (fill_count, label) in push_fill_levels.iter() {
        let builder_params = Arc::clone(&builder_params);
        let members = all_members.clone();

        let template = {
            let mut intermediate = VerifiableImpl::start_members(config);
            if *fill_count > 0 {
                VerifiableImpl::push_members(
                    &mut intermediate,
                    (0..*fill_count).map(|i| members[i].clone()),
                    |range: Range<usize>| {
                        builder_params
                            .as_ref()
                            .lookup(range)
                            .map(|chunks: Vec<_>| chunks.into_iter().map(|c| StaticChunk(c)).collect())
                            .ok_or(())
                    },
                )
                .expect("template setup");
            }
            intermediate
        };

        let template = Arc::new(template);
        let builder_params = Arc::clone(&builder_params);
        let next_member = members[*fill_count].clone();

        group.bench_function(*label, move |b| {
            let template = Arc::clone(&template);
            let builder_params = Arc::clone(&builder_params);
            let next_member = next_member.clone();
            b.iter_batched_ref(
                || template.as_ref().clone(),
                |intermediate| {
                    VerifiableImpl::push_members(
                        intermediate,
                        std::iter::once(next_member.clone()),
                        |range: Range<usize>| {
                            builder_params
                                .as_ref()
                                .lookup(range)
                                .map(|chunks| {
                                    chunks.into_iter().map(|c| StaticChunk(c)).collect()
                                })
                                .ok_or(())
                        },
                    )
                    .expect("bench push_members");
                    black_box(&*intermediate);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();

    // ===== finish_members benchmarks =====
    let mut group = c.benchmark_group(format!("{dlabel}/finish_members_at_fill_level"));
    for ctx in contexts.iter() {
        let builder_params = Arc::clone(&builder_params);
        let members = ctx.members.clone();
        let fill_count = ctx.fill_count;

        let template = {
            let mut intermediate = VerifiableImpl::start_members(config);
            VerifiableImpl::push_members(
                &mut intermediate,
                (0..fill_count).map(|i| members[i].clone()),
                |range: Range<usize>| {
                    builder_params
                        .as_ref()
                        .lookup(range)
                        .map(|chunks: Vec<_>| chunks.into_iter().map(|c| StaticChunk(c)).collect())
                        .ok_or(())
                },
            )
            .expect("template setup");
            intermediate
        };

        let template = Arc::new(template);
        let label = ctx.label;

        group.bench_function(label, move |b| {
            let template = Arc::clone(&template);
            b.iter_batched(
                || template.as_ref().clone(),
                |intermediate| {
                    let members = VerifiableImpl::finish_members(black_box(intermediate));
                    black_box(members);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();

    // ===== open benchmarks =====
    let mut group = c.benchmark_group(format!("{dlabel}/open_at_fill_level"));
    for ctx in contexts.iter() {
        let members = ctx.members.clone();
        let target_member = ctx.target_member.clone();
        let label = ctx.label;
        let config = ctx.config;

        group.bench_function(label, move |b| {
            b.iter(|| {
                let commitment = VerifiableImpl::open(
                    black_box(config),
                    black_box(&target_member),
                    black_box(&members).iter().cloned(),
                )
                .expect("bench open");
                black_box(commitment);
            });
        });
    }
    group.finish();

    // ===== create benchmarks =====
    let mut group = c.benchmark_group(format!("{dlabel}/create_at_fill_level"));
    for ctx in contexts.iter() {
        let members = ctx.members.clone();
        let target_member = ctx.target_member.clone();
        let target_secret = ctx.target_secret.clone();
        let context_bytes = ctx.context_bytes.clone();
        let message_bytes = ctx.message_bytes.clone();
        let label = ctx.label;
        let config = ctx.config;

        group.bench_function(label, move |b| {
            b.iter(|| {
                let commitment = VerifiableImpl::open(
                    black_box(config),
                    black_box(&target_member),
                    black_box(&members).iter().cloned(),
                )
                .expect("bench create open");
                let result = VerifiableImpl::create(
                    black_box(commitment),
                    black_box(&target_secret),
                    black_box(context_bytes.as_slice()),
                    black_box(message_bytes.as_slice()),
                )
                .expect("bench create");
                black_box(result);
            });
        });
    }
    group.finish();

    // ===== validate benchmarks =====
    let mut group = c.benchmark_group(format!("{dlabel}/validate_at_fill_level"));
    for ctx in contexts.iter() {
        let proof = ctx.proof.clone();
        let members_commitment = ctx.members_commitment.clone();
        let context_bytes = ctx.context_bytes.clone();
        let message_bytes = ctx.message_bytes.clone();
        let label = ctx.label;
        let config = ctx.config;

        group.bench_function(label, move |b| {
            b.iter(|| {
                let alias = VerifiableImpl::validate(
                    black_box(config),
                    black_box(&proof),
                    black_box(&members_commitment),
                    black_box(context_bytes.as_slice()),
                    black_box(message_bytes.as_slice()),
                )
                .expect("bench validate");
                black_box(alias);
            });
        });
    }
    group.finish();

    // ===== is_valid benchmarks =====
    let mut group = c.benchmark_group(format!("{dlabel}/is_valid_at_fill_level"));
    for ctx in contexts.iter() {
        let proof = ctx.proof.clone();
        let members_commitment = ctx.members_commitment.clone();
        let alias = ctx.alias;
        let context_bytes = ctx.context_bytes.clone();
        let message_bytes = ctx.message_bytes.clone();
        let label = ctx.label;
        let config = ctx.config;

        group.bench_function(label, move |b| {
            b.iter(|| {
                let valid = VerifiableImpl::is_valid(
                    black_box(config),
                    black_box(&proof),
                    black_box(&members_commitment),
                    black_box(context_bytes.as_slice()),
                    black_box(&alias),
                    black_box(message_bytes.as_slice()),
                );
                assert!(valid);
            });
        });
    }
    group.finish();
}

/// Context for benchmarking batch validation
struct BatchValidateContext {
    batch_items: Vec<BatchProofItemFor<VerifiableImpl>>,
}

impl BatchValidateContext {
    fn new(domain: RingDomainSize, num_proofs: usize) -> Self {
        let config: Config = domain;
        let ring_size = domain.max_ring_size::<Suite>();

        // Generate all members for the ring
        let entropies: Vec<Entropy> = (0..ring_size).map(entropy_from_index).collect();
        let secrets: Vec<Secret> = entropies
            .iter()
            .map(|&e| VerifiableImpl::new_secret(e))
            .collect();
        let members: Vec<Member> = secrets
            .iter()
            .map(VerifiableImpl::member_from_secret)
            .collect();

        // Build members commitment
        let builder_params = Arc::new(ring_verifier_builder_params::<Suite>(domain));
        let mut intermediate = VerifiableImpl::start_members(config);
        {
            let builder_params = Arc::clone(&builder_params);
            VerifiableImpl::push_members(
                &mut intermediate,
                members.iter().cloned(),
                move |range: Range<usize>| {
                    builder_params
                        .as_ref()
                        .lookup(range)
                        .map(|chunks: Vec<_>| chunks.into_iter().map(|c| StaticChunk(c)).collect())
                        .ok_or(())
                },
            )
            .expect("batch context push_members");
        }
        let members_commitment = VerifiableImpl::finish_members(intermediate);

        // Generate proofs for different members with unique messages
        let context_bytes = b"batch-verify-context".to_vec();
        let mut batch_items = Vec::with_capacity(num_proofs);

        for i in 0..num_proofs {
            // Use different members from the ring for each proof
            let member_idx = (i * ring_size / num_proofs) % ring_size;
            let secret = &secrets[member_idx];
            let member = &members[member_idx];

            // Unique message for each proof
            let message = format!("batch message {}", i).into_bytes();

            // Create commitment and proof
            let commitment =
                VerifiableImpl::open(config, member, members.iter().cloned())
                    .expect("batch context open");
            let (proof, _alias) = VerifiableImpl::create(
                commitment,
                secret,
                context_bytes.as_slice(),
                message.as_slice(),
            )
            .expect("batch context create");

            batch_items.push(BatchProofItem {
                proof,
                config,
                members: members_commitment.clone(),
                context: context_bytes.clone(),
                message,
            });
        }

        BatchValidateContext { batch_items }
    }
}

fn bench_batch_validate(c: &mut Criterion, domain: RingDomainSize) {
    let label = domain_label(domain);
    let batch_sizes: [usize; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

    // Pre-generate context with 128 proofs (max batch size)
    let ctx = BatchValidateContext::new(domain, 128);

    let mut group = c.benchmark_group(format!("{label}/batch_validate"));

    for &batch_size in &batch_sizes {
        let batch_items: Vec<BatchProofItemFor<VerifiableImpl>> =
            ctx.batch_items[..batch_size].to_vec();

        group.bench_function(format!("{batch_size}"), move |b| {
            b.iter(|| {
                let aliases = VerifiableImpl::batch_validate(black_box(&batch_items))
                    .expect("batch_validate");
                black_box(aliases);
            });
        });
    }
    group.finish();
}

fn bench_domain11(c: &mut Criterion) {
    bench_verifiable_methods(c, RingDomainSize::Domain11);
    bench_ring_fill_levels(c, RingDomainSize::Domain11);
    bench_batch_validate(c, RingDomainSize::Domain11);
}

fn bench_domain12(c: &mut Criterion) {
    bench_verifiable_methods(c, RingDomainSize::Domain12);
    bench_ring_fill_levels(c, RingDomainSize::Domain12);
    bench_batch_validate(c, RingDomainSize::Domain12);
}

fn bench_domain16(c: &mut Criterion) {
    bench_verifiable_methods(c, RingDomainSize::Domain16);
    bench_ring_fill_levels(c, RingDomainSize::Domain16);
    bench_batch_validate(c, RingDomainSize::Domain16);
}

criterion_group!(benches, bench_domain11, bench_domain12, bench_domain16);
criterion_main!(benches);
