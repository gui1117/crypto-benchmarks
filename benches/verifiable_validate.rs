use std::{ops::Range, sync::Arc};
use ressai::RING_SIZE;

use ark_vrf::ring::SrsLookup;
use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use verifiable::ring_vrf_impl::{
    BandersnatchVrfVerifiable, RingBuilderParams, StaticChunk, ring_verifier_builder_params,
};
use verifiable::{Alias, Entropy, GenerateVerifiable};

type VerifiableImpl = BandersnatchVrfVerifiable;
type Intermediate = <VerifiableImpl as GenerateVerifiable>::Intermediate;
type Members = <VerifiableImpl as GenerateVerifiable>::Members;
type Member = <VerifiableImpl as GenerateVerifiable>::Member;
type Secret = <VerifiableImpl as GenerateVerifiable>::Secret;
type Proof = <VerifiableImpl as GenerateVerifiable>::Proof;
type Signature = <VerifiableImpl as GenerateVerifiable>::Signature;

struct MethodBenchContext {
    builder_params: Arc<RingBuilderParams>,
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
    fn new(ring_size: usize) -> Self {
        let builder_params = Arc::new(ring_verifier_builder_params());

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

        let empty_intermediate = VerifiableImpl::start_members();
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
                        .map(|chunks| chunks.into_iter().map(StaticChunk).collect())
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
            VerifiableImpl::open(&target_member, members.iter().cloned()).expect("context open");

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
    builder_params: &RingBuilderParams,
) -> Intermediate {
    let mut intermediate = VerifiableImpl::start_members();
    VerifiableImpl::push_members(
        &mut intermediate,
        (0..ring_size).map(|i| {
            let secret = VerifiableImpl::new_secret(entropy_from_index(i));
            VerifiableImpl::member_from_secret(&secret)
        }),
        |range: Range<usize>| {
            builder_params
                .lookup(range)
                .map(|chunks| chunks.into_iter().map(StaticChunk).collect())
                .ok_or(())
        },
    )
    .expect("build_members_template_with_size push_members");
    intermediate
}

fn bench_verifiable_methods(c: &mut Criterion) {
    let ctx = MethodBenchContext::new(RING_SIZE);

    c.bench_function("verifiable_start_members", |b| {
        b.iter(|| black_box(VerifiableImpl::start_members()));
    });

    // Push many members into a fresh intermediate
    {
        let builder_params = Arc::clone(&ctx.builder_params);
        let members = ctx.members.clone();
        let empty_intermediate = ctx.empty_intermediate.clone();
        c.bench_function("verifiable_push_all_members_in_one_time", move |b| {
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
                                .map(|chunks| chunks.into_iter().map(StaticChunk).collect())
                                .ok_or(())
                        },
                    )
                    .expect("bench push_members");
                    // Keep the result alive:
                    black_box(&*intermediate);
                },
                BatchSize::SmallInput,
            );
        });
    }

    // Push 1 member into an almost-full intermediate
    {
        let builder_params = Arc::clone(&ctx.builder_params);
        let members = Arc::new(ctx.members.clone());
        let full_minus_one_template = {
            let mut intermediate = VerifiableImpl::start_members();
            VerifiableImpl::push_members(
                &mut intermediate,
                (0..RING_SIZE - 1).map(|i| members[i].clone()),
                |range: Range<usize>| {
                    builder_params
                        .as_ref()
                        .lookup(range)
                        .map(|chunks| chunks.into_iter().map(StaticChunk).collect())
                        .ok_or(())
                },
            )
            .expect("build_members_template_with_size push_members");
            intermediate
        };
        let builder_params = Arc::clone(&ctx.builder_params);
        let bench_template = Arc::new(full_minus_one_template);
        c.bench_function("verifiable_push_one_member_in_almost_full", move |b| {
            let members = Arc::clone(&members);
            let builder_params = Arc::clone(&builder_params);
            let bench_template = Arc::clone(&bench_template);
            b.iter_batched_ref(
                || bench_template.as_ref().clone(),
                |intermediate| {
                    VerifiableImpl::push_members(
                        intermediate,
                        std::iter::once(members[RING_SIZE - 1].clone()),
                        |range: Range<usize>| {
                            builder_params
                                .as_ref()
                                .lookup(range)
                                .map(|chunks| chunks.into_iter().map(StaticChunk).collect())
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

    // Finish a prepared template
    {
        let members_template = ctx.members_template.clone();
        c.bench_function("verifiable_finish_members", move |b| {
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
        let full = Arc::new(build_members_template_with_size(
            RING_SIZE,
            builder_params.as_ref(),
        ));
        c.bench_function("verifiable_finish_members_full", move |b| {
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
        c.bench_function("verifiable_new_secret", move |b| {
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
        c.bench_function("verifiable_member_from_secret", move |b| {
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
        c.bench_function("verifiable_open", move |b| {
            b.iter(|| {
                let commitment = VerifiableImpl::open(
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
        c.bench_function("verifiable_create", move |b| {
            b.iter(|| {
                let commitment = VerifiableImpl::open(
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
        c.bench_function("verifiable_sign", move |b| {
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
        c.bench_function("verifiable_alias_in_context", move |b| {
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
        c.bench_function("verifiable_validate", move |b| {
            b.iter(|| {
                let alias = VerifiableImpl::validate(
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
        c.bench_function("verifiable_is_valid", move |b| {
            b.iter(|| {
                let valid = VerifiableImpl::is_valid(
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
        c.bench_function("verifiable_verify_signature", move |b| {
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
        c.bench_function("verifiable_is_member_valid", move |b| {
            b.iter(|| {
                let valid = VerifiableImpl::is_member_valid(black_box(&member));
                assert!(valid);
            });
        });
    }
}

fn bench_verifiable_methods_255(c: &mut Criterion) {
    let ctx = MethodBenchContext::new(255);

    c.bench_function("verifiable_start_members_for_255_ring_size", |b| {
        b.iter(|| black_box(VerifiableImpl::start_members()));
    });

    // Push many members into a fresh intermediate
    {
        let builder_params = Arc::clone(&ctx.builder_params);
        let members = ctx.members.clone();
        let empty_intermediate = ctx.empty_intermediate.clone();
        c.bench_function("verifiable_push_members_for_255_ring_size", move |b| {
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
                                .map(|chunks| chunks.into_iter().map(StaticChunk).collect())
                                .ok_or(())
                        },
                    )
                    .expect("bench push_members");
                    // Keep the result alive:
                    black_box(&*intermediate);
                },
                BatchSize::SmallInput,
            );
        });
    }

    // Push 1 member into an almost-full intermediate
    {
        let builder_params = Arc::clone(&ctx.builder_params);
        let members = Arc::new(ctx.members.clone());
        let full_minus_one_template = {
            let mut intermediate = VerifiableImpl::start_members();
            VerifiableImpl::push_members(
                &mut intermediate,
                (0..255 - 1).map(|i| members[i].clone()),
                |range: Range<usize>| {
                    builder_params
                        .as_ref()
                        .lookup(range)
                        .map(|chunks| chunks.into_iter().map(StaticChunk).collect())
                        .ok_or(())
                },
            )
            .expect("build_members_template_with_size push_members");
            intermediate
        };
        let builder_params = Arc::clone(&ctx.builder_params);
        let bench_template = Arc::new(full_minus_one_template);
        c.bench_function("verifiable_push_one_member_in_almost_full_for_255_ring_size", move |b| {
            let members = Arc::clone(&members);
            let builder_params = Arc::clone(&builder_params);
            let bench_template = Arc::clone(&bench_template);
            b.iter_batched_ref(
                || bench_template.as_ref().clone(),
                |intermediate| {
                    VerifiableImpl::push_members(
                        intermediate,
                        std::iter::once(members[255 - 1].clone()),
                        |range: Range<usize>| {
                            builder_params
                                .as_ref()
                                .lookup(range)
                                .map(|chunks| chunks.into_iter().map(StaticChunk).collect())
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

    // Finish a prepared template
    {
        let members_template = ctx.members_template.clone();
        c.bench_function("verifiable_finish_members_for_255_ring_size", move |b| {
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
        let full = Arc::new(build_members_template_with_size(
            255,
            builder_params.as_ref(),
        ));
        c.bench_function("verifiable_finish_members_full_for_255_ring_size", move |b| {
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
        c.bench_function("verifiable_new_secret_for_255_ring_size", move |b| {
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
        c.bench_function("verifiable_member_from_secret_for_255_ring_size", move |b| {
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
        c.bench_function("verifiable_open_for_255_ring_size", move |b| {
            b.iter(|| {
                let commitment = VerifiableImpl::open(
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
        c.bench_function("verifiable_create_for_255_ring_size", move |b| {
            b.iter(|| {
                let commitment = VerifiableImpl::open(
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
        c.bench_function("verifiable_sign_for_255_ring_size", move |b| {
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
        c.bench_function("verifiable_alias_in_contex_for_255_ring_sizet", move |b| {
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
        c.bench_function("verifiable_validate_for_255_ring_size", move |b| {
            b.iter(|| {
                let alias = VerifiableImpl::validate(
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
        c.bench_function("verifiable_is_valid_for_255_ring_size", move |b| {
            b.iter(|| {
                let valid = VerifiableImpl::is_valid(
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
        c.bench_function("verifiable_verify_signature_for_255_ring_size", move |b| {
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
        c.bench_function("verifiable_is_member_valid_for_255_ring_size", move |b| {
            b.iter(|| {
                let valid = VerifiableImpl::is_member_valid(black_box(&member));
                assert!(valid);
            });
        });
    }
}

/// Context for benchmarking at a specific ring fill level
struct FillLevelContext {
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
    fn new(fill_count: usize, label: &'static str, builder_params: &RingBuilderParams) -> Self {
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
        let mut intermediate = VerifiableImpl::start_members();
        VerifiableImpl::push_members(
            &mut intermediate,
            members.iter().cloned(),
            |range: Range<usize>| {
                builder_params
                    .lookup(range)
                    .map(|chunks| chunks.into_iter().map(StaticChunk).collect())
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
            VerifiableImpl::open(&target_member, members.iter().cloned()).expect("context open");
        let (proof, alias) = VerifiableImpl::create(
            commitment,
            &target_secret,
            context_bytes.as_slice(),
            message_bytes.as_slice(),
        )
        .expect("context create");

        FillLevelContext {
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

fn bench_ring_fill_levels(c: &mut Criterion) {
    let builder_params = Arc::new(ring_verifier_builder_params());

    // Define fill levels (must have at least 1 member for most operations)
    let fill_levels: &[(usize, &'static str)] = &[
        (1.max(RING_SIZE / 100), "nearly_empty"),
        (RING_SIZE / 4, "quarter"),
        (RING_SIZE / 2, "half"),
        (RING_SIZE * 3 / 4, "three_quarters"),
        (RING_SIZE, "full"),
    ];

    // Pre-build contexts for each fill level
    let contexts: Vec<FillLevelContext> = fill_levels
        .iter()
        .map(|(count, label)| FillLevelContext::new(*count, label, builder_params.as_ref()))
        .collect();

    // Generate all members for push benchmarks
    let all_members: Vec<Member> = (0..RING_SIZE)
        .map(|i| {
            let secret = VerifiableImpl::new_secret(entropy_from_index(i));
            VerifiableImpl::member_from_secret(&secret)
        })
        .collect();

    // ===== push_one_member benchmarks =====
    let push_fill_levels = [
        (0, "empty"),
        (RING_SIZE / 4, "quarter"),
        (RING_SIZE / 2, "half"),
        (RING_SIZE * 3 / 4, "three_quarters"),
        (RING_SIZE - 1, "full_minus_one"),
    ];

    let mut group = c.benchmark_group("push_one_member_at_fill_level");
    for (fill_count, label) in push_fill_levels.iter() {
        let builder_params = Arc::clone(&builder_params);
        let members = all_members.clone();

        let template = {
            let mut intermediate = VerifiableImpl::start_members();
            if *fill_count > 0 {
                VerifiableImpl::push_members(
                    &mut intermediate,
                    (0..*fill_count).map(|i| members[i].clone()),
                    |range: Range<usize>| {
                        builder_params
                            .as_ref()
                            .lookup(range)
                            .map(|chunks| chunks.into_iter().map(StaticChunk).collect())
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
                                .map(|chunks| chunks.into_iter().map(StaticChunk).collect())
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
    let mut group = c.benchmark_group("finish_members_at_fill_level");
    for ctx in contexts.iter() {
        let builder_params = Arc::clone(&builder_params);
        let members = ctx.members.clone();
        let fill_count = ctx.fill_count;

        let template = {
            let mut intermediate = VerifiableImpl::start_members();
            VerifiableImpl::push_members(
                &mut intermediate,
                (0..fill_count).map(|i| members[i].clone()),
                |range: Range<usize>| {
                    builder_params
                        .as_ref()
                        .lookup(range)
                        .map(|chunks| chunks.into_iter().map(StaticChunk).collect())
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
    let mut group = c.benchmark_group("open_at_fill_level");
    for ctx in contexts.iter() {
        let members = ctx.members.clone();
        let target_member = ctx.target_member.clone();
        let label = ctx.label;

        group.bench_function(label, move |b| {
            b.iter(|| {
                let commitment = VerifiableImpl::open(
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
    let mut group = c.benchmark_group("create_at_fill_level");
    for ctx in contexts.iter() {
        let members = ctx.members.clone();
        let target_member = ctx.target_member.clone();
        let target_secret = ctx.target_secret.clone();
        let context_bytes = ctx.context_bytes.clone();
        let message_bytes = ctx.message_bytes.clone();
        let label = ctx.label;

        group.bench_function(label, move |b| {
            b.iter(|| {
                let commitment = VerifiableImpl::open(
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
    let mut group = c.benchmark_group("validate_at_fill_level");
    for ctx in contexts.iter() {
        let proof = ctx.proof.clone();
        let members_commitment = ctx.members_commitment.clone();
        let context_bytes = ctx.context_bytes.clone();
        let message_bytes = ctx.message_bytes.clone();
        let label = ctx.label;

        group.bench_function(label, move |b| {
            b.iter(|| {
                let alias = VerifiableImpl::validate(
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
    let mut group = c.benchmark_group("is_valid_at_fill_level");
    for ctx in contexts.iter() {
        let proof = ctx.proof.clone();
        let members_commitment = ctx.members_commitment.clone();
        let alias = ctx.alias;
        let context_bytes = ctx.context_bytes.clone();
        let message_bytes = ctx.message_bytes.clone();
        let label = ctx.label;

        group.bench_function(label, move |b| {
            b.iter(|| {
                let valid = VerifiableImpl::is_valid(
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

criterion_group!(benches, bench_verifiable_methods, bench_verifiable_methods_255, bench_ring_fill_levels);
criterion_main!(benches);
