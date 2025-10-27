use criterion::{Criterion, black_box, criterion_group, criterion_main};
use sp_core::Pair;
use sp_core::ed25519;

fn bench_ed25519_verify(c: &mut Criterion) {
    let seed = [0u8; 32];
    let pair = ed25519::Pair::from_seed(&seed);
    let public = pair.public();
    let message = vec![42u8; 128];
    let signature = pair.sign(&message);
    let signature_ref = &signature;
    let public_ref = &public;
    let message_slice = message.as_slice();

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            let result = ed25519::Pair::verify(
                black_box(signature_ref),
                black_box(message_slice),
                black_box(public_ref),
            );
            assert!(result, "verification must succeed");
        });
    });
}

criterion_group!(benches, bench_ed25519_verify);
criterion_main!(benches);
