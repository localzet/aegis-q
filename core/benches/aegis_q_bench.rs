use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use aegis_q_core::{aegis_q_encrypt, aegis_q_decrypt};

fn bench_encrypt(c: &mut Criterion) {
    let key = b"bench-key-123456789012345678901234567890";
    let nonce = b"bench-nonce-123456";
    
    let mut group = c.benchmark_group("encrypt");
    
    for size in [16, 64, 256, 1024, 4096, 16384].iter() {
        let plaintext = vec![0u8; *size];
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &plaintext,
            |b, pt| {
                b.iter(|| aegis_q_encrypt(key, nonce, pt));
            },
        );
    }
    
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let key = b"bench-key-123456789012345678901234567890";
    let nonce = b"bench-nonce-123456";
    
    let mut group = c.benchmark_group("decrypt");
    
    for size in [16, 64, 256, 1024, 4096, 16384].iter() {
        let plaintext = vec![0u8; *size];
        let ciphertext = aegis_q_encrypt(key, nonce, &plaintext);
        
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &ciphertext,
            |b, ct| {
                b.iter(|| aegis_q_decrypt(key, nonce, ct).unwrap());
            },
        );
    }
    
    group.finish();
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
criterion_main!(benches);

