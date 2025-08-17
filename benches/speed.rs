use cipher::{Iv, Key};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ysc1::cipher::{KeyIvInit, StreamCipher};
use ysc1::{Ysc1_1024Cipher, Ysc1_512Cipher};

// A generic function to benchmark any cipher that implements the required traits.
fn bench_cipher<C>(c: &mut Criterion, name: &str)
where
    C: KeyIvInit + StreamCipher
{
    let mut group = c.benchmark_group(name);

    // Benchmark throughput for different buffer sizes.
    for size in [1024, 4096, 16384, 65536].iter() {
        let mut buffer = vec![0u8; *size];
        let key = Key::<C>::default();
        let nonce = Iv::<C>::default();
        let mut cipher = C::new(&key, &nonce);

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| cipher.apply_keystream(&mut buffer));
        });
    }
    group.finish();
}

// Main benchmark function that sets up and runs all benchmarks.
fn benchmarks(c: &mut Criterion) {
    bench_cipher::<Ysc1_512Cipher>(c, "YSC1-512");
    bench_cipher::<Ysc1_1024Cipher>(c, "YSC1-1024");
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
