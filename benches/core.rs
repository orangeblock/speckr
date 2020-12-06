use rand::random;
use speckr::Key;
use criterion::*;

pub fn speck_32_64(c: &mut Criterion){
    let k = Key::<u16, u32, u64>::new(0x1918111009080100u64);

    c.bench_function(
        "Speck 32/64 encryption",
        |b| b.iter_batched(
            || random::<u32>(),
            |data| k.encrypt(data),
            BatchSize::SmallInput
        )
    );

    c.bench_function(
        "Speck 32/64 decryption",
        |b| b.iter_batched(
            || k.encrypt(random::<u32>()),
            |data| k.decrypt(data),
            BatchSize::SmallInput
        )
    );
}

pub fn speck_64_128(c: &mut Criterion){
    let k = Key::<u32, u64, u128>::new(0x1b1a1918131211100b0a090803020100u128);

    c.bench_function(
        "Speck 64/128 encryption",
        |b| b.iter_batched(
            || random::<u64>(),
            |data| k.encrypt(data),
            BatchSize::SmallInput
        )
    );

    c.bench_function(
        "Speck 64/128 decryption",
        |b| b.iter_batched(
            || k.encrypt(random::<u64>()),
            |data| k.decrypt(data),
            BatchSize::SmallInput
        )
    );
}

pub fn speck_128_128(c: &mut Criterion){
    let k = Key::<u64, u128, u128>::new(0x0f0e0d0c0b0a09080706050403020100u128);

    c.bench_function(
        "Speck 128/128 encryption",
        |b| b.iter_batched(
            || random::<u128>(),
            |data| k.encrypt(data),
            BatchSize::SmallInput
        )
    );

    c.bench_function(
        "Speck 128/128 decryption",
        |b| b.iter_batched(
            || k.encrypt(random::<u128>()),
            |data| k.decrypt(data),
            BatchSize::SmallInput
        )
    );
}

criterion_group!(benches, speck_32_64, speck_64_128, speck_128_128);
criterion_main!(benches);
