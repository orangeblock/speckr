use rand::random;
use criterion::*;

pub fn speck_64_96(c: &mut Criterion){
    let k = speckr::Speck6496::new(&[0x13121110u32, 0x0b0a0908u32, 0x03020100u32]);

    c.bench_function(
        "Speck 64/96 encryption",
        |b| b.iter_batched(
            || random::<u64>(),
            |data| k.encrypt(data),
            BatchSize::SmallInput
        )
    );

    c.bench_function(
        "Speck 64/96 decryption",
        |b| b.iter_batched(
            || k.encrypt(random::<u64>()),
            |data| k.decrypt(data),
            BatchSize::SmallInput
        )
    );
}

pub fn speck_64_128(c: &mut Criterion){
    let k = speckr::Speck64128::new(0x1b1a1918131211100b0a090803020100u128);

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
    let k = speckr::Speck128128::new(0x0f0e0d0c0b0a09080706050403020100u128);

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

pub fn speck_128_192(c: &mut Criterion){
    let k = speckr::Speck128192::new(
        &[0x1716151413121110u64, 0x0f0e0d0c0b0a0908u64, 0x0706050403020100u64]);

    c.bench_function(
        "Speck 128/192 encryption",
        |b| b.iter_batched(
            || random::<u128>(),
            |data| k.encrypt(data),
            BatchSize::SmallInput
        )
    );

    c.bench_function(
        "Speck 128/192 decryption",
        |b| b.iter_batched(
            || k.encrypt(random::<u128>()),
            |data| k.decrypt(data),
            BatchSize::SmallInput
        )
    );
}

pub fn speck_128_256(c: &mut Criterion){
    let k = speckr::Speck128256::new(
        &[0x1f1e1d1c1b1a1918u64, 0x1716151413121110u64, 0x0f0e0d0c0b0a0908u64, 0x0706050403020100u64]
    );

    c.bench_function(
        "Speck 128/256 encryption",
        |b| b.iter_batched(
            || random::<u128>(),
            |data| k.encrypt(data),
            BatchSize::SmallInput
        )
    );

    c.bench_function(
        "Speck 128/256 decryption",
        |b| b.iter_batched(
            || k.encrypt(random::<u128>()),
            |data| k.decrypt(data),
            BatchSize::SmallInput
        )
    );
}

criterion_group!(benches, speck_64_96, speck_64_128, speck_128_128, speck_128_192, speck_128_256);
criterion_main!(benches);
