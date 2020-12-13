# speckr
0-dependency implementation of the SPECK block cipher: https://eprint.iacr.org/2013/404.pdf

Currently supports `64/96`, `64/128`, `128/128`, `128/192` and `128/256` variants.

## Usage
You create a Speck key instance by calling `new` on one of the exposed types, passing the appropriately sized key. This will perform the costly key expansion once and store the generated round keys on the struct. Then you simply call `encrypt` with the plaintext and `decrypt` with the ciphertext which will use the round keys to perform the operations.

The module exposes the `Speck<block-size><key-size>` types for easy access, so for example, encrypting a `u128` block using Speck 128/128:
```rust
let pt = 0x6c617669757165207469206564616d20u128;
// Create the Speck key instance
let k = speckr::Speck128128::new(0x0f0e0d0c0b0a09080706050403020100u128);
// Get the encrypted block
let ct = k.encrypt(pt);
// Get back the original plaintext
let pt2 = k.decrypt(ct);
```

Using the 128/256, 128/192 and 64/96 variants requires you to pass the key as a slice of the type which is half the block size, so e.g. for Speck 64/96:
```rust
let pt = 0x74614620736e6165u64;
// Block size is u64 so we pass 3 u32 parts to build the u96 key.
let k = speckr::Speck6496::new(&[0x13121110u32, 0x0b0a0908u32, 0x03020100u32];
// Operations are same as before
let ct = k.encrypt(pt);
let pt2 = k.decrypt(ct);
```

See tests and benches for more examples.
