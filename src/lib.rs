use num::PrimInt;
use num::traits::{WrappingAdd, WrappingSub, AsPrimitive};
use std::marker::PhantomData;

pub struct Key<W, B, K>{
    _marker_b: PhantomData<B>,
    _marker_k: PhantomData<K>,
    round_keys: Vec<W>,
    rounds: usize,
    word_size: usize,
    key_size: usize,
    alpha: usize,
    beta: usize
}

// Custom bit rotations which are *not* correct for the general case
// but should be slightly faster than rotate_left/rotate_right here.
#[inline]
fn _ror<W>(x: W, n: usize, wsize: usize) -> W
where W: PrimInt
{
    x >> n | x << (wsize - n)
}
#[inline]
fn _ror2<W>(x: W, n: usize) -> W
where W: PrimInt
{
    x >> n | x << ((std::mem::size_of::<W>()*8) - n)
}
#[inline]
fn _rol<W>(x: W, n: usize, wsize: usize) -> W
where W: PrimInt
{
    x << n | x >> (wsize - n)
}
#[inline]
fn _rol2<W>(x: W, n: usize) -> W
where W: PrimInt
{
    x << n | x >> ((std::mem::size_of::<W>()*8) - n)
}

/// The Speck round function used for encryption as well as key expansion.
fn round_enc<W, B, K>(key: &Key<W,B,K>, x: W, y: W, k: W) -> (W, W)
where W: PrimInt + WrappingAdd
{
    // let mut x = _ror(x, key.alpha, key.word_size);
    let mut x = _ror2(x, key.alpha);
    x = x.wrapping_add(&y);
    x = x ^ k;
    // let mut y = _rol(y, key.beta, key.word_size);
    let mut y = _rol2(y, key.beta);
    y = y ^ x;
    (x, y)
}

/// Inverse operations of the round function used for decryption.
fn round_dec<W,B,K>(key: &Key<W,B,K>, x: W, y: W, k: W) -> (W, W)
where W: PrimInt + WrappingSub
{
    let mut y = y ^ x;
    // y = _ror(y, key.beta, key.word_size);
    y = _ror2(y, key.beta);
    let mut x = x ^ k;
    x = x.wrapping_sub(&y);
    // x = _rol(x, key.alpha, key.word_size);
    x = _rol2(x, key.alpha);
    (x, y)
}

/// Performs key scheduling storing the round keys in the struct.
///
/// The key is split into an array of words where the 0-th
/// index is the first word in memory (rightmost word below).
/// For illustration purposes the following mental image is assumed:
///
/// [ <L_(i+m-2)>   ...    <L_i>   <k_i> ]
///      idx=3     idx=2   idx=1   idx=0
///
/// ...which for first round (i=0) and a 4-word key (m=4) becomes:
///
/// [ <L_2>  <L_1>  <L_0>  <k_0> ]
///   idx=3  idx=2  idx=1  idx=0
///
/// See also [sec. 4.2]: https://eprint.iacr.org/2013/404.pdf
fn gen_round_keys<W, B, K>(key: &mut Key<W,B,K>, composite: K)
where
    W: PrimInt + WrappingAdd + WrappingSub + AsPrimitive<B>,
    B: PrimInt + AsPrimitive<W>,
    K: PrimInt + AsPrimitive<W>
{
    let mut parts: Vec<W> = vec![];
    for i in 0..(key.key_size / key.word_size){
        parts.push((composite >> (i * key.word_size)).as_());
    }
    // set first round key to k0
    // let mut ret = SpeckKey { round_keys: vec!(parts[0]; key.rounds) };
    key.round_keys[0] = parts[0];
    let plen = parts.len();
    for i in 0..(key.rounds-1){
        // calculate next key schedule using round number as key
        let (e1, e0) = round_enc(
            &key, parts[1], parts[0], num::NumCast::from(i).unwrap()
        );
        // update key parts
        parts[0] = e0;
        for j in 1..(plen-1){
            parts[j] = parts[j+1];
        }
        parts[plen-1] = e1;
        // set current round key
        key.round_keys[i+1] = parts[0];
    }
}

/// Performs block encryption by successively applying the round
/// function using the generated round keys.
fn encrypt<W,B,K>(k: &Key<W,B,K>, block: B) -> B
where
    W: PrimInt + WrappingAdd + WrappingSub + AsPrimitive<B>,
    B: PrimInt + AsPrimitive<W>,
    K: PrimInt + AsPrimitive<W>
{
    let (mut b1, mut b0) = ((block >> k.word_size).as_(), block.as_());
    for i in 0..k.rounds{
        let (l, r) = round_enc(&k,
            b1, b0, k.round_keys[i]
        );
        b1 = l; b0 = r;
    }
    ((b1.as_()) << k.word_size) | b0.as_()
}

/// Performs block decryption by reversing the encryption operations.
fn decrypt<W,B,K>(k: &Key<W,B,K>, block: B) -> B
where
    W: PrimInt + WrappingAdd + WrappingSub + AsPrimitive<B>,
    B: PrimInt + AsPrimitive<W>,
    K: PrimInt + AsPrimitive<W>
{
    let (mut b1, mut b0) = ((block >> k.word_size).as_(), block.as_());
    for i in (0..k.rounds).rev(){
        let (l, r) = round_dec(
            &k, b1, b0, k.round_keys[i]
        );
        b1 = l; b0 = r;
    }
    ((b1.as_()) << k.word_size) | b0.as_()
}

/// Speck 32/64
impl Key<u16, u32, u64> {
    const ROUNDS: usize = 22;

    pub fn new(key: u64) -> Key<u16, u32, u64>{
        let mut k: Key<u16, u32, u64> = Key {
            _marker_b: PhantomData,
            _marker_k: PhantomData,
            rounds: Self::ROUNDS,
            round_keys: vec!(0u16; Self::ROUNDS),
            word_size: 16,
            key_size: 64,
            alpha: 7,
            beta: 2
        };
        gen_round_keys(&mut k, key);
        k
    }

    #[inline]
    fn _ror(x: u16, n: usize) -> u16 { x >> n | x << (16 - n) }
    #[inline]
    fn _rol(x: u16, n: usize) -> u16 { x << n | x >> (16 - n) }

    fn round_enc(&self, x: u16, y: u16, k: u16) -> (u16, u16)
    {
        // let mut x = Self::_ror(x, self.alpha);
        // let mut x = _ror(x, self.alpha, self.word_size);
        let mut x = _ror2(x, self.alpha);
        x = x.wrapping_add(y);
        x = x ^ k;
        // let mut y = Self::_rol(y, self.beta);
        // let mut y = _rol(y, self.beta, self.word_size);
        let mut y = _rol2(y, self.beta);
        y = y ^ x;
        (x, y)
    }

    fn round_dec(&self, x: u16, y: u16, k: u16) -> (u16, u16)
    {
        let mut y = y ^ x;
        // y = Self::_ror(y, self.beta);
        // y = _ror(y, self.beta, self.word_size);
        y = _ror2(y, self.beta);
        let mut x = x ^ k;
        x = x.wrapping_sub(y);
        // x = Self::_rol(x, self.alpha);
        // x = _rol(x, self.alpha, self.word_size);
        x = _rol2(x, self.alpha);
        (x, y)
    }

    pub fn encrypt(&self, block: u32) -> u32 {
        let (mut b1, mut b0) = ((block >> 16) as u16, block as u16);
        for i in 0..Self::ROUNDS{
            let (l, r) = self.round_enc(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u32) << 16) | b0 as u32
    }

    pub fn decrypt(&self, block: u32) -> u32 {
        let (mut b1, mut b0) = ((block >> 16) as u16, block as u16);
        for i in (0..Self::ROUNDS).rev(){
            let (l, r) = self.round_dec(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u32) << 16) | b0 as u32
    }
}

/// Speck 64/128
impl Key<u32, u64, u128> {
    const ROUNDS: usize = 27;

    pub fn new(key: u128) -> Key<u32, u64, u128>{
        let mut k: Key<u32, u64, u128> = Key {
            _marker_b: PhantomData,
            _marker_k: PhantomData,
            rounds: Self::ROUNDS,
            round_keys: vec!(0u32; Self::ROUNDS),
            word_size: 32,
            key_size: 128,
            alpha: 8,
            beta: 3
        };
        gen_round_keys(&mut k, key);
        k
    }

    pub fn encrypt(&self, block: u64) -> u64 {
        encrypt(&self, block)
    }

    pub fn decrypt(&self, block: u64) -> u64 {
        decrypt(&self, block)
    }
}

/// Speck 128/128
impl Key<u64, u128, u128> {
    const ROUNDS: usize = 32;

    pub fn new(key: u128) -> Key<u64, u128, u128>{
        let mut k: Key<u64, u128, u128> = Key {
            _marker_b: PhantomData,
            _marker_k: PhantomData,
            rounds: Self::ROUNDS,
            round_keys: vec!(0u64; Self::ROUNDS),
            word_size: 64,
            key_size: 128,
            alpha: 8,
            beta: 3
        };
        gen_round_keys(&mut k, key);
        k
    }

    pub fn encrypt(&self, block: u128) -> u128 {
        encrypt(self, block)
    }

    pub fn decrypt(&self, block: u128) -> u128 {
        decrypt(self, block)
    }
}

/// Speck 128/256
impl Key<u64, u128, [u64;4]> {
    const ROUNDS: usize = 34;

    pub fn new(key: &[u64; 4]) -> Key<u64, u128, [u64; 4]>{
        let mut k: Key<u64, u128, [u64; 4]> = Key {
            _marker_b: PhantomData,
            _marker_k: PhantomData,
            rounds: Self::ROUNDS,
            round_keys: vec!(0u64; Self::ROUNDS),
            word_size: 64,
            key_size: 256,
            alpha: 8,
            beta: 3
        };
        let mut parts: Vec<u64> = key.to_vec();
        parts.reverse();

        k.round_keys[0] = parts[0];
        let plen = parts.len();
        for i in 0..(k.rounds-1){
            // calculate next key schedule using round number as key
            let (e1, e0) = round_enc(
                &k, parts[1], parts[0], num::NumCast::from(i).unwrap()
            );
            // update key parts
            parts[0] = e0;
            for j in 1..(plen-1){
                parts[j] = parts[j+1];
            }
            parts[plen-1] = e1;
            // set current round key
            k.round_keys[i+1] = parts[0];
        }
        k
    }

    #[inline]
    fn _ror(x: u64, n: usize) -> u64 { x >> n | x << (64 - n) }
    #[inline]
    fn _rol(x: u64, n: usize) -> u64 { x << n | x >> (64 - n) }

    fn round_enc(&self, x: u64, y: u64, k: u64) -> (u64, u64){
        let mut x = Self::_ror(x, self.alpha);
        x = x.wrapping_add(y);
        x = x ^ k;
        let mut y = Self::_rol(y, self.beta);
        y = y ^ x;
        (x, y)
    }

    fn round_dec(&self, x: u64, y: u64, k: u64) -> (u64, u64){
        let mut y = y ^ x;
        y = Self::_ror(y, self.beta);
        let mut x = x ^ k;
        x = x.wrapping_sub(y);
        x = Self::_rol(x, self.alpha);
        (x, y)
    }

    pub fn encrypt(&self, block: u128) -> u128 {
        let (mut b1, mut b0) = ((block >> 64) as u64, block as u64);
        for i in 0..Self::ROUNDS{
            let (l, r) = self.round_enc(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u128) << 64) | b0 as u128
    }

    pub fn decrypt(&self, block: u128) -> u128 {
        let (mut b1, mut b0) = ((block >> 64) as u64, block as u64);
        for i in (0..Self::ROUNDS).rev(){
            let (l, r) = self.round_dec(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u128) << 64) | b0 as u128
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;

    #[test]
    fn test_correct_32_64(){
        let pt = 0x6574694cu32;
        let k = Key::<u16,u32,u64>::new(0x1918111009080100u64);
        let ct = k.encrypt(pt);
        assert_eq!(ct, 0xa86842f2);
        let pt2 = k.decrypt(ct);
        assert_eq!(pt2, pt);
    }

    #[test]
    fn test_random_32_64(){
        let k = Key::<u16,u32,u64>::new(random::<u64>());
        for _ in 0..50{
            let pt = random::<u32>();
            assert_eq!(pt, k.decrypt(k.encrypt(pt)));
        }
    }

    #[test]
    fn test_correct_64_128(){
        let pt = 0x3b7265747475432du64;
        let k = Key::<u32, u64, u128>::new(0x1b1a1918131211100b0a090803020100u128);
        let ct = k.encrypt(pt);
        assert_eq!(ct, 0x8c6fa548454e028b);
        let pt2 = k.decrypt(ct);
        assert_eq!(pt2, pt);
    }

    #[test]
    fn test_random_64_128(){
        let k = Key::<u32, u64, u128>::new(rand::random::<u128>());
        for _ in 0..50{
            let pt = rand::random::<u64>();
            assert_eq!(pt, k.decrypt(k.encrypt(pt)));
        }
    }

    #[test]
    fn test_correct_128_128(){
        let pt = 0x6c617669757165207469206564616d20u128;
        let k = Key::<u64, u128, u128>::new(0x0f0e0d0c0b0a09080706050403020100u128);
        let ct = k.encrypt(pt);
        assert_eq!(ct, 0xa65d9851797832657860fedf5c570d18);
        let pt2 = k.decrypt(ct);
        assert_eq!(pt2, pt);
    }

    #[test]
    fn test_random_128_128(){
        let k = Key::<u64, u128, u128>::new(rand::random::<u128>());
        for _ in 0..50{
            let pt = rand::random::<u128>();
            assert_eq!(pt, k.decrypt(k.encrypt(pt)));
        }
    }

    #[test]
    fn test_correct_128_256(){
        let pt = 0x65736f6874206e49202e72656e6f6f70u128;
        let k = Key::<u64, u128, [u64;4]>::new(
            &[0x1f1e1d1c1b1a1918u64, 0x1716151413121110u64, 0x0f0e0d0c0b0a0908u64, 0x0706050403020100u64]
        );
        let ct = k.encrypt(pt);
        assert_eq!(ct, 0x4109010405c0f53e4eeeb48d9c188f43u128);
        let pt2 = k.decrypt(ct);
        assert_eq!(pt2, pt);
    }

    #[test]
    fn test_random_128_256(){
        let k = Key::<u64, u128, [u64;4]>::new(
            &[rand::random::<u64>(), rand::random::<u64>(), rand::random::<u64>(), rand::random::<u64>()]
        );
        for _ in 0..50{
            let pt = rand::random::<u128>();
            assert_eq!(pt, k.decrypt(k.encrypt(pt)));
        }
    }
}
