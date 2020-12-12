use std::marker::PhantomData;

pub struct Key<W, B, K>{
    _marker_b: PhantomData<B>,
    _marker_k: PhantomData<K>,
    round_keys: Vec<W>,
    rounds: usize,
    word_size: usize,
    key_size: usize,
}

/// The Speck round function used for encryption as well as key expansion.
macro_rules! round_enc {
    ($x:expr, $y:expr, $k:expr) => {
        {
            let mut x = $x.rotate_right(8);
            x = x.wrapping_add($y);
            x ^= $k;
            let mut y = $y.rotate_left(3);
            y ^= x;
            (x, y)
        }
    };
}

/// Inverse operations of the round function used for decryption.
macro_rules! round_dec {
    ($x:expr, $y:expr, $k:expr) => {
        {
            let mut y = $y ^ $x;
            y = y.rotate_right(3);
            let mut x = $x ^ $k;
            x = x.wrapping_sub(y);
            x = x.rotate_left(8);
            (x, y)
        }
    };
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
macro_rules! gen_round_keys {
    ($key:expr, $composite:expr, $wt:ty) => {
        {
            let mut parts: Vec<$wt> = vec![];
            for i in 0..($key.key_size / $key.word_size){
                parts.push(($composite >> (i * $key.word_size)) as $wt);
            }
            // set first round key to k0
            $key.round_keys[0] = parts[0];
            let plen = parts.len();
            for i in 0..($key.rounds-1){
                // calculate next key schedule using round number as key
                let (e1, e0) = round_enc!(
                    parts[1], parts[0], i as $wt
                );
                // update key parts
                parts[0] = e0;
                for j in 1..(plen-1){
                    parts[j] = parts[j+1];
                }
                parts[plen-1] = e1;
                // set current round key
                $key.round_keys[i+1] = parts[0];
            }
        }
    };
}

/// Performs block encryption by successively applying the round
/// function using the generated round keys.
macro_rules! encrypt {
    ($k:expr, $b:expr, $st:ty, $bt:ty) => {
        {
            let (mut b1, mut b0) = (($b >> $k.word_size) as $st, $b as $st);
            for i in 0..$k.rounds{
                let (l, r) = round_enc!(b1, b0, $k.round_keys[i]);
                b1 = l; b0 = r;
            }
            ((b1 as $bt) << $k.word_size) | b0 as $bt
        }
    };
}

/// Performs block decryption by reversing the encryption operations.
macro_rules! decrypt {
    ($k:expr, $b:expr, $st:ty, $bt:ty) => {
        {
            let (mut b1, mut b0) = (($b >> $k.word_size) as $st, $b as $st);
            for i in (0..$k.rounds).rev(){
                let (l, r) = round_dec!(b1, b0, $k.round_keys[i]);
                b1 = l; b0 = r;
            }
            ((b1 as $bt) << $k.word_size) | b0 as $bt
        }
    };
}

/// Speck 32/64
impl Key<u16, u32, u64> {
    /// We reimplement all the operations defined by the macros for this specific
    /// iteration since it uses differnet alpha/beta values. Hardcoding those values
    /// in the macros leads to a significant enough speedup to warrant this duplication.
    const ROUNDS: usize = 22;

    pub fn new(key: u64) -> Key<u16, u32, u64>{
        let mut k: Key<u16, u32, u64> = Key {
            _marker_b: PhantomData,
            _marker_k: PhantomData,
            rounds: Self::ROUNDS,
            round_keys: vec!(0u16; Self::ROUNDS),
            word_size: 16,
            key_size: 64
        };
        let mut parts: Vec<u16> = vec![];
        for i in 0..(k.key_size / k.word_size){
            parts.push((key >> (i * k.word_size)) as u16);
        }
        k.round_keys[0] = parts[0];
        let plen = parts.len();
        for i in 0..(k.rounds-1){
            let (e1, e0) = Self::round_enc(parts[1], parts[0], i as u16);
            parts[0] = e0;
            for j in 1..(plen-1){
                parts[j] = parts[j+1];
            }
            parts[plen-1] = e1;
            k.round_keys[i+1] = parts[0];
        }
        k
    }

    fn round_enc(x: u16, y: u16, k: u16) -> (u16, u16){
        let mut x = x.rotate_right(7);
        x = x.wrapping_add(y);
        x ^= k;
        let mut y = y.rotate_left(2);
        y ^= x;
        (x, y)
    }

    fn round_dec(x: u16, y: u16, k: u16) -> (u16, u16) {
        let mut y = y ^ x;
        y = y.rotate_right(2);
        let mut x = x ^ k;
        x = x.wrapping_sub(y);
        x = x.rotate_left(7);
        (x, y)
    }

    pub fn encrypt(&self, block: u32) -> u32 {
        let (mut b1, mut b0) = ((block >> self.word_size) as u16, block as u16);
        for i in 0..self.rounds{
            let (l, r) = Self::round_enc(b1, b0, self.round_keys[i]);
            b1 = l; b0 = r;
        }
        ((b1 as u32) << self.word_size) | b0 as u32
    }

    pub fn decrypt(&self, block: u32) -> u32 {
        let (mut b1, mut b0) = ((block >> self.word_size) as u16, block as u16);
        for i in (0..self.rounds).rev(){
            let (l, r) = Self::round_dec(b1, b0, self.round_keys[i]);
            b1 = l; b0 = r;
        }
        ((b1 as u32) << self.word_size) | b0 as u32
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
            key_size: 128
        };
        gen_round_keys!(&mut k, key, u32);
        k
    }

    pub fn encrypt(&self, block: u64) -> u64 {
        encrypt!(&self, block, u32, u64)
    }

    pub fn decrypt(&self, block: u64) -> u64 {
        decrypt!(&self, block, u32, u64)
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
            key_size: 128
        };
        gen_round_keys!(&mut k, key, u64);
        k
    }

    pub fn encrypt(&self, block: u128) -> u128 {
        encrypt!(&self, block, u64, u128)
    }

    pub fn decrypt(&self, block: u128) -> u128 {
        decrypt!(self, block, u64, u128)
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
            key_size: 256
        };
        let mut parts: Vec<u64> = key.to_vec();
        parts.reverse();

        k.round_keys[0] = parts[0];
        let plen = parts.len();
        for i in 0..(k.rounds-1){
            let (e1, e0) = round_enc!(parts[1], parts[0], i as u64);
            parts[0] = e0;
            for j in 1..(plen-1){
                parts[j] = parts[j+1];
            }
            parts[plen-1] = e1;
            k.round_keys[i+1] = parts[0];
        }
        k
    }

    pub fn encrypt(&self, block: u128) -> u128 {
        encrypt!(self, block, u64, u128)
    }

    pub fn decrypt(&self, block: u128) -> u128 {
        decrypt!(self, block, u64, u128)
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
