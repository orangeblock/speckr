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
/// The key is split into an array of words (parts) where the 0-th
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
    ($key:expr, $parts:expr, $wt:ty) => {
        {
            $key.round_keys[0] = $parts[0];
            let plen = $parts.len();
            for i in 0..($key.rounds-1){
                // calculate next key schedule using round number as key
                let (e1, e0) = round_enc!($parts[1], $parts[0], i as $wt);
                // update key parts
                $parts[0] = e0;
                for j in 1..(plen-1){
                    $parts[j] = $parts[j+1];
                }
                $parts[plen-1] = e1;
                // set current round key
                $key.round_keys[i+1] = $parts[0];
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
        let mut parts: Vec<u32> = vec![];
        for i in 0..(k.key_size / k.word_size){
            parts.push((key >> (i * k.word_size)) as u32);
        }
        gen_round_keys!(k, parts, u32);
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
        let mut parts: Vec<u64> = vec![];
        for i in 0..(k.key_size / k.word_size){
            parts.push((key >> (i * k.word_size)) as u64);
        }
        gen_round_keys!(k, parts, u64);
        k
    }

    pub fn encrypt(&self, block: u128) -> u128 {
        encrypt!(self, block, u64, u128)
    }

    pub fn decrypt(&self, block: u128) -> u128 {
        decrypt!(self, block, u64, u128)
    }
}

/// Speck 128/192
impl Key<u64, u128, [u64;3]>{
    const ROUNDS: usize = 33;

    pub fn new(key: &[u64; 3]) -> Key<u64, u128, [u64; 3]>{
        let mut k: Key<u64, u128, [u64; 3]> = Key {
            _marker_b: PhantomData,
            _marker_k: PhantomData,
            rounds: Self::ROUNDS,
            round_keys: vec!(0u64; Self::ROUNDS),
            word_size: 64,
            key_size: 192
        };
        let mut parts: Vec<u64> = key.to_vec();
        parts.reverse();
        gen_round_keys!(k, parts, u64);
        k
    }

    pub fn encrypt(&self, block: u128) -> u128 {
        encrypt!(self, block, u64, u128)
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
        gen_round_keys!(k, parts, u64);
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
    fn test_correct_128_192(){
        let pt = 0x726148206665696843206f7420746e65u128;
        let k = Key::<u64, u128, [u64;3]>::new(
            &[0x1716151413121110u64, 0x0f0e0d0c0b0a0908u64, 0x0706050403020100u64]);
        let ct = k.encrypt(pt);
        assert_eq!(ct, 0x1be4cf3a13135566f9bc185de03c1886u128);
        let pt2 = k.decrypt(ct);
        assert_eq!(pt2, pt);
    }

    #[test]
    fn test_random_128_192(){
        let k = Key::<u64, u128, [u64;3]>::new(
            &[0x1716151413121110u64, 0x0f0e0d0c0b0a0908u64, 0x0706050403020100u64]);
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
