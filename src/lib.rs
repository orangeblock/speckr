use num::PrimInt;
use num::traits::{WrappingAdd, WrappingSub, AsPrimitive};

pub struct Key<W> {
    round_keys: Vec<W>
}

pub trait SpeckOps<W, B, K> 
where 
    W: PrimInt + WrappingAdd + WrappingSub + AsPrimitive<B>, 
    B: PrimInt + AsPrimitive<W>, 
    K: PrimInt + AsPrimitive<W>
{
    const ROUNDS: usize;
    const WORD_SIZE: usize;
    const BLOCK_SIZE: usize;
    const KEY_SIZE: usize;
    const ROUND_ALPHA: usize;
    const ROUND_BETA: usize;

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
    fn new(key: K) -> Key<W> {
        let mut parts: Vec<W> = vec![];
        for i in 0..(Self::KEY_SIZE / Self::WORD_SIZE){
            parts.push((key >> (i * Self::WORD_SIZE)).as_());
        }
        // set first round key to k0
        let mut ret = Key { round_keys: vec!(parts[0]; Self::ROUNDS) };

        let plen = parts.len();
        for i in 0..(Self::ROUNDS-1){
            // calculate next key schedule using round number as key
            let (e1, e0) = Self::round_enc(
               parts[1], parts[0], num::NumCast::from(i).unwrap()
            );
            // update key parts
            parts[0] = e0;
            for j in 1..(plen-1){
                parts[j] = parts[j+1];
            }
            parts[plen-1] = e1;
            // set current round key
            ret.round_keys[i+1] = parts[0];
        }
        ret
    }

    /// Performs block encryption by successively applying the round 
    /// function using the generated round keys.
    fn encrypt(&self, block: B) -> B;

    /// Performs block decryption by reversing the encryption operations.
    fn decrypt(&self, block: B) -> B;

    /// The Speck round function used for encryption as well as key expansion. 
    fn round_enc(x: W, y: W, k: W) -> (W, W) {
        let mut x = Self::_ror(x, Self::ROUND_ALPHA);
        x = x.wrapping_add(&y);
        x = x ^ k;
        let mut y = Self::_rol(y, Self::ROUND_BETA);
        y = y ^ x;
        (x, y)
    }

    /// Inverse operations of the round function used for decryption.
    fn round_dec(x: W, y: W, k: W) -> (W, W) {
        let mut y = y ^ x;
        y = Self::_ror(y, Self::ROUND_BETA);
        y.rotate_right(3);
        let mut x = x ^ k;
        x = x.wrapping_sub(&y);
        x = Self::_rol(x, Self::ROUND_ALPHA);
        (x, y)
    }

    // Custom bit rotations which are *not* correct for the general case
    // but should be slightly faster than rotate_left/rotate_right here.
    #[inline]
    fn _ror(x: W, n: usize) -> W { x >> n | x << (Self::WORD_SIZE - n) }
    #[inline]
    fn _rol(x: W, n: usize) -> W { x << n | x >> (Self::WORD_SIZE - n) }
}

/// Speck 32/64
impl SpeckOps<u16, u32, u64> for Key<u16> {
    const ROUNDS: usize = 22;
    const WORD_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 32;
    const KEY_SIZE: usize = 64;
    const ROUND_ALPHA: usize = 7;
    const ROUND_BETA: usize = 2;

    fn encrypt(&self, block: u32) -> u32 {
        let (mut b1, mut b0) = ((block >> 16) as u16, block as u16);
        for i in 0..Self::ROUNDS{
            let (l, r) = Self::round_enc(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u32) << 16) | b0 as u32
    }

    fn decrypt(&self, block: u32) -> u32 {
        let (mut b1, mut b0) = ((block >> 16) as u16, block as u16); 
        for i in (0..Self::ROUNDS).rev(){
            let (l, r) = Self::round_dec(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u32) << 16) | b0 as u32
    }
}

/// Speck 64/128
impl SpeckOps<u32, u64, u128> for Key<u32> {
    const ROUNDS: usize = 27;
    const WORD_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 64;
    const KEY_SIZE: usize = 128;
    const ROUND_ALPHA: usize = 8;
    const ROUND_BETA: usize = 3;

    fn encrypt(&self, block: u64) -> u64 {
        let (mut b1, mut b0) = ((block >> 32) as u32, block as u32);
        for i in 0..Self::ROUNDS{
            let (l, r) = Self::round_enc(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u64) << 32) | b0 as u64
    }

    fn decrypt(&self, block: u64) -> u64 {
        let (mut b1, mut b0) = ((block >> 32) as u32, block as u32); 
        for i in (0..Self::ROUNDS).rev(){
            let (l, r) = Self::round_dec(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u64) << 32) | b0 as u64
    }
}

/// Speck 128/128
impl SpeckOps<u64, u128, u128> for Key<u64> {
    const ROUNDS: usize = 32;
    const WORD_SIZE: usize = 64;
    const BLOCK_SIZE: usize = 128;
    const KEY_SIZE: usize = 128;
    const ROUND_ALPHA: usize = 8;
    const ROUND_BETA: usize = 3;

    fn encrypt(&self, block: u128) -> u128 {
        let (mut b1, mut b0) = ((block >> 64) as u64, block as u64);
        for i in 0..Self::ROUNDS{
            let (l, r) = Self::round_enc(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u128) << 64) | b0 as u128
    }

    fn decrypt(&self, block: u128) -> u128 {
        let (mut b1, mut b0) = ((block >> 64) as u64, block as u64); 
        for i in (0..Self::ROUNDS).rev(){
            let (l, r) = Self::round_dec(
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
        let k = Key::new(0x1918111009080100u64);
        let ct = k.encrypt(pt);
        assert_eq!(ct, 0xa86842f2);
        let pt2 = k.decrypt(ct);
        assert_eq!(pt2, pt);
    }

    #[test]
    fn test_random_32_64(){
        let k = Key::new(random::<u64>());
        for _ in 0..50{
            let pt = random::<u32>();
            assert_eq!(pt, k.decrypt(k.encrypt(pt)));
        }
    }

    #[test]
    fn test_correct_64_128(){
        let pt = 0x3b7265747475432du64;
        let k = Key::new(0x1b1a1918131211100b0a090803020100u128);
        let ct = k.encrypt(pt);
        assert_eq!(ct, 0x8c6fa548454e028b);
        let pt2 = k.decrypt(ct);
        assert_eq!(pt2, pt);
    }

    #[test]
    fn test_random_64_128(){
        let k = Key::new(rand::random::<u128>());
        for _ in 0..50{
            let pt = rand::random::<u64>();
            assert_eq!(pt, k.decrypt(k.encrypt(pt)));
        }
    }

    #[test]
    fn test_correct_128_128(){
        let pt = 0x6c617669757165207469206564616d20u128;
        let k = Key::new(0x0f0e0d0c0b0a09080706050403020100u128);
        let ct = k.encrypt(pt);
        assert_eq!(ct, 0xa65d9851797832657860fedf5c570d18);
        let pt2 = k.decrypt(ct);
        assert_eq!(pt2, pt);
    }

    #[test]
    fn test_random_128_128(){
        let k = Key::new(rand::random::<u128>());
        for _ in 0..50{
            let pt = rand::random::<u128>();
            assert_eq!(pt, k.decrypt(k.encrypt(pt)));
        }
    }
}
