struct Key<T>{
    round_keys: Vec<T>
}

trait SpeckOps<W, B, K> {
    const ROUNDS: usize;

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
    fn new(key: K) -> Key<W>;

    /// Performs block encryption by successively applying the round 
    /// function using the generated round keys.
    fn encrypt(&self, block: B) -> B;

    /// Performs block decryption by reversing the encryption operations.
    fn decrypt(&self, block: B) -> B;

    /// The Speck round function used for encryption as well as key expansion. 
    fn _round_enc(x: W, y: W, k: W) -> (W, W);

    /// Inverse operations of the round function used for decryption.
    fn _round_dec(x: W, y: W, k: W) -> (W, W);

    // TODO: compare with built-in rotate_ fns.
    fn _ror(x: W, n: u8) -> W;
    fn _rol(x: W, n: u8) -> W;
}

/// Speck 32/64
impl SpeckOps<u16, u32, u64> for Key<u16> {
    const ROUNDS: usize = 22;

    fn new(key: u64) -> Key<u16> {
        let (mut l2, mut l1, mut l0, mut k0) = (
            (key >> 48) as u16, (key >> 32) as u16, 
            (key >> 16) as u16, key as u16
        );
        let mut ret = Key { round_keys: vec!(k0; Self::ROUNDS) };
        for i in 0..(Self::ROUNDS-1){
            let (e1, e0) = Self::_round_enc(l0, k0, i as u16);
            k0 = e0; l0 = l1; l1 = l2; l2 = e1;
            ret.round_keys[i+1] = k0;
        }
        ret
    }

    fn encrypt(&self, block: u32) -> u32 {
        let (mut b1, mut b0) = ((block >> 16) as u16, block as u16);
        for i in 0..Self::ROUNDS{
            let (l, r) = Self::_round_enc(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u32) << 16) | b0 as u32
    }

    fn decrypt(&self, block: u32) -> u32 {
        let (mut b1, mut b0) = ((block >> 16) as u16, block as u16); 
        for i in (0..Self::ROUNDS).rev(){
            let (l, r) = Self::_round_dec(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u32) << 16) | b0 as u32
    }
    
    fn _round_enc(x: u16, y: u16, k: u16) -> (u16, u16) {
        let mut x = Self::_ror(x, 7);
        x = x.wrapping_add(y);
        x ^= k;
        let mut y = Self::_rol(y, 2);
        y ^= x;
        (x, y)
    }

    fn _round_dec(x: u16, y: u16, k: u16) -> (u16, u16) {
        let mut y = y ^ x;
        y = Self::_ror(y, 2);
        let mut x = x ^ k;
        x = x.wrapping_sub(y);
        x = Self::_rol(x, 7);
        (x, y)
    }

    // #[inline]
    fn _ror(x: u16, n: u8) -> u16 { x >> n | x << (16 - n) }
    // #[inline]
    fn _rol(x: u16, n: u8) -> u16 { x << n | x >> (16 - n) }
}

/// Speck 64/128
impl SpeckOps<u32, u64, u128> for Key<u32> {
    const ROUNDS: usize = 27;

    fn new(key: u128) -> Key<u32> {
        let (mut l2, mut l1, mut l0, mut k0) = (
            (key >> 96) as u32, (key >> 64) as u32, 
            (key >> 32) as u32, key as u32
        );
        let mut ret = Key { round_keys: vec!(k0; Self::ROUNDS) };
        for i in 0..(Self::ROUNDS-1){
            let (e1, e0) = Self::_round_enc(l0, k0, i as u32);
            k0 = e0; l0 = l1; l1 = l2; l2 = e1;
            ret.round_keys[i+1] = k0;
        }
        ret
    }

    fn encrypt(&self, block: u64) -> u64 {
        let (mut b1, mut b0) = ((block >> 32) as u32, block as u32);
        for i in 0..Self::ROUNDS{
            let (l, r) = Self::_round_enc(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u64) << 32) | b0 as u64
    }

    fn decrypt(&self, block: u64) -> u64 {
        let (mut b1, mut b0) = ((block >> 32) as u32, block as u32); 
        for i in (0..Self::ROUNDS).rev(){
            let (l, r) = Self::_round_dec(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u64) << 32) | b0 as u64
    }

    // TODO: _round_enc and _round_dec are identical for anything
    // above Speck 32/64 (excluding non-native sizes) so might be
    // able to consolidate.
    fn _round_enc(x: u32, y: u32, k: u32) -> (u32, u32) {
        let mut x = Self::_ror(x, 8);
        x = x.wrapping_add(y);
        x ^= k;
        let mut y = Self::_rol(y, 3);
        y ^= x;
        (x, y)
    }

    fn _round_dec(x: u32, y: u32, k: u32) -> (u32, u32) {
        let mut y = y ^ x;
        y = Self::_ror(y, 3);
        let mut x = x ^ k;
        x = x.wrapping_sub(y);
        x = Self::_rol(x, 8);
        (x, y)
    }

    fn _ror(x: u32, n: u8) -> u32 { x >> n | x << (32 - n) }
    fn _rol(x: u32, n: u8) -> u32 { x << n | x >> (32 - n) }
}

/// Speck 128/128
impl SpeckOps<u64, u128, u128> for Key<u64> {
    const ROUNDS: usize = 32;

    fn new(key: u128) -> Key<u64> {
        let (mut l0, mut k0) = ((key >> 64) as u64, key as u64);
        let mut ret = Key { round_keys: vec!(k0; Self::ROUNDS) };
        for i in 0..(Self::ROUNDS-1){
            // generate next round of keys
            let (e1, e0) = Self::_round_enc(l0, k0, i as u64);
            // update key parts for next round
            k0 = e0; l0 = e1;
            // set current round key
            ret.round_keys[i+1] = k0;
        }
        ret
    }

    fn encrypt(&self, block: u128) -> u128 {
        let (mut b1, mut b0) = ((block >> 64) as u64, block as u64);
        for i in 0..Self::ROUNDS{
            let (l, r) = Self::_round_enc(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u128) << 64) | b0 as u128
    }

    fn decrypt(&self, block: u128) -> u128 {
        let (mut b1, mut b0) = ((block >> 64) as u64, block as u64); 
        for i in (0..Self::ROUNDS).rev(){
            let (l, r) = Self::_round_dec(
                b1, b0, self.round_keys[i]
            );
            b1 = l; b0 = r;
        }
        ((b1 as u128) << 64) | b0 as u128
    }

    fn _round_enc(x: u64, y: u64, k: u64) -> (u64, u64) {
        let mut x = Self::_ror(x, 8);
        x = x.wrapping_add(y);
        x ^= k;
        let mut y = Self::_rol(y, 3);
        y ^= x;
        (x, y)
    }

    fn _round_dec(x: u64, y: u64, k: u64) -> (u64, u64) {
        let mut y = y ^ x;
        y = Self::_ror(y, 3);
        let mut x = x ^ k;
        x = x.wrapping_sub(y);
        x = Self::_rol(x, 8);
        (x, y)
    }

    fn _ror(x: u64, n: u8) -> u64 { x >> n | x << (64 - n) }
    fn _rol(x: u64, n: u8) -> u64 { x << n | x >> (64 - n) }
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::random;
    
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
