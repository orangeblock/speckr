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
            // generate next round of keys
            let (e1, e0) = Self::_round_enc(l0, k0, i as u16);
            // update key parts for next round
            k0 = e0; l0 = l1; l1 = l2; l2 = e1;
            // set current round key
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

    fn _ror(x: u16, n: u8) -> u16 { x >> n | x << (16 - n) }
    fn _rol(x: u16, n: u8) -> u16 { x << n | x >> (16 - n) }
}

fn hex2str(hex_str: &String) -> String {
    let mut ret: String = String::from("");
    for i in (0..hex_str.len()).step_by(2){
        // decode next pair of hex chars
        let c: char = u8::from_str_radix(&hex_str[i..i+2], 16).unwrap() as char;
        ret.push(c);
    }
    return ret;
}

fn main() {
    let pt = 0x6574694cu32;
    let k = 0x1918111009080100u64;
    let key = Key::new(k);
    // let ct = encrypt32(pt, &key);
    let ct = key.encrypt(pt);
    println!("ct: {:08x}", ct);
    // let pt2 = decrypt32(ct, &key);
    let pt2 = key.decrypt(ct);
    println!("pt: {:08x}", pt2);
    // let f = File::open("test.txt").unwrap();
    // let mut reader = BufReader::new(f);
    // let mut buf = vec![0u8; 1024];
    // reader.read_exact(&mut buf).unwrap();
}
