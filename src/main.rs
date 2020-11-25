use std::convert::TryInto;

struct Key{
    round_keys: [u16; 22]
}

/// Performs key scheduling and stores the round keys in the struct.
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
impl Key {
    pub fn new(key: u64) -> Key {
        let mut parts: [u16; 4] = bytes2words(&key.to_le_bytes())
            .as_slice().try_into().expect("Invalid key size");
        let mut ret = Key{ round_keys: [parts[0]; 22] };
        for i in 0..(ret.round_keys.len()-1){
            // generate next round keys
            let (l, r) = speck_round_enc(
                parts[1], parts[0], i as u16
            );
            // update key parts for next round
            parts[0] = r;
            for j in 1..parts.len()-1{
                parts[j] = parts[j+1];
            }
            parts[parts.len()-1] = l;
            // set current round key
            ret.round_keys[i+1] = parts[0];
        }
        ret
    }
}

// TODO: compare with built-in rotate_ fns.
fn ror(x: u16, n: u8) -> u16 { x >> n | x << (16 - n) }
fn rol(x: u16, n: u8) -> u16 { x << n | x >> (16 - n) }

fn hex2str(hex_str: &String) -> String {
    let mut ret: String = String::from("");
    for i in (0..hex_str.len()).step_by(2){
        // decode next pair of hex chars
        let c: char = u8::from_str_radix(&hex_str[i..i+2], 16).unwrap() as char;
        ret.push(c);
    }
    return ret;
}

fn speck_round_enc(x: u16, y: u16, k: u16) -> (u16, u16) {
    let mut x = ror(x, 7);
    x = x.wrapping_add(y);
    x ^= k;
    let mut y = rol(y, 2);
    y ^= x;
    (x, y)
}

fn speck_round_dec(x: u16, y: u16, k: u16) -> (u16, u16) {
    let mut y = y ^ x;
    y = ror(y, 2);
    let mut x = x ^ k;
    x = x.wrapping_sub(y);
    x = rol(x, 7);
    (x, y)
}

fn expand_key(mut parts: [u16; 4]) -> [u16; 22]{
    let mut round_keys = [parts[0]; 22];
    for i in 0..(round_keys.len()-1){
        // generate next round key
        let (l, r) = speck_round_enc(
            parts[1], parts[0], i as u16
        );
        // update key parts for next round
        parts[0] = r;
        for j in 1..parts.len()-1{
            parts[j] = parts[j+1];
        }
        parts[parts.len()-1] = l;
        // set current round key
        round_keys[i+1] = parts[0];
    }
    round_keys
}

fn bytes2words(bytes: &[u8]) -> Vec<u16>{
    let mut v: Vec<u16> = Vec::new();
    for i in (0..bytes.len()).step_by(2){
        // beware, this ties the code to little endian architectures
        v.push(u16::from_le_bytes([bytes[i], bytes[i+1]]));
    }
    v
}

fn encrypt(block: u32, k: u64) -> u32{
    let key_vec: Vec<u16> = bytes2words(&k.to_le_bytes());
    let block_vec: Vec<u16> = bytes2words(&block.to_le_bytes());
    let round_keys = expand_key(
        key_vec.as_slice().try_into().expect("Invalid vector size")
    );
    let mut bl = block_vec[1];
    let mut br = block_vec[0];
    for i in 0..22{
        let (l, r) = speck_round_enc(bl, br, round_keys[i]);
        bl = l;
        br = r;
    }
    ((bl as u32) << 16) | br as u32
}

fn encrypt32(block: u32, k: &Key) -> u32 {
    let block_vec: Vec<u16> = bytes2words(&block.to_le_bytes());
    let mut bl = block_vec[1];
    let mut br = block_vec[0];
    for i in 0..22{
        let (l, r) = speck_round_enc(bl, br, k.round_keys[i]);
        bl = l;
        br = r;
    }
    ((bl as u32) << 16) | br as u32
}

fn decrypt(block: u32, k: u64) -> u32{
    let key_vec: Vec<u16> = bytes2words(&k.to_le_bytes());
    let block_vec: Vec<u16> = bytes2words(&block.to_le_bytes());
    let round_keys = expand_key(
        key_vec.as_slice().try_into().expect("Invalid vector size")
    );
    let mut bl = block_vec[1];
    let mut br = block_vec[0];
    for i in (0..22).rev(){
        let (l, r) = speck_round_dec(bl, br, round_keys[i]);
        bl = l;
        br = r;
    }
    ((bl as u32) << 16) | br as u32
}


fn decrypt32(block: u32, k: &Key) -> u32{
    let block_vec: Vec<u16> = bytes2words(&block.to_le_bytes());
    let mut bl = block_vec[1];
    let mut br = block_vec[0];
    for i in (0..22).rev(){
        let (l, r) = speck_round_dec(bl, br, k.round_keys[i]);
        bl = l;
        br = r;
    }
    ((bl as u32) << 16) | br as u32
}


fn main() {
    let pt = 0x6574694cu32;
    let k = 0x1918111009080100u64;
    let key = Key::new(k);
    let ct = encrypt32(pt, &key);
    println!("ct: {:08x}", ct);
    let pt2 = decrypt32(ct, &key);
    println!("pt: {:08x}", pt2);
    // let f = File::open("test.txt").unwrap();
    // let mut reader = BufReader::new(f);
    // let mut buf = vec![0u8; 1024];
    // reader.read_exact(&mut buf).unwrap();
}
