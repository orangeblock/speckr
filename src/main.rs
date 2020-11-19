use std::convert::TryInto;
use std::mem::size_of;

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
    let mut x = x.rotate_right(7);
    x = x.wrapping_add(y);
    x ^= k;
    let mut y = y.rotate_left(2);
    y ^= x;
    (x, y)
}

fn speck_round_dec(x: u16, y: u16, k: u16) -> (u16, u16) {
    let mut y = y ^ x;
    y = y.rotate_right(2);
    let mut x = x ^ k;
    x = x.wrapping_sub(y);
    x = x.rotate_left(7);
    (x, y)
}

/// Performs key scheduling and outputs the round keys.
///
/// Expects the key parts as an array of words where the 0-th 
/// index is the first word in memory (rightmost word below). 
/// For illustration purposes the comments in this function
/// assume the following mental image:
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

fn main() {
    let a = 0b10101010u16;
    let b = 0b10010101u16;
    // let k = 0b10010101u16;
    let k: u64 = 0x1918111009080100;
    
    let v = bytes2words(&k.to_le_bytes());
    let keys = expand_key(v.as_slice().try_into().expect("Invalid vector size"));
    for (i, k) in keys.iter().enumerate(){
        println!("{:02}: 0x{:04x}", i, k);
    }
    

    // let pt = 0x6574694cu32;
    // println!("a: {:04b}", a);
    // println!("b: {:04b}", b);
    // println!("a ^ b: {:04b}", a ^ b);
    // println!("a & b: {:04b}", a & b);
    // println!("a | b: {:04b}", a | b);
    // println!("a(hex): {:x}", a);
    // println!("b(hex): {:x}", b);
    // println!("a ^ b to hex: {:x}", a ^ b);
    // println!("hex(a) ^ hex(b): {:x}", 0xaau32 ^ 0x95u32);
    // println!("{:?}", hex2str(&format!("{:x}", pt)));
    // println!("a: {:016b}", a);
    // println!("b: {:016b}", b);
    // println!("k: {:016b}", k);
    // println!("==after encryption");
    // let (e1, e2) = speck_round_enc(a, b, k);
    // println!("a: {:016b}", e1);
    // println!("b: {:016b}", e2);
    // println!("==after decryption");
    // let (d1, d2) = speck_round_dec(e1, e2, k);
    // println!("a: {:016b}", d1);
    // println!("b: {:016b}", d2);

    // expand_key(arr);
}
