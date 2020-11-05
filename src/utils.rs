use std::collections::BTreeMap;
use std::error::Error;

use crate::curve_traits;
use crate::ristretto_curve;

use curve_traits::{ECPoint, ECScalar};
use ristretto_curve::{FE, GE};

use rand_core::{CryptoRng, RngCore};
use schnorrkel::keys::Keypair;

pub fn create_keypair(secret_key: &FE, pub_key: &GE) -> Result<Keypair, Box<dyn Error>> {
    let mut csprng = rand_hack();
    let mut nonce: [u8; 32] = [0u8; 32];
    csprng.fill_bytes(&mut nonce);
    let byte_keys: Vec<u8> = [
        secret_key.get_element().to_bytes(),
        nonce,
        pub_key.get_element().to_bytes(),
    ]
    .concat();
    let keypair = Keypair::from_bytes(byte_keys.as_ref());
    match keypair {
        Ok(k) => return Ok(k),
        Err(_) => bail!("vss: error while create keypair from secret"),
    }
}

pub fn rand_hack() -> impl RngCore + CryptoRng {
    ::rand_core::OsRng
}

pub fn from_slice(bytes: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
    let mut array = [0; 32];
    if bytes.len() != 32 as usize {
        bail!("Incorrect bytes len to convert vector into array")
    }
    array.copy_from_slice(bytes);
    Ok(array)
}

pub fn bitwise_comparison(a: &[u8], b: &[u8]) -> bool {
    let diff = a
        .iter()
        .zip(b.iter())
        .map(|(a, b)| a ^ b)
        .fold(0, |acc, x| acc | x);
    diff == 0 && a.len() == b.len()
}

pub fn to_32_vector(num: f64) -> Vec<u8> {
    let power: f64 = num.log(256 as f64);
    if power > 1 as f64 {
        let start_diap: f64 = (256 as u64).pow(power as u32) as f64;
        let amount_numbers: u64 = (power + 1 as f64) as u64;
        let mut num_to_distr: u64 = (num - start_diap) as u64;
        let mut borders: BTreeMap<u8, Vec<u64>> = BTreeMap::new();
        let mut bytes_vec: Vec<u8> = vec![0; amount_numbers as usize];

        for ind in 0..amount_numbers {
            let max_border: u64 = (256 as u64).pow((amount_numbers - ind) as u32) - 1 as u64;
            let min_border: u64;

            if ind == amount_numbers - 1 {
                min_border = 0;
            } else {
                min_border = (256 as u64).pow((amount_numbers - (ind + 1)) as u32) as u64;
            }

            borders.insert(ind as u8, vec![min_border, max_border]);
        }

        bytes_vec[0] = 1;
        for (k, v) in borders.iter() {
            if num_to_distr <= 255 as u64 {
                bytes_vec[*k as usize] = bytes_vec[*k as usize] + num_to_distr as u8;
                continue;
            }
            let n: u8 = (num_to_distr / v[0]) as u8; // number which we will write to vec
            let v: u64 = n as u64 * v[0]; // value which 'n' denotes
            num_to_distr = num_to_distr - v; // decrease 'num_to_distr' to move to the next position in vec
            bytes_vec[*k as usize] = bytes_vec[*k as usize] + n;
        }

        return bytes_vec;
    } else {
        return vec![num as u8];
    }
}
