//! Misc helper functions used by other modules

use std::convert::TryInto;
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
    let keypair = Keypair::from_bytes(byte_keys.as_ref())
        .map_err(|_| simple_error!("vss: error while create keypair from secret"))?;
    Ok(keypair)
}

pub fn rand_hack() -> impl RngCore + CryptoRng {
    ::rand_core::OsRng
}

pub fn arr32_from_slice(bytes: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
    Ok(bytes.try_into()?)
}

// Compare byte strings in constant time (linear in min(a, b))
pub fn bitwise_eq(a: &[u8], b: &[u8]) -> bool {
    let diff = a
        .iter()
        .zip(b.iter())
        .map(|(a, b)| a ^ b)
        .fold(0, |acc, x| acc | x);
    diff == 0 && a.len() == b.len()
}
