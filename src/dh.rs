use crate::curve_traits;
use crate::ristretto_curve;

use aead::{generic_array::GenericArray, NewAead};
use aes_gcm::Aes256Gcm;
use blake2b::blake2xb::Iter;
use blake2b::Blake2xb;
use curve_traits::{ECPoint, ECScalar};
use hkdf::Hkdf;
use ristretto_curve::{FE, GE};
use sha2::Sha256;

pub fn dh_exchange(own_priv: &FE, remote_public: &GE) -> GE {
    let sk: GE = remote_public.scalar_mul(&own_priv.get_element());
    sk
}

pub fn new_aead(pre_shared_key: &GE, context: &Vec<u8>) -> Aes256Gcm {
    let h = Hkdf::<Sha256>::new(None, &pre_shared_key.get_element().to_bytes());
    let mut shared_key = [0u8; 32];
    h.expand(context, &mut shared_key).unwrap();

    let key = GenericArray::clone_from_slice(&shared_key);
    let aead = Aes256Gcm::new(key);
    aead
}

pub fn context(dealer: &GE, verifiers: &Vec<GE>) -> Vec<u8> {
    let mut hash = Blake2xb::keyed(None, &String::from("vss-dealer").into_bytes()[..]);
    hash.update(&dealer.get_element().to_bytes());
    hash.update(&String::from("vss-verifiers").into_bytes()[..]);

    for point in verifiers.iter() {
        hash.update(&point.get_element().to_bytes());
    }

    let mut hash: Iter = hash.finish();
    let mut contx: Vec<u8> = Vec::new();
    let mut count = 1;

    loop {
        if let Some(value) = hash.next() {
            for symbol in value.as_ref().to_vec() {
                contx.push(symbol);
            }
        }
        if count == 0 {
            break;
        }
        count -= 1;
    }
    contx
}