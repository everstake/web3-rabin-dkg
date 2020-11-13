use std::error::Error;

use crate::utils;

use curve25519_dalek::scalar::Scalar;

use crate::curve_traits;
use crate::ristretto_curve;

use curve_traits::{ECPoint, ECScalar};
use ristretto_curve::{FE, GE};

use schnorrkel::keys::PublicKey as schnrPubKey;
use schnorrkel::sign::Signature as schnrSig;

pub fn verify_signature(pub_k: &[u8], signature: &[u8], msg: &[u8], context: &[u8]) -> bool {
    let verif_key = schnrPubKey::from_bytes(pub_k).unwrap();
    let sign = schnrSig::from_bytes(signature).unwrap();
    let verify = verif_key.verify_simple(context, msg, &sign).is_ok();
    verify
}

pub fn sign_msg(
    scalar: [u8; 32],
    point: [u8; 32],
    msg: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let s = Scalar::from_bytes_mod_order(scalar);
    let mut sec_k: FE = ECScalar::new_random();
    sec_k.set_element(s);
    let pub_k = ECPoint::from_bytes(point.as_ref());
    if let false = pub_k.is_ok() {
        bail!("Error while reconstruct secret key from bytes")
    }
    let pub_k: GE = pub_k.unwrap();

    let keypair = utils::create_keypair(&sec_k, &pub_k)?;

    let signature = keypair.sign_simple(context, msg).to_bytes().to_vec();

    Ok(signature)
}
