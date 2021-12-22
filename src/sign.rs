//! Helper functions to sign and verify signatures
//! using Schnorr signature algorithm

use std::error::Error;

use curve25519_dalek::scalar::Scalar;

use crate::curve_traits::ECPoint;
use crate::ristretto_curve::{FE, GE};
use crate::utils;

use schnorrkel::keys::PublicKey as schnrPubKey;
use schnorrkel::sign::Signature as schnrSig;
use schnorrkel::SignatureError;

pub fn verify_signature(
    pub_k: &[u8],
    signature: &[u8],
    msg: &[u8],
    context: &[u8],
) -> Result<(), SignatureError> {
    let verif_key = schnrPubKey::from_bytes(pub_k)?;
    let sign = schnrSig::from_bytes(signature)?;
    verif_key.verify_simple(context, msg, &sign)?;
    Ok(())
}

pub fn sign_msg(
    scalar: [u8; 32],
    point: [u8; 32],
    msg: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let s = Scalar::from_bytes_mod_order(scalar);
    let sec_k = FE::from(s);
    let pub_k = GE::from_bytes(&point)
        .map_err(|_| simple_error!("Error while reconstruct pub key from bytes"))?;

    let keypair = utils::create_keypair(&sec_k, &pub_k)?;

    let signature = keypair.sign_simple(context, msg).to_bytes().to_vec();

    Ok(signature)
}
