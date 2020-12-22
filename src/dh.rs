//! The Diffie–Hellman key exchange method allows two parties
//! that have no prior knowledge of each other to jointly establish
//! a shared secret key over an insecure channel.
//!
//! AEAD stands for authenticated encryption with associated data,
//! is used to encrypt messages using pre-shared key. Message can
//! have both encrypted and unencrypted parts.

use {
    crate::{curve_traits, ristretto_curve},
    aead::{generic_array::GenericArray, NewAead},
    aes_gcm::Aes256Gcm,
    blake2b::{blake2xb::Iter, Blake2xb},
    curve_traits::{ECPoint, ECScalar},
    hkdf::Hkdf,
    ristretto_curve::{FE, GE},
    sha2::Sha256,
};

/// Compute shared private key from public input
pub fn dh_exchange(own_priv: &FE, remote_public: &GE) -> GE {
    remote_public.scalar_mul(&own_priv.get_element())
}

/// Creates AEAD object with key derived using HKDF
///
/// `pre_shared_key`: a symmetric key you have shared previously, for example,
/// using dh_exchange
///
/// `context`: a byte string of any length that must be unique to the key produced
///
/// https://eprint.iacr.org/2010/264.pdf
pub fn new_aead(pre_shared_key: &GE, context: &[u8]) -> Aes256Gcm {
    let input_key_material = &pre_shared_key.get_element().to_bytes();
    let h = Hkdf::<Sha256>::new(None, input_key_material);

    let mut shared_key = [0u8; 32];
    h.expand(context, &mut shared_key).unwrap();

    let key = GenericArray::clone_from_slice(&shared_key);
    Aes256Gcm::new(key)
}

/// Create context byte string for new_aead from dealer and verifiers pub keys.
pub fn context(dealer: &GE, verifiers: &[GE]) -> Vec<u8> {
    let mut hash = Blake2xb::keyed(None, b"vss-dealer");
    hash.update(&dealer.get_element().to_bytes());
    hash.update(b"vss-verifiers");

    for point in verifiers.iter() {
        hash.update(point.get_element().as_bytes());
    }

    let hash: Iter = hash.finish();

    let mut contx: Vec<u8> = Vec::new();
    for value in hash.take(2) {
        contx.extend_from_slice(&value);
    }

    contx
}

#[cfg(test)]
mod tests {
    use crate::curve_traits;
    use crate::ristretto_curve;
    use aead::{generic_array::GenericArray, Aead, Payload};
    use curve_traits::{ECPoint, ECScalar};
    use ristretto_curve::{FE, GE};

    use super::dh_exchange;

    fn make_context() -> Vec<u8> {
        let generator = GE::generator();

        let priv1 = FE::from(168 as u64);
        let priv2 = FE::from(54 as u64);
        let priv3 = FE::from(2089 as u64);
        let priv4 = FE::from(8962 as u64);
        let priv5 = FE::from(362 as u64);

        let pub_1: GE = generator.scalar_mul(&priv1.get_element());
        let pub_2: GE = generator.scalar_mul(&priv2.get_element());
        let pub_3: GE = generator.scalar_mul(&priv3.get_element());
        let pub_4: GE = generator.scalar_mul(&priv4.get_element());
        let pub_dealer: GE = generator.scalar_mul(&priv5.get_element());

        let verifiers = [pub_1, pub_2, pub_3, pub_4];

        super::context(&pub_dealer, &verifiers)
    }

    #[test]
    fn test_aead() {
        let generator = GE::generator();
        let priv1 = FE::from(19846 as u64);
        let pub_1: GE = generator.scalar_mul(&priv1.get_element());

        let context = make_context();
        let aead = super::new_aead(&pub_1, &context);

        let pay = Payload {
            msg: b"super phrase".as_ref(),
            aad: context.as_ref(),
        };
        let nonce = GenericArray::from_slice(&[0u8; 12]);

        let ciphertext = aead.encrypt(nonce, pay).expect("encryption failure!");
        let plaintext = aead
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext.as_ref(),
                    aad: context.as_ref(),
                },
            )
            .expect("decryption failure!");
        assert_eq!(&plaintext, b"super phrase");
    }

    #[test]
    fn test_dh() {
        let generator = GE::generator();
        let priv1 = FE::from(19846);
        let pub_1: GE = generator.scalar_mul(&priv1.get_element());

        let priv2 = FE::from(271637);
        let pub_2: GE = generator.scalar_mul(&priv2.get_element());

        let shared_priv_1 = dh_exchange(&priv1, &pub_2);
        let shared_priv_2 = dh_exchange(&priv2, &pub_1);

        assert_eq!(shared_priv_1, shared_priv_2);
    }
}
