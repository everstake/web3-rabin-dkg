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

#[cfg(test)]
mod tests {
    use crate::curve_traits;
    use crate::ristretto_curve;
    use aead::{generic_array::GenericArray, Aead, Payload};
    use curve_traits::{ECPoint, ECScalar};
    use ristretto_curve::{FE, GE};

    fn make_context() -> Vec<u8> {
        let generator: GE = ECPoint::generator();

        let priv1: FE = ECScalar::from(168 as u64);
        let priv2: FE = ECScalar::from(54 as u64);
        let priv3: FE = ECScalar::from(2089 as u64);
        let priv4: FE = ECScalar::from(8962 as u64);
        let priv5: FE = ECScalar::from(362 as u64);

        let pub_1: GE = generator.scalar_mul(&priv1.get_element());
        let pub_2: GE = generator.scalar_mul(&priv2.get_element());
        let pub_3: GE = generator.scalar_mul(&priv3.get_element());
        let pub_4: GE = generator.scalar_mul(&priv4.get_element());
        let pub_dealer: GE = generator.scalar_mul(&priv5.get_element());

        let verifiers: Vec<GE> = vec![pub_1, pub_2, pub_3, pub_4];

        super::context(&pub_dealer, &verifiers)
    }

    #[test]
    fn test_aead() {
        let generator: GE = ECPoint::generator();
        let priv1: FE = ECScalar::from(19846 as u64);
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
}