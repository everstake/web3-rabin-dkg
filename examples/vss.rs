//! Verifiable secret sharing
//!
//! Suppose you (a dealer) want to share some secret with a number of people (verifiers),
//! such that they only can know the secret if they cooperate in a group of at least T.
//!
//! You then create Dealer, passing the secret to share and pubkeys of verifiers.
//! Dealer creates encrypted deals: shares of the secret, each share can be decrypted only
//! by one verifier, its recepient.
//!
//! Verifiers receive encrypted deals and produce responses, which indicate if encrypted deal is valid.
//! These responses should be broadcasted to every other Verifier. Once a verifier receives at least t
//! valid responses, he can return the decrypted deal. If at least t decrypted deals is collected,
//! they can be used to recover the secret.
use threshold_dkg::{
    curve_traits::{ECPoint, ECScalar},
    ristretto_curve::{FE, GE},
    vss::{minimum_t, recover_secret, Dealer, Verifier},
};
fn main() {
    // generator element of the cryptographic group
    let generator = GE::generator();
    let longterm_dealer_priv_key = FE::new_random();
    let longterm_dealer_pub_key = generator.scalar_mul(&longterm_dealer_priv_key.get_element());
    // number of verifiers to participate in vss
    let n_verifiers = 7;
    // safe threshold parameter
    let threshold = minimum_t(n_verifiers);
    let verifiers_priv_keys = (0..n_verifiers)
        .map(|_| FE::new_random())
        .collect::<Vec<_>>();
    let verifiers_pub_keys = verifiers_priv_keys
        .iter()
        .map(|pk| generator.scalar_mul(&pk.get_element()))
        .collect::<Vec<_>>();
    let mut verifiers = verifiers_priv_keys
        .iter()
        .map(|pk| {
            Verifier::new(
                pk.clone(),
                longterm_dealer_pub_key,
                verifiers_pub_keys.clone(),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to create verifiers");
    println!("\nAll the Verifiers have generated their priv keys and create Verifier struct with pub key of Dealer");
    let secret_to_share = FE::new_random();
    let dealer = Dealer::new(
        longterm_dealer_priv_key,
        secret_to_share,
        verifiers_pub_keys.clone(),
        threshold,
    )
    .expect("Failed to create dealer");
    println!("\nDealer create Dealer struct with secret to share, pub keys of Verifiers and other VSS data");
    println!("Shared secret - {:?}", secret_to_share);
    let encrypted_deals = dealer.encrypt_deals().expect("Failed to encrypt deals");
    println!("\nDealer generate deals for all the Verifiers");
    let mut resps = Vec::new();
    for (enc_deal, verifier) in encrypted_deals.iter().zip(&mut verifiers) {
        let resp = verifier
            .process_encrypted_deal(enc_deal)
            .expect("Failed to process deal");
        resps.push(resp);
    }
    println!("\nEvery Verifier receive and process Deal and then sends Response back to the Dealer");
    for resp in &resps {
        for (i, v) in verifiers.iter_mut().enumerate() {
            if resp.index != i as u32 {
                v.process_response(&resp).unwrap();
            }
        }
    }
    let deals = verifiers
        .iter()
        .map(Verifier::get_deal)
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to get all deals");
    // not all deals needed, subset of size `threshold` is enough
    let recovered_secret = recover_secret(&deals[0..threshold as usize], threshold).unwrap();
    println!("\nNow if we have threshold of certified Deals we can reconstruct secret");
    println!("\nRecovered secret - {:?}", recovered_secret);
    assert_eq!(recovered_secret, secret_to_share);
}