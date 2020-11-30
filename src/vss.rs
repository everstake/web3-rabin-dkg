//! Verifiable secret sharing
//!
//! Can be used to share a secret with a group of verifiers.
//! The secret can be recovered only by a subset of at least T verifiers.

use std::collections::HashMap;
use std::convert::TryInto;
use std::error::Error;
use std::io::Write;
use std::rc::Rc;

use crate::blake;
use crate::curve_traits;
use crate::dh;
use crate::poly;
use crate::ristretto_curve;
use crate::sign;
use crate::utils;

use crate::poly::{PriPoly, PriShare, PubPoly, PubShare};
use aead::{generic_array::GenericArray, Aead, Payload};
use aes_gcm::Aes256Gcm;
use curve_traits::{ECPoint, ECScalar};
use ristretto_curve::{FE, GE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utils::bitwise_eq;

/// Dealer encapsulates for creating and distributing the shares and for
/// replying to any Responses.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Dealer {
    // private key of dealer
    long: FE,
    // public key of dealer
    pub_key: GE,
    // the secret to be shared
    secret: FE,
    // secret commits of the secret polynomial polynomial to be shared with verifiers
    secret_commits: Vec<Vec<u8>>,
    // pub keys of verifiers
    verifiers: Rc<[GE]>,
    // context for hkdf encryption
    hkdf_context: Vec<u8>,
    // threshold security parameter
    t: u32,
    // hash of stuff specific to the session: verifiers pub keys, dealer pub key, etc
    session_id: Vec<u8>,
    // Deals to be encrypted and distributed to verifiers. It is pub(crate) for tests.
    pub(crate) deals: Vec<Deal>,
    // Collects deals and responses
    aggregator: Aggregator,
}

/// Aggregator is used to collect all deals, and responses for one protocol run.
/// It brings common functionalities for both Dealer and Verifier structs.
/// If threshold is 0, Aggregator is in invalid state and should be populated with correct data.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Aggregator {
    // Pub key of dealer
    dealer: GE,
    // Pub keys of verifiers
    verifiers: Rc<[GE]>,
    // Map between participant id and response
    responses: HashMap<u32, Response>,
    // All Responses received have to have the same session_id
    session_id: Vec<u8>,
    // Deal, used for distributed secret reconstruction
    deal: Deal,
    // Security parameter T. If 0, means Aggregator isn't fully initialized
    threshold: u32,
    // set bad_dealer to true, so that deal_certified always returns false
    bad_dealer: bool,
}

/// Deal encapsulates the verifiable secret share and is sent by the dealer to a verifier.
#[derive(Default, Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Deal {
    pub session_id: Vec<u8>,
    // Share of distributed secret
    pub sec_share: PriShare<FE>,
    // Share of random, used for share verification
    pub rnd_share: PriShare<FE>,
    // Threshold security parameter
    pub t: u32,
    // Polynomial committments for share verification
    pub commitments: Vec<Vec<u8>>,
}

/// EncryptedDeal contains the deal in a encrypted form only decipherable by the
/// correct recipient. The encryption is performed in a similar manner as what is
/// done in TLS. The dealer generates a temporary key pair, signs it with its
/// longterm secret key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedDeal {
    // Ephemeral Diffie Hellman key
    pub dh_key: GE,
    // Signature of the DH key by the longterm key of the dealer
    pub signature: Vec<u8>,
    // Nonce used for the encryption
    pub nonce: Vec<u8>,
    // AEAD encryption of the deal marshalled by protobuf
    pub cipher: Vec<u8>,
}

/// Response is sent by the verifiers to all participants and holds each
/// individual validation or refusal of a Deal.
#[derive(Clone, Default, Debug, PartialEq, Deserialize, Serialize)]
pub struct Response {
    // SessionID related to this run of the protocol
    pub session_id: Vec<u8>,
    // Index of the verifier issuing this Response
    pub index: u32,
    // Approved is true if the Response is valid
    pub approved: bool,
    // Signature over the whole packet
    pub signature: Vec<u8>,
}

/// Justification is a message that is broadcasted by the Dealer in response to
/// a Complaint. It contains the original Complaint as well as the shares
/// distributed to the complainer.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Justification {
    // SessionID related to the current run of the protocol
    pub session_id: Vec<u8>,
    // Index of the verifier who issued the Complaint,i.e. index of this Deal
    pub index: u32,
    // Deal in cleartext
    pub deal: Deal,
    // Signature over the whole packet
    pub signature: Vec<u8>,
}

/// Verifier receives a Deal from a Dealer, can reply with a Complaint, and can
/// collaborate with other Verifiers to reconstruct a secret.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Verifier {
    // Longterm secret (priv key) of Verifier
    longterm: FE,
    // Public key of Verifier
    pub_k: GE,
    // Public key of dealer
    dealer: GE,
    // Index of this verifier
    index: u32,
    // Pub keys of verifiers (including our pub key)
    verifiers: Rc<[GE]>,
    // Context for hkdf function
    hkdf_context: Vec<u8>,
    aggregator: Aggregator,
}