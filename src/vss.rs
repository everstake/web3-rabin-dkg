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

impl Verifier {
    /// new_verifier returns a Verifier out of:
    /// - its longterm secret key
    /// - the longterm dealer public key
    /// - the list of public key of verifiers. The list MUST include the public key
    /// of this Verifier also.
    /// The security parameter t of the secret sharing scheme is automatically set to
    /// a default safe value. If a different t value is required, it is possible to set
    /// it with verifier.set_t().
    pub fn new(longterm: FE, dealer: GE, verifiers: Vec<GE>) -> Result<Verifier, Box<dyn Error>> {
        let verifiers: Rc<[GE]> = verifiers.into();

        let generator = GE::generator();
        let pub_k: GE = generator.scalar_mul(&longterm.get_element());

        let index = verifiers
            .iter()
            .position(|point| point == &pub_k)
            .map(|i| i as u32)
            .ok_or_else(|| simple_error!("vss: public key not found in the list of verifiers"))?;
        let hkdf_context = dh::context(&dealer, &verifiers);

        let aggregator = Aggregator::new(dealer, verifiers.clone(), 0, Vec::new());

        Ok(Verifier {
            longterm,
            pub_k,
            dealer,
            verifiers,
            hkdf_context,
            index,
            aggregator,
        })
    }

    // process_encrypted_deal decrypt the deal received from the Dealer.
    /// If the deal is valid, i.e. the verifier can verify its shares
    /// against the public coefficients and the signature is valid, an approval
    /// response is returned and must be broadcasted to every participants
    /// including the dealer.
    /// If the deal itself is invalid, it returns a complaint response that must be
    /// broadcasted to every other participants including the dealer.
    /// If the deal has already been received, or the signature generation of the
    /// response failed, it returns an error without any responses.
    pub fn process_encrypted_deal(
        &mut self,
        encr_d: &EncryptedDeal,
    ) -> Result<Response, Box<dyn Error>> {
        let deal = self.decrypt_deal(encr_d)?;

        if deal.sec_share.i != self.index {
            bail!("vss: verifier got wrong index from deal")
        }

        let session_id = session_id(&self.dealer, self.verifiers(), &deal.commitments, deal.t);

        if deal.session_id != session_id {
            bail!("vss: session id doesn't match");
        }

        if self.aggregator.threshold == 0 {
            self.aggregator = Aggregator::new(
                self.dealer,
                self.verifiers.clone(),
                deal.t,
                deal.session_id.clone(),
            );
        }

        if self.aggregator.deal.t != 0 {
            bail!("vss: verifier already received a deal")
        }

        self.aggregator.session_id = deal.session_id.clone();
        self.aggregator.deal = deal.clone();

        let approved = deal.verify(&self.aggregator.verifiers, &session_id).is_ok();

        let r_hash = Response::hash(&session_id, self.index, approved as u32)?;
        let signature = sign::sign_msg(
            self.longterm.get_element().to_bytes(),
            self.pub_k.get_element().to_bytes(),
            &r_hash,
            &self.index.to_le_bytes(),
        )?;

        let response = Response {
            index: self.index,
            session_id: session_id.to_vec(),
            approved,
            signature,
        };

        self.aggregator.add_response(&response)?;

        Ok(response)
    }

    pub fn decrypt_deal(&mut self, encr_d: &EncryptedDeal) -> Result<Deal, Box<dyn Error>> {
        let eph_buff = encr_d.dh_key.get_element().to_bytes();

        // verify signature
        sign::verify_signature(
            self.dealer.get_element().to_bytes().as_ref(),
            encr_d.signature.as_ref(),
            eph_buff.as_ref(),
            self.index.to_le_bytes().as_ref(),
        )
        .map_err(|e| simple_error!("vss: signature verification failed: {}", e))?;

        // compute shared key and AES526-GCM cipher
        let pre: GE = dh::dh_exchange(&self.longterm, &encr_d.dh_key);
        let gcm = dh::new_aead(&pre, &self.hkdf_context);
        let nonce = GenericArray::from_slice(encr_d.nonce.as_slice());
        let decrypted = gcm.decrypt(
            nonce,
            Payload {
                msg: encr_d.cipher.as_ref(),
                aad: self.hkdf_context.as_ref(),
            },
        );
        let decrypted_vec =
            decrypted.map_err(|_| simple_error!("vss: failed decrypt AES526-GCM cipher deal"))?;
        let decoded: Deal = bincode::deserialize(&decrypted_vec[..])?;

        Ok(decoded)
    }

    pub fn deal_certified(&self) -> bool {
        self.aggregator.deal_certified()
    }

    pub fn enough_approvals(&self) -> bool {
        self.aggregator.enough_approvals()
    }

    // process_justification takes a Justification from dealer and returns an error if
    // something went wrong during the verification. If it is the case, that
    // probably means the Dealer is acting maliciously. In order to be sure, call
    // `v.EnoughApprovals()` and if true, `v.DealCertified()`.
    pub fn process_justification(
        &mut self,
        justification: &Justification,
    ) -> Result<(), Box<dyn Error>> {
        if self.aggregator.verifiers.len() <= justification.index as usize {
            bail!("vss: index out of bounds in justification")
        }

        // copy our session id to use later when we borrow mut self
        let session_id = self.session_id().to_vec();
        if session_id != justification.deal.session_id {
            bail!("vss: session id doesn't match");
        }

        let resp: &mut Response = self
            .aggregator
            .responses
            .get_mut(&justification.index)
            .ok_or_else(|| simple_error!("vss: no complaints received for this justification"))?;

        if resp.approved {
            bail!("vss: justification received for an approval")
        }

        // if aggregator isn't fully initialized
        if self.aggregator.deal.t == 0 {
            self.aggregator.session_id = justification.deal.session_id.clone();
            self.aggregator.deal = justification.deal.clone();
        }

        let verif = justification
            .deal
            .verify(&self.aggregator.verifiers, &session_id);

        if let Err(e) = verif {
            self.aggregator.bad_dealer = true;
            bail!(e);
        }

        resp.approved = true;

        Ok(())
    }

    pub fn set_timeout(&mut self) {
        self.aggregator.clean_verifiers();
    }

    // index returns the index of the verifier in the list of participants used
    // during this run of the protocol.
    pub fn index(&self) -> u32 {
        self.index
    }

    // key returns the longterm key pair this verifier is using during this protocol
    // run.
    pub fn key(&self) -> (FE, GE) {
        (self.longterm, self.pub_k)
    }

    // returns session id for this protocol run.
    pub fn session_id(&self) -> &[u8] {
        &self.aggregator.deal.session_id
    }

    // get_deal returns the Deal that this verifier has received. It returns
    // error if the deal is not certified or there is not enough approvals.
    pub fn get_deal(&self) -> Result<Deal, Box<dyn Error>> {
        if !self.aggregator.enough_approvals() || !self.aggregator.deal_certified() {
            bail!("Not enough approvals or deal not certified");
        }

        Ok(self.aggregator.deal.clone())
    }

    // process_response analyzes the given response. If it's a valid complaint, the
    // verifier should expect to see a Justification from the Dealer. It returns an
    // error if it's not a valid response.
    // Call `v.deal_certified()` to check if the whole protocol is finished.
    pub fn process_response(&mut self, resp: &Response) -> Result<(), Box<dyn Error>> {
        self.aggregator.verify_response(resp)
    }

    // unsafe_set_response_dkg is an UNSAFE bypass method to allow DKG to use VSS
    // that works on basis of approval only.
    pub(crate) fn unsafe_set_response_dkg(
        &mut self,
        index: u32,
        approved: bool,
    ) -> Result<(), Box<dyn Error>> {
        self.aggregator.unsafe_set_response_dkg(index, approved)
    }

    pub fn verifiers(&self) -> &[GE] {
        &self.verifiers
    }
}

impl Response {
    pub fn hash(session_id: &[u8], index: u32, approved: u32) -> Result<[u8; 32], Box<dyn Error>> {
        let mut hasher = Sha256::new();
        hasher.write_all(b"response".as_ref()).unwrap();
        hasher.write_all(session_id.as_ref()).unwrap();
        hasher.write_all(&index.to_le_bytes()).unwrap();
        hasher.write_all(&approved.to_le_bytes()).unwrap();
        let result = hasher.result().as_slice().try_into()?;
        Ok(result)
    }

    pub fn hash_self(&self) -> Result<[u8; 32], Box<dyn Error>> {
        Response::hash(&self.session_id, self.index, self.approved as u32)
    }
}

impl Justification {
    pub fn hash(session_id: &[u8], index: u32, deal: &Deal) -> Result<[u8; 32], Box<dyn Error>> {
        let mut hasher = Sha256::new();
        hasher.write_all(b"justification".as_ref()).unwrap();
        hasher.write_all(session_id.as_ref()).unwrap();
        hasher.write_all(&index.to_le_bytes()).unwrap();
        let deal_buff: Vec<u8> = bincode::serialize(deal)?;
        hasher.write_all(deal_buff.as_ref()).unwrap();
        let result = hasher.result().as_slice().try_into()?;
        Ok(result)
    }
}

impl Deal {
    /// analyzes the deal and returns an error if it's incorrect. If
    /// inclusion is true, it also returns an error if it the second time this struct
    /// analyzes a Deal.
    pub fn verify(&self, verifiers: &[GE], sid: &[u8]) -> Result<(), Box<dyn Error>> {
        if !valid_t(self.t, verifiers) {
            bail!("vss: invalid t received in Deal")
        }

        if sid != self.session_id.as_slice() {
            bail!("vss: find different sessionIDs from Deal")
        }

        let fi: PriShare<FE> = self.sec_share.clone();
        let gi: PriShare<FE> = self.rnd_share.clone();
        if fi.i != gi.i {
            bail!("vss: not the same index for f and g share in Deal")
        }
        if fi.i >= verifiers.len() as u32 {
            bail!("vss: index out of bounds in Deal")
        }
        // compute fi * G + gi * H
        let generator = GE::generator();
        let fig: GE = generator.scalar_mul(&fi.v.get_element());
        let h: GE = derive_h(&verifiers)?;
        let gih: GE = h.scalar_mul(&gi.v.get_element());
        let ci: GE = fig.add_point(&gih.get_element());

        let mut commitments: Vec<GE> = Vec::new();
        for comm in self.commitments.iter() {
            let point = GE::from_bytes(comm.as_ref())
                .map_err(|_| simple_error!("vss: error while construct point from bytes"))?;
            commitments.push(point);
        }
        let commit_poly: PubPoly = poly::PubPoly::new(generator, commitments);

        let pub_share: PubShare<GE> = commit_poly.eval(fi.i);
        if ci != pub_share.v {
            bail!("vss: share does not verify against commitments in Deal")
        }

        Ok(())
    }
}

/// Hash dealer and verifiers pub keys, committments to get a unique session id
pub fn session_id(dealer: &GE, verifiers: &[GE], commitments: &[Vec<u8>], t: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.input(dealer.get_element().to_bytes());

    for ver in verifiers {
        hasher.input(ver.get_element().to_bytes());
    }

    for comm in commitments {
        hasher.input(comm);
    }

    hasher.write_all(&t.to_le_bytes()).unwrap();

    hasher
        .result()
        .as_slice()
        .try_into()
        .expect("Slice with incorrect length")
}

/// Hash verifiers pub keys as bytes and return the hash as Point
pub fn derive_h(verifiers: &[GE]) -> Result<GE, Box<dyn Error>> {
    let points_bytes: Vec<[u8; 32]> = verifiers
        .iter()
        .map(|x| x.get_element().to_bytes())
        .collect();
    let buffer: Vec<u8> = points_bytes.concat();
    let hash = blake::new_blake2xb(buffer);
    for value in hash {
        for chunk in value.as_ref().chunks(32) {
            if let Ok(point) = ECPoint::from_bytes(chunk) {
                return Ok(point);
            }
        }
    }
    bail!("Error hash")
}

/// recover_secret recovers the secret shared by a Dealer by gathering at least t
/// Deals from the verifiers. It returns an error if there is not enough Deals or
/// if all Deals don't have the same SessionID.
pub fn recover_secret(deals: &[Deal], t: u32) -> Result<FE, Box<dyn Error>> {
    let mut shares: Vec<PriShare<FE>> = Vec::new();
    let sess_id: Vec<u8> = deals[0].session_id.clone();
    for deal in deals.iter() {
        if bitwise_eq(&sess_id[..], &deal.session_id[..]) {
            shares.push(deal.sec_share.clone());
        } else {
            bail!("vss: all deals need to have same session id")
        }
    }
    let secret: FE = poly::recover_secret(shares.as_mut_slice(), t)?;
    Ok(secret)
}