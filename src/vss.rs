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

pub fn valid_t(t: u32, verifiers: &[GE]) -> bool {
    t >= 2 && t <= verifiers.len() as u32
}

// minimum_t returns the minimum safe T that is proven to be secure with this
// protocol. It expects n, the total number of participants.
// WARNING: Setting a lower T could make
// the whole protocol insecure. Setting a higher T only makes it harder to
// reconstruct the secret.
pub fn minimum_t(n: u32) -> u32 {
    (n + 1) / 2
}

impl Dealer {
    /// creates a Dealer capable of leading the secret sharing scheme. It
    /// does not have to be trusted by other Verifiers. The security parameter t is
    /// the number of shares required to reconstruct the secret. It is HIGHLY
    /// RECOMMENDED to use a threshold higher or equal than what the method
    /// minimum_t() returns, otherwise it breaks the security assumptions of the whole
    /// scheme. It returns an error if the t is inferior or equal to 2.
    ///
    /// `longterm`: private key of dealer
    /// `secret`: the secret to be shared with verifiers
    /// `verifiers`: list of pubkeys of verifiers
    /// `threshold`: security parameter t. Any t+1 share holders can recover the secret
    pub fn new(
        longterm: FE,
        secret: FE,
        verifiers: Vec<GE>,
        threshold: u32,
    ) -> Result<Dealer, Box<dyn Error>> {
        if !valid_t(threshold, &verifiers) {
            bail!("Invalid threshold")
        }

        let h: GE = derive_h(&verifiers)?;
        let sec_pri_poly: PriPoly = PriPoly::new(threshold, Some(secret));
        let rand_pri_poly: PriPoly = PriPoly::new(threshold, None);

        let generator = GE::generator();
        let dealer_pub: GE = generator.scalar_mul(&longterm.get_element());

        // Compute public polynomial coefficients
        let f_pub: PubPoly = sec_pri_poly.commit(Some(generator));
        let g_pub: PubPoly = rand_pri_poly.commit(Some(h));

        let c: PubPoly = f_pub.add(&g_pub)?;

        let (_, commitments) = c.info();
        let commitments: Vec<Vec<u8>> = commitments
            .iter()
            .map(|x| x.get_element().to_bytes().to_vec())
            .collect();

        let session_id: [u8; 32] = session_id(&dealer_pub, &verifiers, &commitments, threshold);

        let verifiers: Rc<[GE]> = verifiers.into();

        let aggregator = Aggregator::new(
            dealer_pub,
            verifiers.clone(),
            threshold,
            session_id.to_vec(),
        );

        // deals are to be encrypted and distributed to respective
        // verifiers, one deal per verifier
        let deals: Vec<Deal> = (0..verifiers.len() as u32)
            .map(|i| {
                let sec_share: PriShare<FE> = sec_pri_poly.eval(i as u32);
                let rnd_share: PriShare<FE> = rand_pri_poly.eval(i as u32);
                Deal {
                    session_id: session_id.to_vec(),
                    sec_share,
                    rnd_share,
                    t: threshold,
                    commitments: commitments.clone(),
                }
            })
            .collect();

        let hkdf_context: Vec<u8> = dh::context(&dealer_pub, &verifiers);

        let (_, secret_commits) = f_pub.info();
        let secret_commits: Vec<Vec<u8>> = secret_commits
            .iter()
            .map(|x| x.get_element().to_bytes().to_vec())
            .collect();

        Ok(Dealer {
            long: longterm,
            pub_key: dealer_pub,
            session_id: session_id.to_vec(),
            secret,
            secret_commits,
            verifiers,
            hkdf_context,
            t: threshold,
            deals,
            aggregator,
        })
    }

    /// encrypt_deal returns the encryption of the deal that must be given to the
    /// verifier at index i.
    /// The dealer first generates a temporary Diffie Hellman key, signs it using its
    /// longterm key, and computes the shared key depending on its longterm and
    /// ephemeral key and the verifier's public key.
    /// This shared key is then fed into a HKDF whose output is the key to a AEAD
    /// (AES256-GCM) scheme to encrypt the deal.
    pub fn encrypt_deal(&self, i: u32) -> Result<EncryptedDeal, Box<dyn Error>> {
        let v_pub = self
            .verifiers
            .get(i as usize)
            .ok_or_else(|| simple_error!("dealer: wrong index to generate encrypted deal"))?;

        // gen ephemeral key
        let generator = GE::generator();
        let dh_secret: FE = ECScalar::new_random();
        let dh_key: GE = generator.scalar_mul(&dh_secret.get_element());
        // signs the public key
        let dh_pub_buf: [u8; 32] = dh_key.get_element().to_bytes();
        let signature = sign::sign_msg(
            self.long.get_element().to_bytes(),
            self.pub_key.get_element().to_bytes(),
            &dh_pub_buf,
            &i.to_le_bytes(),
        )?;

        // AES256-GCM
        let pre: GE = dh::dh_exchange(&dh_secret, v_pub);
        let gcm: Aes256Gcm = dh::new_aead(&pre, &self.hkdf_context);

        let nonce = GenericArray::from_slice(&[0u8; 12]);
        let deal = self
            .deals
            .get(i as usize)
            .ok_or_else(|| simple_error!("dealer: wrong index to get deal"))?;
        let deal_buff: Vec<u8> = bincode::serialize(deal)?;
        let pay = Payload {
            msg: deal_buff.as_ref(),
            aad: self.hkdf_context.as_ref(),
        };
        let cipher = gcm
            .encrypt(nonce, pay)
            .map_err(|_| simple_error!("vss: encryption failure!"))?;

        Ok(EncryptedDeal {
            cipher,
            nonce: nonce.to_vec(),
            dh_key,
            signature,
        })
    }

    // deal_certified returns true if there has been less than t complaints, all
    // Justifications were correct and if enough_approvals() returns true.
    pub fn deal_certified(&self) -> bool {
        self.aggregator.deal_certified()
    }

    /// encrypt_deals calls encrypt_deal for each index of the verifier and
    /// returns the list of encrypted deals. Each index in the returned slice
    /// corresponds to the index in the list of verifiers.
    pub fn encrypt_deals(&self) -> Result<Vec<EncryptedDeal>, Box<dyn Error>> {
        (0..self.verifiers.len() as u32)
            .map(|i| self.encrypt_deal(i))
            .collect()
    }

    /// process_response analyzes the given Response. If it's a valid complaint, then
    /// it returns a Justification. This Justification must be broadcasted to every
    /// participants. If it's an invalid complaint, it returns an error about the
    /// complaint. The verifiers will also ignore an invalid Complaint.
    pub fn process_response(
        &mut self,
        r: &Response,
    ) -> Result<Option<Justification>, Box<dyn Error>> {
        self.aggregator.verify_response(r)?;

        if r.approved {
            return Ok(None);
        }

        let j_hash = Justification::hash(&self.session_id, r.index, &self.deals[r.index as usize])?;
        let signature = sign::sign_msg(
            self.long.get_element().to_bytes(),
            self.pub_key.get_element().to_bytes(),
            &j_hash,
            &r.index.to_le_bytes(),
        )?;

        Ok(Some(Justification {
            session_id: self.session_id.clone(),
            index: r.index,
            deal: self.deals[r.index as usize].clone(),
            signature,
        }))
    }

    /// secret_commit returns the commitment of the secret being shared by this
    /// dealer. This function is only to be called once the deal has enough approvals
    /// and is verified otherwise it returns Err.
    pub fn secret_commit(&self) -> Result<GE, Box<dyn Error>> {
        if !self.aggregator.enough_approvals() || !self.deal_certified() {
            bail!("Not enough approvas or the deal is not certified");
        }

        let generator = GE::generator();
        Ok(generator.scalar_mul(&self.secret.get_element()))
    }

    /// commits returns the commitments of the coefficient of the secret polynomial
    /// the Dealer is sharing.
    pub fn commits(&self) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
        if !self.aggregator.enough_approvals() || !self.deal_certified() {
            bail!("Not enough approvas or the deal is not certified");
        }

        Ok(self.secret_commits.clone())
    }

    /// key returns the longterm key pair used by this Dealer.
    pub fn key(&self) -> (FE, GE) {
        (self.long, self.pub_key)
    }

    /// get_session_id returns the current sessionID generated by this dealer for this
    /// protocol run.
    pub fn get_session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// set_timeout tells this dealer to consider this moment the maximum time limit.
    /// it calls cleanVerifiers which will take care of all Verifiers who have not
    /// responded until now.
    pub fn set_timeout(&mut self) {
        self.aggregator.clean_verifiers()
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
}

impl Aggregator {
    pub fn new(dealer: GE, verifiers: Rc<[GE]>, threshold: u32, session_id: Vec<u8>) -> Self {
        Self {
            dealer,
            verifiers,
            session_id,
            threshold,
            responses: HashMap::new(),
            deal: Deal::default(),
            bad_dealer: false,
        }
    }

    pub fn verify_response(&mut self, r: &Response) -> Result<(), Box<dyn Error>> {
        let s1: [u8; 32] = r.session_id.as_slice().try_into()?;
        let s2: [u8; 32] = self.session_id.as_slice().try_into()?;

        if !bitwise_eq(&s1, &s2) {
            bail!("vss: receiving inconsistent sessionID in response");
        }
        let pub_k = self
            .verifiers
            .get(r.index as usize)
            .ok_or_else(|| simple_error!("vss: index out of bounds in response"))?;
        // schnorrkel PublicKey to verify signature
        let response_h = r.hash_self()?;

        sign::verify_signature(
            pub_k.get_element().to_bytes().as_ref(),
            r.signature.as_ref(),
            response_h.as_ref(),
            r.index.to_le_bytes().as_ref(),
        )
        .map_err(|e| simple_error!("vss: incorrect response signature: {}", e))?;

        self.add_response(r)?;

        Ok(())
    }

    pub fn add_response(&mut self, r: &Response) -> Result<(), Box<dyn Error>> {
        if self.verifiers.len() <= r.index as usize {
            bail!("vss: index out of bounds in Respose")
        }
        if self.responses.contains_key(&r.index) {
            bail!("vss: already existing response from same origin")
        }
        self.responses.insert(r.index, r.clone());

        Ok(())
    }

    pub(crate) fn unsafe_set_response_dkg(
        &mut self,
        index: u32,
        approved: bool,
    ) -> Result<(), Box<dyn Error>> {
        let r = Response {
            session_id: self.session_id.clone(),
            index,
            approved,
            ..Default::default()
        };
        self.add_response(&r)
    }

    // clean_verifiers checks the aggregator's response array and creates a StatusComplaint
    // response for all verifiers who have no response in the array.
    pub fn clean_verifiers(&mut self) {
        for i in 0..self.verifiers.len() as u32 {
            if self.responses.get(&i).is_none() {
                let response = Response {
                    session_id: self.deal.session_id.clone(),
                    index: i,
                    approved: false,
                    ..Default::default()
                };
                self.responses.insert(i, response);
            }
        }
    }

    // enough_approvals returns true if enough verifiers have sent their approval for
    // the deal they received.
    pub fn enough_approvals(&self) -> bool {
        let n_approved = self.responses.values().filter(|r| r.approved).count();
        n_approved as u32 >= self.threshold
    }

    // deal_certified returns true if there has been less than t complaints, all
    // Justifications were correct and if enough_approvals() returns true.
    pub fn deal_certified(&self) -> bool {
        if self.threshold == 0 {
            return false;
        }

        let verifiers_stable =
            (0..self.verifiers.len() as u32).all(|i| self.responses.contains_key(&i));

        let too_much_complaints: bool = !verifiers_stable || self.bad_dealer;
        self.enough_approvals() && !too_much_complaints
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve_traits;
    use crate::ristretto_curve;
    use dh::*;
    use utils::bitwise_eq;

    use curve_traits::{ECPoint, ECScalar};
    use ristretto_curve::{FE, GE};
    use schnorrkel::context::signing_context;
    use schnorrkel::{Keypair, Signature};

    struct InitData {
        nb_verifiers: u32,
        vss_threshold: u32,
        verifiers_pub: Vec<GE>,
        verifiers_sec: Vec<FE>,
        dealer_pub: GE,
        dealer_sec: FE,
        secret: FE,
    }

    fn setup(nb_verifiers: u32) -> InitData {
        let (verifiers_sec, verifiers_pub) = gen_commits(nb_verifiers);
        let (dealer_sec, dealer_pub) = gen_pair();
        let (secret, _) = gen_pair();
        let vss_threshold: u32 = minimum_t(nb_verifiers);
        InitData {
            nb_verifiers,
            vss_threshold,
            verifiers_pub,
            verifiers_sec,
            dealer_pub,
            dealer_sec,
            secret,
        }
    }

    fn gen_pair() -> (FE, GE) {
        let generator = GE::generator();
        let g_scalar: FE = ECScalar::new_random();
        let g_point: GE = generator.scalar_mul(&g_scalar.get_element());
        (g_scalar, g_point)
    }

    fn gen_commits(n: u32) -> (Vec<FE>, Vec<GE>) {
        (0..n).map(|_| gen_pair()).unzip()
    }

    fn gen_dealer(
        dealer_sec: FE,
        secret: FE,
        verifiers_pub: Vec<GE>,
        vss_threshold: u32,
    ) -> super::Dealer {
        Dealer::new(dealer_sec, secret, verifiers_pub, vss_threshold).unwrap()
    }

    fn gen_all(data: &InitData) -> (Dealer, Vec<Verifier>) {
        let dealer: Dealer = gen_dealer(
            data.dealer_sec,
            data.secret,
            data.verifiers_pub.clone(),
            data.vss_threshold,
        );
        let mut verifiers: Vec<Verifier> = Vec::new();
        for i in 0..data.nb_verifiers {
            let v: Verifier = Verifier::new(
                data.verifiers_sec[i as usize],
                data.dealer_pub,
                data.verifiers_pub.clone(),
            )
            .unwrap();
            verifiers.push(v);
        }
        (dealer, verifiers)
    }

    fn custom_signature() -> Vec<u8> {
        let keypair: Keypair = Keypair::generate_with(utils::rand_hack());
        let context = signing_context(b"some context");
        let message: &[u8] = b"Very secret message";
        let signature: Signature = keypair.sign(context.bytes(message));
        signature.to_bytes().to_vec()
    }

    #[test]
    fn test_vss_whole() {
        let init_data: InitData = setup(7);
        let (mut dealer, mut verifiers) = gen_all(&init_data);

        // 1. dispatch deal
        let mut resps: Vec<Response> = Vec::new();
        let enc_deals: Vec<EncryptedDeal> = dealer.encrypt_deals().unwrap();
        for (i, deal) in enc_deals.iter().enumerate() {
            let resp: Response = verifiers[i].process_encrypted_deal(&deal).unwrap();
            resps.push(resp);
        }

        // 2. dispatch responces
        for resp in resps.iter() {
            for (i, v) in verifiers.iter_mut().enumerate() {
                if resp.index == i as u32 {
                    continue;
                }
                v.process_response(&resp).unwrap();
            }
            // 2.1. check dealer
            let justification = dealer.process_response(&resp).unwrap();
            assert_eq!(None, justification);
        }

        // 3. check certified
        for v in verifiers.iter() {
            assert!(v.aggregator.deal_certified());
        }

        // 4. collect deals
        let mut deals: Vec<Deal> = Vec::new();
        for v in verifiers.iter_mut() {
            let d: Deal = v.get_deal().unwrap();
            deals.push(d);
        }

        // 5. recover
        let sec = recover_secret(&deals, init_data.vss_threshold).unwrap();
        assert_eq!(sec, dealer.secret);
    }

    #[test]
    fn test_vss_dealer_new() {
        let init_data: InitData = setup(7);
        Dealer::new(
            init_data.dealer_sec,
            init_data.secret,
            init_data.verifiers_pub.clone(),
            init_data.vss_threshold,
        )
        .expect("Failed to create dealer");

        for threshold in 0..=1 {
            Dealer::new(
                init_data.dealer_sec,
                init_data.secret,
                init_data.verifiers_pub.clone(),
                threshold as u32,
            )
            .expect_err("Can't create dealer with threshold 0, 1");
        }
    }

    #[test]
    fn test_vss_verifier_new() {
        let init_data: InitData = setup(7);
        let rnd_index = 4;
        let v = Verifier::new(
            init_data.verifiers_sec[rnd_index as usize],
            init_data.dealer_pub,
            init_data.verifiers_pub.clone(),
        )
        .expect("Must create verifier");

        assert_eq!(rnd_index as u32, v.index);

        let rand_scalar: FE = ECScalar::new_random();
        Verifier::new(rand_scalar, init_data.dealer_pub, init_data.verifiers_pub)
            .expect_err("Can't create verifier with wrong longterm secret");
    }

    #[test]
    fn test_vss_share() {
        let init_data: InitData = setup(7);
        let (dealer, mut verifiers) = gen_all(&init_data);

        let ver: &mut Verifier = &mut verifiers[0];
        let deal: EncryptedDeal = dealer.encrypt_deal(0 as u32).unwrap();

        let resp: Response = ver.process_encrypted_deal(&deal).unwrap();

        assert!(resp.approved);

        for i in 0..ver.aggregator.threshold - 1 {
            ver.aggregator.responses.insert(
                i as u32,
                Response {
                    approved: true,
                    ..Default::default()
                },
            );
        }

        ver.set_timeout();

        // not enough approvals
        ver.get_deal().expect_err("Not enough approvals");
        ver.aggregator.responses.insert(
            ver.aggregator.threshold,
            Response {
                approved: true,
                ..Default::default()
            },
        );
        // deal not certified
        ver.aggregator.bad_dealer = true;
        ver.get_deal().expect_err("Must fail, bad dealer");
        ver.aggregator.bad_dealer = false;
        ver.get_deal().expect("Must work fine");
    }

    #[test]
    fn test_vss_aggregator_enough_approvals() {
        let init_data: InitData = setup(7);
        let (mut dealer, _) = gen_all(&init_data);

        for i in 0..dealer.aggregator.threshold - 1 {
            dealer.aggregator.responses.insert(
                i as u32,
                Response {
                    approved: true,
                    ..Default::default()
                },
            );
        }

        dealer.set_timeout();

        assert!(!dealer.aggregator.enough_approvals());
        assert!(dealer.secret_commit().is_err());

        dealer.aggregator.responses.insert(
            dealer.aggregator.threshold,
            Response {
                approved: true,
                ..Default::default()
            },
        );
        assert!(dealer.aggregator.enough_approvals());

        for i in (dealer.aggregator.threshold + 1)..init_data.nb_verifiers {
            dealer.aggregator.responses.insert(
                i as u32,
                Response {
                    approved: true,
                    ..Default::default()
                },
            );
        }
        assert!(dealer.aggregator.enough_approvals());
        let generator = GE::generator();
        let s = generator.scalar_mul(&init_data.secret.get_element());
        assert_eq!(s, dealer.secret_commit().unwrap());
    }

    #[test]
    fn test_vss_aggregator_deal_certified() {
        let init_data: InitData = setup(7);
        let (mut dealer, _) = gen_all(&init_data);

        for i in 0..dealer.aggregator.threshold {
            dealer.aggregator.responses.insert(
                i as u32,
                Response {
                    approved: true,
                    ..Default::default()
                },
            );
        }

        dealer.set_timeout();

        assert!(dealer.aggregator.deal_certified());
        let generator = GE::generator();
        let s = generator.scalar_mul(&init_data.secret.get_element());
        assert_eq!(s, dealer.secret_commit().unwrap());
        // bad dealer response
        dealer.aggregator.bad_dealer = true;
        assert!(!dealer.aggregator.deal_certified());
        assert!(dealer.secret_commit().is_err());
        // inconsistent state on purpose
        // too much complaints
        for i in 0..dealer.aggregator.threshold {
            dealer.aggregator.responses.insert(
                i as u32,
                Response {
                    approved: false,
                    ..Default::default()
                },
            );
        }
        assert!(!dealer.aggregator.deal_certified());
    }

    #[test]
    fn test_vss_verifier_decrypt_deal() {
        let init_data: InitData = setup(7);
        let (dealer, mut verifiers) = gen_all(&init_data);
        let d: &Deal = &dealer.deals[0];
        let v: &mut Verifier = &mut verifiers[0];

        // all fine
        let mut enc_deal: EncryptedDeal = dealer.encrypt_deal(0).unwrap();
        let dec_deal: Deal = v.decrypt_deal(&enc_deal).unwrap();
        let d1: Vec<u8> = bincode::serialize(d).unwrap();
        let d2: Vec<u8> = bincode::serialize(&dec_deal).unwrap();
        assert!(bitwise_eq(&d1, &d2));

        // wrong dh key
        let correct_dh = enc_deal.dh_key;
        enc_deal.dh_key = ECPoint::generator();
        v.decrypt_deal(&enc_deal).expect_err("Wrong dh key");
        enc_deal.dh_key = correct_dh;

        // wrong signature
        let correct_sig = enc_deal.signature.clone();
        enc_deal.signature = custom_signature();
        v.decrypt_deal(&enc_deal).expect_err("Wrong signature");

        enc_deal.signature = correct_sig;

        // wrong cipgertext
        let correct_cipher = enc_deal.cipher.clone();
        enc_deal.cipher = [0u8; 64].to_vec();
        let dec_deal = v.decrypt_deal(&enc_deal);
        assert!(dec_deal.is_err());
        enc_deal.cipher = correct_cipher;
    }

    #[test]
    fn test_vss_verifier_receive_deal_correct_deal() {
        let init_data: InitData = setup(7);
        let (dealer, mut verifiers) = gen_all(&init_data);
        let unm_dealer = dealer.clone();
        let v: &mut Verifier = &mut verifiers[0];

        let enc_deal: EncryptedDeal = unm_dealer.encrypt_deal(0).unwrap();

        let resp = v.process_encrypted_deal(&enc_deal).unwrap();
        assert!(resp.approved);
        assert_eq!(v.index, resp.index);
        assert_eq!(dealer.session_id, resp.session_id);
        let contx = resp.hash_self().unwrap();

        sign::verify_signature(
            &v.pub_k.get_element().to_bytes(),
            &resp.signature,
            &contx,
            &v.index.to_le_bytes(),
        )
        .expect("Signature must be valid");

        assert_eq!(resp, *v.aggregator.responses.get(&v.index).unwrap());
    }

    #[test]
    fn test_vss_verifier_receive_deal_wrong_encryption() {
        let init_data: InitData = setup(7);
        let (dealer, mut verifiers) = gen_all(&init_data);
        let v: &mut Verifier = &mut verifiers[0];

        let mut enc_deal: EncryptedDeal = dealer.encrypt_deal(0).unwrap();

        enc_deal.signature = custom_signature();
        let resp = v.process_encrypted_deal(&enc_deal).is_err();
        assert!(resp);
    }

    #[test]
    fn test_vss_verifier_receive_deal_wrong_index() {
        let init_data: InitData = setup(7);
        let (mut dealer, mut verifiers) = gen_all(&init_data);
        let d: &mut Deal = &mut dealer.deals[0];
        let v: &mut Verifier = &mut verifiers[0];

        let correct_index = d.sec_share.i;
        d.sec_share.i = correct_index + 1;
        let enc_deal: EncryptedDeal = dealer.encrypt_deals().unwrap()[0].clone();
        v.process_encrypted_deal(&enc_deal)
            .expect_err("Incorrect share index");
    }

    #[test]
    fn test_vss_verifier_receive_deal_wrong_commitments() {
        let init_data: InitData = setup(7);
        let (mut dealer, mut verifiers) = gen_all(&init_data);
        let unm_dealer = dealer.clone();
        let d: &mut Deal = &mut dealer.deals[0];
        let v: &mut Verifier = &mut verifiers[0];

        let enc_deal: EncryptedDeal = unm_dealer.encrypt_deal(0).unwrap();
        v.process_encrypted_deal(&enc_deal).expect("Must work fine");

        let _ = d.commitments.remove(0 as usize);
        let generator = GE::generator();
        let priv1 = FE::from(7960 as u64);
        let pub_1: GE = generator.scalar_mul(&priv1.get_element());
        d.commitments
            .insert(0 as usize, pub_1.get_element().to_bytes().to_vec());
        let enc_deal: EncryptedDeal = dealer.encrypt_deal(0).unwrap();
        v.process_encrypted_deal(&enc_deal)
            .expect_err("Wrong committment");
    }

    #[test]
    fn test_vss_verifier_receive_deal_already_seen_deal() {
        let init_data: InitData = setup(7);
        let (dealer, mut verifiers) = gen_all(&init_data);
        let v: &mut Verifier = &mut verifiers[0];

        let enc_deal: EncryptedDeal = dealer.encrypt_deal(0).unwrap();

        v.process_encrypted_deal(&enc_deal)
            .expect("First time work fine");
        v.process_encrypted_deal(&enc_deal)
            .expect_err("Already received this deal");
    }

    #[test]
    fn test_vss_verifier_receive_deal_approval_already_exist() {
        let init_data: InitData = setup(7);
        let (dealer, mut verifiers) = gen_all(&init_data);
        let v: &mut Verifier = &mut verifiers[0];

        let enc_deal: EncryptedDeal = dealer.encrypt_deal(0).unwrap();

        v.process_encrypted_deal(&enc_deal)
            .expect("New deal, must work fine");
        v.aggregator.deal.t = 0; // reset aggregator in such way

        v.aggregator.responses.insert(
            v.index,
            Response {
                approved: true,
                ..Default::default()
            },
        );
        v.process_encrypted_deal(&enc_deal)
            .expect_err("Approval already exists");
    }

    #[test]
    fn test_vss_verifier_receive_deal_valid_complaint() {
        let init_data: InitData = setup(7);
        let (mut dealer, mut verifiers) = gen_all(&init_data);
        let unm_dealer = dealer.clone();
        let d: &mut Deal = &mut dealer.deals[0];
        let v: &mut Verifier = &mut verifiers[0];

        let enc_deal: EncryptedDeal = unm_dealer.encrypt_deal(0).unwrap();

        v.process_encrypted_deal(&enc_deal).expect("Must work fine");

        v.aggregator.deal.t = 0; // reset aggregator in such way
        let _ = v.aggregator.responses.remove(&v.index).unwrap();
        d.rnd_share.v = ECScalar::new_random();
        let enc_deal: EncryptedDeal = dealer.encrypt_deal(0).unwrap();
        let resp = v.process_encrypted_deal(&enc_deal).unwrap();
        assert!(!resp.approved);
    }

    #[test]
    fn test_vss_aggregator_verify_justification() {
        let init_data: InitData = setup(7);
        let (mut dealer, mut verifiers) = gen_all(&init_data);
        let d: &mut Deal = &mut dealer.deals[0];
        let v: &mut Verifier = &mut verifiers[0];

        let wrong_v = FE::new_random();
        let good_d: Deal = d.clone();
        d.sec_share.v = wrong_v;
        let enc_deal: EncryptedDeal = dealer.encrypt_deals().unwrap()[0].clone();
        let mut resp = v.process_encrypted_deal(&enc_deal).unwrap();

        assert!(!resp.approved);
        assert_eq!(Some(&resp), v.aggregator.responses.get(&v.index));

        dealer.deals[0] = good_d;

        let mut j: Justification = dealer.process_response(&resp).unwrap().unwrap();

        // invalid deal justified
        let good_v: FE = j.deal.sec_share.v;
        j.deal.sec_share.v = FE::from(168 as u64);
        v.process_justification(&j)
            .expect_err("invalid deal justified");

        assert!(v.aggregator.bad_dealer);

        j.deal.sec_share.v = good_v;
        v.aggregator.bad_dealer = false;

        // valid complaint
        v.process_justification(&j).expect("Valid complaint");

        // invalid complaint
        resp.session_id = [5u8; 32].to_vec();
        dealer
            .process_response(&resp)
            .expect_err("Can't process response with invalid complaint");

        // no complaints for this justification before
        v.aggregator.responses.remove(&v.index);
        v.process_justification(&j)
            .expect_err("no complaints for this justification before");
    }

    #[test]
    fn test_vss_aggregator_verify_response_duplicate() {
        let init_data: InitData = setup(7);
        let (dealer, verifiers) = gen_all(&init_data);

        let mut v0: Verifier = verifiers[0].clone();
        let mut v1: Verifier = verifiers[1].clone();

        let enc_deals: Vec<EncryptedDeal> = dealer.encrypt_deals().unwrap();

        let d0: &EncryptedDeal = &enc_deals[0];
        let d1: &EncryptedDeal = &enc_deals[1];

        let resp0: Response = v0.process_encrypted_deal(&d0).unwrap();

        assert!(resp0.approved);

        let resp1: Response = v1.process_encrypted_deal(&d1).unwrap();

        assert!(resp1.approved);

        v0.process_response(&resp1).expect("Must work fine");

        assert_eq!(v0.aggregator.responses.get(&v1.index).unwrap(), &resp1);

        v0.process_response(&resp1)
            .expect_err("Already processed response");

        v0.aggregator.responses.insert(
            v1.index,
            Response {
                approved: true,
                ..Default::default()
            },
        );
        v0.process_response(&resp1).expect_err("Must fail");
    }

    #[test]
    fn test_vss_aggregator_verify_response() {
        let init_data: InitData = setup(7);
        let (mut dealer, mut verifiers) = gen_all(&init_data);

        let v: &mut Verifier = &mut verifiers[0];

        let (wrong_sec, _) = gen_pair();
        dealer.deals[0].sec_share.v = wrong_sec;

        let enc_deal: EncryptedDeal = dealer.encrypt_deal(0).unwrap();

        // valid complaint
        let mut resp = v.process_encrypted_deal(&enc_deal).unwrap();

        assert!(!resp.approved);
        assert_eq!(resp.session_id, dealer.session_id);

        let r = v.aggregator.responses.get(&v.index).unwrap();

        assert!(!r.approved);

        // wrong index
        resp.index = 45;
        let r_hash = Response::hash(&resp.session_id.to_vec(), resp.index, false as u32).unwrap();
        let sig: Vec<u8> = sign::sign_msg(
            v.longterm.get_element().to_bytes(),
            v.pub_k.get_element().to_bytes(),
            &r_hash,
            &v.index.to_le_bytes(),
        )
        .unwrap();
        resp.signature = sig;
        let r = v.aggregator.verify_response(&resp);

        assert!(r.is_err());

        resp.index = 0;

        // wrong signature
        let good_sig = resp.signature.clone();
        resp.signature = sign::sign_msg(
            v.longterm.get_element().to_bytes(),
            v.pub_k.get_element().to_bytes(),
            &[0u8; 32],
            &v.index.to_le_bytes(),
        )
        .unwrap();
        v.aggregator
            .verify_response(&resp)
            .expect_err("Wrong signature");

        resp.signature = good_sig;

        // wrong ID
        let wrong_id = [0u8; 32].to_vec();
        resp.session_id = wrong_id;
        v.aggregator.verify_response(&resp).expect_err("Wrong ID");
    }

    #[test]
    fn test_vss_aggregator_verify_deal() {
        let init_data: InitData = setup(7);
        let (dealer, verifiers) = gen_all(&init_data);

        let mut deal: Deal = dealer.deals[0].clone();

        deal.verify(&dealer.aggregator.verifiers, &deal.session_id)
            .expect("Must work fine");

        // wrong T
        let correct_t = deal.t;
        deal.t = 1;
        deal.verify(&dealer.aggregator.verifiers, &deal.session_id)
            .expect_err("wrong threshold");

        deal.t = correct_t;

        // wrong SessionID
        let correct_sid = deal.session_id.clone();
        deal.session_id = [0u8; 32].to_vec();
        deal.verify(&dealer.aggregator.verifiers, &correct_sid)
            .expect_err("Wrong SessionId");

        deal.session_id = correct_sid;

        // index different in one share
        let correct_ind = deal.rnd_share.i;
        deal.rnd_share.i = correct_ind + 1;
        deal.verify(&dealer.aggregator.verifiers, &deal.session_id)
            .expect_err("index different in one share");

        deal.rnd_share.i = correct_ind;

        // index not in bounds
        let correct_i = deal.sec_share.i;
        deal.sec_share.i = verifiers.len() as u32;
        deal.verify(&dealer.aggregator.verifiers, &deal.session_id)
            .expect_err("index not in bounds");

        deal.sec_share.i = correct_i;

        // shares invalid in respect to the commitments
        let (wrong_sec, _) = gen_pair();
        deal.sec_share.v = wrong_sec;
        deal.verify(&dealer.aggregator.verifiers, &deal.session_id)
            .expect_err("shares invalid in respect to the commitments");
    }

    #[test]
    fn test_vss_aggregator_add_complaint() {
        let init_data: InitData = setup(7);
        let (mut dealer, _) = gen_all(&init_data);

        let resp: Response = Response {
            approved: false,
            index: 1,
            ..Default::default()
        };
        dealer
            .aggregator
            .add_response(&resp)
            .expect("Must work fine");

        assert_eq!(&resp, dealer.aggregator.responses.get(&1).unwrap());

        // response already there
        dealer
            .aggregator
            .add_response(&resp)
            .expect_err("response already there");
    }

    #[test]
    fn test_vss_aggregator_clean_verifiers() {
        let init_data: InitData = setup(7);
        let (mut dealer, _) = gen_all(&init_data);

        for el in 0..dealer.t {
            dealer.aggregator.responses.insert(
                el,
                Response {
                    approved: true,
                    ..Default::default()
                },
            );
        }

        assert!(dealer.aggregator.enough_approvals());

        assert!(!dealer.aggregator.deal_certified());

        dealer.aggregator.clean_verifiers();

        assert!(dealer.aggregator.deal_certified());
    }

    #[test]
    fn test_vss_dealer_set_timeout() {
        let init_data: InitData = setup(7);
        let (mut dealer, _) = gen_all(&init_data);

        for el in 0..dealer.t {
            dealer.aggregator.responses.insert(
                el,
                Response {
                    approved: true,
                    ..Default::default()
                },
            );
        }

        assert!(dealer.aggregator.enough_approvals());

        assert!(!dealer.aggregator.deal_certified());

        dealer.set_timeout();

        assert!(dealer.aggregator.deal_certified());
    }

    #[test]
    fn test_vss_verifier_set_timeout() {
        let init_data: InitData = setup(7);
        let (dealer, mut verifiers) = gen_all(&init_data);

        let v: &mut Verifier = &mut verifiers[0];

        let enc_deal: EncryptedDeal = dealer.encrypt_deal(0).unwrap();

        v.process_encrypted_deal(&enc_deal).unwrap();

        for el in 0..v.aggregator.threshold {
            v.aggregator.responses.insert(
                el,
                Response {
                    approved: true,
                    ..Default::default()
                },
            );
        }

        assert!(v.aggregator.enough_approvals());

        assert!(!v.aggregator.deal_certified());

        v.set_timeout();

        assert!(v.aggregator.deal_certified());
    }

    #[test]
    fn test_vss_session_id() {
        let init_data: InitData = setup(7);
        let (dealer, _) = gen_all(&init_data);

        let commitments: Vec<Vec<u8>> = dealer.deals[0].commitments.clone();
        let sid0: [u8; 32] = session_id(
            &init_data.dealer_pub,
            &init_data.verifiers_pub,
            &commitments,
            dealer.t,
        );

        let sid1: [u8; 32] = session_id(
            &init_data.dealer_pub,
            &init_data.verifiers_pub,
            &commitments,
            dealer.t,
        );

        assert_eq!(&sid0, &sid1);

        let wrong_point = dealer
            .pub_key
            .add_point(&init_data.dealer_pub.get_element());

        let sid2: [u8; 32] = session_id(
            &wrong_point,
            &init_data.verifiers_pub,
            &commitments,
            dealer.t,
        );

        assert_ne!(&sid1, &sid2);
    }

    #[test]
    fn test_vss_dh_exchange() {
        let generator = GE::generator();
        let priv1 = FE::from(168 as u64);
        let dh = dh_exchange(&priv1, &generator);
        let point = generator.scalar_mul(&priv1.get_element());

        assert_eq!(dh, point);
    }

    #[test]
    fn test_vss_context() {
        let init_data: InitData = setup(7);
        let c = context(&init_data.dealer_pub, &init_data.verifiers_pub);

        assert_eq!(128 as usize, c.len());
    }

    #[test]
    fn test_derive_h() {
        let generator = GE::generator();

        let priv1 = FE::from(168 as u64);
        let priv2 = FE::from(54 as u64);
        let priv3 = FE::from(8902 as u64);
        let priv4 = FE::from(4890 as u64);
        let priv5 = FE::from(5109 as u64);
        let priv6 = FE::from(7960 as u64);

        let pub_1: GE = generator.scalar_mul(&priv1.get_element());
        let pub_2: GE = generator.scalar_mul(&priv2.get_element());
        let pub3: GE = generator.scalar_mul(&priv3.get_element());
        let pub4: GE = generator.scalar_mul(&priv4.get_element());
        let pub5: GE = generator.scalar_mul(&priv5.get_element());
        let pub6: GE = generator.scalar_mul(&priv6.get_element());

        let some_vec: Vec<GE> = vec![pub_1, pub_2, pub3, pub4, pub5, pub6];
        derive_h(&some_vec).unwrap();
    }
}
