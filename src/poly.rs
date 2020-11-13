use std::collections::BTreeMap;
use std::convert::TryInto;
use std::error::Error;
use std::io::Write;

use crate::curve_traits;
use crate::ristretto_curve;
use crate::utils;

use curve_traits::{ECPoint, ECScalar};
use ristretto_curve::{FE, GE, PK, SK};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utils::bitwise_comparison;

/// PriShare represents a private share.
#[derive(Debug, Eq, Ord, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub struct PriShare<T> {
    pub i: u32, // index of private share
    pub v: T,   // value of share
}

impl<T: ECScalar<SK>> PriShare<T> {
    /// hash returns the hash representation of this share
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.input(self.v.get_element().to_bytes());
        hasher.write(&self.i.to_le_bytes()).unwrap();

        let result = hasher.result();
        result
            .as_slice()
            .try_into()
            .expect("Slice with incorrect length")
    }
}

/// PriPoly represents a secret sharing polynomial.
#[derive(Debug, Clone)]
pub struct PriPoly {
    pub coeffs: Vec<FE>, // Coefficients of the polynomial
}

impl PriPoly {
    pub fn new_pri_poly(t: u32, s: Option<FE>) -> PriPoly {
        let mut coeffs: Vec<FE> = Vec::new();
        if let Some(secret) = s {
            coeffs.push(secret);
        } else {
            coeffs.push(ECScalar::new_random());
        }
        for _ in 1..t {
            coeffs.push(ECScalar::new_random());
        }
        PriPoly { coeffs: coeffs }
    }

    /// coefficients_to_pri_poly returns a PriPoly based on the given coefficients
    pub fn coefficients_to_pri_poly(coeffs: Vec<FE>) -> PriPoly {
        PriPoly { coeffs: coeffs }
    }

    /// threshold returns the secret sharing threshold.
    pub fn threshold(&self) -> u32 {
        self.coeffs.len() as u32
    }

    /// secret returns the shared secret p(0), i.e., the constant term of the polynomial.
    pub fn secret(&self) -> &FE {
        &self.coeffs[0]
    }

    /// eval computes the private share v = p(i).
    pub fn eval(&self, i: u32) -> PriShare<FE> {
        let xi: FE = ECScalar::from(i as u64 + 1);
        let mut v: FE = ECScalar::zero();
        for el in self.coeffs.iter().rev() {
            v = v.mul(&xi.get_element());
            v = v.add(&el.get_element());
        }
        PriShare { i: i, v: v }
    }

    /// shares creates a list of n private shares p(1),...,p(n).
    pub fn shares(&self, n: u32) -> Vec<PriShare<FE>> {
        let mut shares: Vec<PriShare<FE>> = Vec::with_capacity(n as usize);
        for el in 0..n {
            shares.push(self.eval(el));
        }
        shares
    }

    /// add computes the component-wise sum of the polynomials p and q and returns it
    /// as a new polynomial.
    pub fn add(&self, q: &PriPoly) -> Result<PriPoly, Box<dyn Error>> {
        if self.threshold() != q.threshold() {
            bail!("different number of coefficients");
        }
        let mut coeffs: Vec<FE> = Vec::with_capacity(self.threshold() as usize);
        for el in 0..self.threshold() {
            coeffs.push(self.coeffs[el as usize].add(&q.coeffs[el as usize].get_element()));
        }
        Ok(PriPoly { coeffs: coeffs })
    }

    /// equal checks equality of two secret sharing polynomials "self" and q. If "self" and q are trivially
    /// unequal (e.g., due to mismatching cryptographic groups or polynomial size), this routine
    /// returns in variable time. Otherwise it runs in constant time regardless of whether it
    /// eventually returns true or false.
    pub fn equal(&self, q: &PriPoly) -> bool {
        if self.coeffs.len() != q.coeffs.len() {
            return false;
        }
        for (ind, el) in self.coeffs.iter().enumerate() {
            let first_binary_scalar: [u8; 32] = el.get_element().to_bytes();
            let second_binary_scalar: [u8; 32] = q.coeffs[ind].get_element().to_bytes();

            match bitwise_comparison(
                &first_binary_scalar.as_ref(),
                &second_binary_scalar.as_ref(),
            ) {
                false => return false,
                true => continue,
            };
        }
        true
    }

    /// commit creates a public commitment polynomial for the given base point b or
    /// the standard base if b == nil.
    pub fn commit(&self, b: Option<GE>) -> PubPoly {
        let mut commits: Vec<GE> = Vec::with_capacity(self.threshold() as usize);
        let mut poly_base: GE = ECPoint::generator(); // Default value
        for el in 0..self.threshold() {
            if let Some(point) = b {
                commits.push(point.scalar_mul(&self.coeffs[el as usize].get_element()));
                poly_base = point;
            } else {
                let base_point: GE = ECPoint::generator();
                commits.push(base_point.scalar_mul(&self.coeffs[el as usize].get_element()));
                poly_base = base_point;
            }
        }
        PubPoly {
            b: poly_base,
            commits: commits,
        }
    }

    /// mul multiples p and q together. The result is a polynomial of the sum of
    /// the two degrees of p and q. NOTE: it does not check for null coefficients
    /// after the multiplication, so the degree of the polynomial is "always" as
    /// described above. This is only for use in secret sharing schemes. It is not
    /// a general polynomial multiplication routine.
    pub fn mul(&self, q: PriPoly) -> PriPoly {
        let d1 = (self.coeffs.len() as u32) - 1;
        let d2 = (q.coeffs.len() as u32) - 1;
        let new_degree = d1 + d2;
        let mut coeffs: Vec<FE> = Vec::with_capacity((new_degree + 1).try_into().unwrap());

        for _ in 0..new_degree + 1 {
            coeffs.push(ECScalar::zero());
        }

        for (i, _) in self.coeffs.iter().enumerate() {
            for (j, _) in q.coeffs.iter().enumerate() {
                let tmp = self.coeffs[i as usize].mul(&q.coeffs[j as usize].get_element());
                coeffs[i + j as usize] = tmp.add(&coeffs[i + j as usize].get_element());
            }
        }
        PriPoly { coeffs }
    }

    /// coefficients return the list of coefficients representing p. This
    /// information is generally PRIVATE and should not be revealed to a third party
    /// lightly.
    pub fn coefficients(&self) -> Vec<FE> {
        self.coeffs.clone()
    }
}
