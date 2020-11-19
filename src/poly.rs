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

/// recover_secret reconstructs the shared secret p(0) from a list of private
/// shares using Lagrange interpolation.
pub fn recover_secret(shares: &mut [PriShare<FE>], t: u32) -> Result<FE, Box<dyn Error>> {
    let (x, y) = xy_scalar(shares, t);

    if (x.len() as u32) < t {
        bail!("Share: not enough shares to recover secret");
    }

    let mut acc: FE = ECScalar::zero();

    for (i, xi) in x.iter() {
        let yi: &FE = y.get(i).unwrap();
        let mut num: FE = ECScalar::new_random();
        num.set_element(yi.get_element());
        let mut den: FE = ECScalar::from(1 as u64);

        for (j, xj) in x.iter() {
            if i == j {
                continue;
            }
            num = num.mul(&xj.get_element());
            let tmp: FE = xj.sub(&xi.get_element());
            den = den.mul(&tmp.get_element());
        }
        den = den.invert();
        num = num.mul(&den.get_element());
        acc = acc.add(&num.get_element());
    }

    Ok(acc)
}

/// xy_scalar returns the list of (x_i, y_i) pairs indexed. The first map returned
/// is the list of x_i and the second map is the list of y_i, both indexed in
/// their respective map at index i.
pub fn xy_scalar(shares: &mut [PriShare<FE>], t: u32) -> (BTreeMap<u32, FE>, BTreeMap<u32, FE>) {
    // we are sorting first the shares since the shares may be unrelated for
    // some applications. In this case, all participants needs to interpolate on
    // the exact same order shares.
    shares.sort_by(|a, b| a.i.cmp(&b.i));

    let mut x: BTreeMap<u32, FE> = BTreeMap::new();
    let mut y: BTreeMap<u32, FE> = BTreeMap::new();
    for el in shares.iter() {
        let idx: u32 = el.i;
        x.insert(idx.clone(), ECScalar::from(idx.clone() as u64 + 1));
        y.insert(idx, el.v);

        if x.len() as u32 == t {
            break;
        }
    }
    (x, y)
}

#[derive(Debug, Clone)]
pub struct PubShare<T> {
    i: u32,
    pub(crate) v: T,
}

impl<T: ECPoint<PK, SK>> PubShare<T> {
    /// hash returns the hash representation of this share.
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PubPoly {
    b: GE, // base point
    commits: Vec<GE>,
}

impl PubPoly {
    /// new_pub_poly creates a new public commitment polynomial.
    pub fn new_pub_poly(b: GE, commits: Vec<GE>) -> PubPoly {
        PubPoly {
            b: b,
            commits: commits,
        }
    }

    /// info returns the base point and the commitments to the polynomial coefficients.
    pub fn info(&self) -> (GE, Vec<GE>) {
        (self.b, self.commits.clone())
    }

    /// threshold returns the secret sharing threshold.
    pub fn threshold(&self) -> u32 {
        self.commits.len() as u32
    }

    /// commit returns the secret commitment p(0), i.e., the constant term of the polynomial.
    pub fn commit(&self) -> GE {
        self.commits[0]
    }

    /// eval computes the public share v = p(i).
    pub fn eval(&self, i: u32) -> PubShare<GE> {
        let xi: FE = ECScalar::from(i as u64 + 1); // x-coordinate of this share
        let mut v: GE = zero_ge();
        let mut r_commits: Vec<GE> = self.commits.clone();
        r_commits.reverse();
        for el in r_commits.iter() {
            v = v.scalar_mul(&xi.get_element());
            v = v.add_point(&el.get_element());
        }
        PubShare { i: i, v: v }
    }

    /// shares creates a list of n public commitment shares p(1),...,p(n).
    pub fn shares(&self, n: u32) -> Vec<PubShare<GE>> {
        let mut shares: Vec<PubShare<GE>> = Vec::with_capacity(n as usize);
        for el in 0..n {
            shares.push(self.eval(el));
        }
        shares
    }

    /// add computes the component-wise sum of the polynomials "self" and q and returns it
    /// as a new polynomial. NOTE: If the base points "self".b and q.b are different then the
    /// base point of the resulting PubPoly cannot be computed without knowing the
    /// discrete logarithm between "self".b and q.b. In this particular case, we are using
    /// "self".b as a default value which of course does not correspond to the correct
    /// base point and thus should not be used in further computations.
    pub fn add(&self, q: &PubPoly) -> Result<PubPoly, Box<dyn Error>> {
        if self.threshold() != q.threshold() {
            bail!("different number of coefficients");
        }
        let mut commits: Vec<GE> = Vec::with_capacity(self.threshold() as usize);
        for el in 0..self.threshold() {
            commits
                .push(self.commits[el as usize].add_point(&q.commits[el as usize].get_element()));
        }
        Ok(PubPoly {
            b: self.b,
            commits: commits,
        })
    }

    /// equal checks equality of two public commitment polynomials p and q. If p and
    /// q are trivially unequal (e.g., due to mismatching cryptographic groups),
    /// this routine returns in variable time. Otherwise it runs in constant time
    /// regardless of whether it eventually returns true or false.
    pub fn equal(&self, q: PubPoly) -> bool {
        for (ind, el) in self.commits.iter().enumerate() {
            let first_binary_point: [u8; 32] = el.get_element().to_bytes();
            let second_binary_point: [u8; 32] = q.commits[ind].get_element().to_bytes();

            match bitwise_comparison(&first_binary_point.as_ref(), &second_binary_point.as_ref()) {
                false => return false,
                true => continue,
            }
        }
        true
    }

    /// check a private share against a public commitment polynomial.
    pub fn check(&self, s: &PriShare<FE>) -> bool {
        let pv: PubShare<GE> = self.eval(s.i);
        let ps: GE = self.b.scalar_mul(&s.v.get_element());
        bitwise_comparison(
            &pv.v.get_element().to_bytes().as_ref(),
            &ps.get_element().to_bytes().as_ref(),
        )
    }
}

/// xy_commit is the public version of xy_scalar.
pub fn xy_commit(shares: &mut [PubShare<GE>], t: u32) -> (BTreeMap<u32, FE>, BTreeMap<u32, GE>) {
    // we are sorting first the shares since the shares may be unrelated for
    // some applications. In this case, all participants needs to interpolate on
    // the exact same order shares.
    shares.sort_by(|a, b| a.i.cmp(&b.i));

    let mut x: BTreeMap<u32, FE> = BTreeMap::new();
    let mut y: BTreeMap<u32, GE> = BTreeMap::new();

    for el in shares.iter() {
        let idx: u32 = el.i;
        x.insert(idx.clone(), ECScalar::from(idx.clone() as u64 + 1));
        y.insert(idx, el.v);

        if x.len() as u32 == t {
            break;
        }
    }
    (x, y)
}

/// recover_commit reconstructs the secret commitment p(0) from a list of public
/// shares using Lagrange interpolation.
pub fn recover_commit(shares: &mut [PubShare<GE>], t: u32) -> Result<GE, Box<dyn Error>> {
    let (x, y) = xy_commit(shares, t);

    if (x.len() as u32) < t {
        bail!("Share: not enough good public shares to reconstruct secret commitment");
    }

    let mut acc: GE = zero_ge();

    for (i, xi) in x.iter() {
        let mut num: FE = ECScalar::from(1 as u64);
        let mut den: FE = ECScalar::from(1 as u64);

        for (j, xj) in x.iter() {
            if i == j {
                continue;
            }
            num = num.mul(&xj.get_element());
            let tmp: FE = xj.sub(&xi.get_element());
            den = den.mul(&tmp.get_element());
        }
        den = den.invert();
        num = num.mul(&den.get_element());
        let tmp_point: GE = y.get(i).unwrap().scalar_mul(&num.get_element());
        acc = acc.add_point(&tmp_point.get_element());
    }

    Ok(acc)
}

/// recover_pub_poly reconstructs the full public polynomial from a set of public
/// shares using Lagrange interpolation.
pub fn recover_pub_poly(shares: &mut [PubShare<GE>], t: u32) -> Result<PubPoly, Box<dyn Error>> {
    let (x, y) = xy_commit(shares, t);
    if (x.len() as u32) < t {
        bail!("Share: not enough good public shares to reconstruct secret commitment")
    }

    let mut acc_poly: Option<PubPoly> = None;

    for (j, _) in x.iter() {
        let basis: PriPoly = lagrange_basis(&j, &x);

        let tmp = basis.commit(Some(*y.get(j).unwrap()));

        match acc_poly {
            Some(el) => acc_poly = Some(el.add(&tmp).unwrap()),
            None => acc_poly = Some(tmp),
        }
    }

    Ok(acc_poly.unwrap())
}

/// recover_pri_poly takes a list of shares and the parameters t and n to
/// reconstruct the secret polynomial completely, i.e., all private
/// coefficients.  It is up to the caller to make sure that there are enough
/// shares to correctly re-construct the polynomial. There must be at least t
/// shares.
pub fn recover_pri_poly(shares: &mut [PriShare<FE>], t: u32) -> Result<PriPoly, Box<dyn Error>> {
    let (x, y) = xy_scalar(shares, t);

    if (x.len() as u32) != t {
        bail!("Share: not enogh shares to recover private polynomial")
    }

    let mut acc_poly: Option<PriPoly> = None;

    for (j, _) in x.iter() {
        let mut basis: PriPoly = lagrange_basis(j, &x);
        for i in basis.coeffs.iter_mut() {
            *i = i.mul(&y.get(j).unwrap().get_element());
        }

        match acc_poly {
            Some(el) => acc_poly = Some(el.add(&basis).unwrap()),
            None => acc_poly = Some(basis),
        };
    }

    Ok(acc_poly.unwrap())
}

/// lagrange_basis returns a PriPoly containing the Lagrange coefficients for the
/// i-th position. xs is a mapping between the indices and the values that the
/// interpolation is using, computed with xyScalar().
pub fn lagrange_basis(i: &u32, xs: &BTreeMap<u32, FE>) -> PriPoly {
    let mut basis: PriPoly = PriPoly {
        coeffs: vec![ECScalar::from(1 as u64)],
    };

    let mut den: FE;
    let mut acc: FE = ECScalar::from(1 as u64);
    for (m, xm) in xs.iter() {
        if i == m {
            continue;
        }
        basis = basis.mul(minus_const(xm));
        den = xs.get(&i).unwrap().sub(&xm.get_element());
        den = den.invert();
        acc = acc.mul(&den.get_element());
    }

    for el in basis.coeffs.iter_mut() {
        *el = el.mul(&acc.get_element());
    }

    basis
}

pub fn minus_const(c: &FE) -> PriPoly {
    let z_scalar: FE = ECScalar::zero();
    let neg: FE = z_scalar.sub(&c.get_element());
    let one: FE = ECScalar::from(1 as u64);
    PriPoly {
        coeffs: vec![neg, one],
    }
}

/// write this custom function because point in cryptoxide doesn't have public zero() function
pub fn zero_ge() -> GE {
    let zero_bytes = [0u8; 32];
    ECPoint::from_bytes(&zero_bytes).unwrap()
}
