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

#[cfg(test)]
mod tests {
    use super::{PriPoly, PriShare, PubPoly, PubShare};
    use std::collections::BTreeMap;
    use crate::curve_traits;
    use crate::ristretto_curve;

    use curve_traits::{ECPoint, ECScalar};
    use ristretto_curve::{FE, GE};

    #[test]
    fn test_recover_secret() {
        let n: u32 = 10;
        let t: u32 = 6;
        let poly = PriPoly::new_pri_poly(t, None);
        let mut shares = poly.shares(n);
        let recovered = super::recover_secret(shares.as_mut_slice(), t).unwrap();
        assert_eq!(recovered, *poly.secret());
    }

    #[test]
    fn test_recover_commit() {
        let n: u32 = 10;
        let t: u32 = 6;
        let poly = PriPoly::new_pri_poly(t.clone(), None);
        let pub_poly = poly.commit(None);
        let mut pub_shares = pub_poly.shares(n.clone());
        let recovered = super::recover_commit(pub_shares.as_mut_slice(), t).unwrap();

        assert_eq!(recovered, pub_poly.commit());
    }

    #[test]
    fn test_secret_recovery() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;
        let poly: PriPoly = PriPoly::new_pri_poly(t, None);
        let mut shares = poly.shares(n); // all priv keys of pri poly
        let recovered = super::recover_secret(shares.as_mut_slice(), t).unwrap();

        assert_eq!(recovered, *poly.secret());
    }

    #[test]
    fn test_secret_recovery_out_index() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;
        let poly: PriPoly = PriPoly::new_pri_poly(t, None);
        let mut shares = poly.shares(n); // all priv keys of pri poly

        let selected = &mut shares[(n - t) as usize..];

        assert_eq!(selected.len() as u32, t);

        let recovered = super::recover_secret(selected, t).unwrap();

        assert_eq!(recovered, *poly.secret());
    }

    #[test]
    fn test_secret_revocery_delete() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;
        let poly: PriPoly = PriPoly::new_pri_poly(t, None);
        let mut shares = poly.shares(n); // all priv keys of pri poly

        shares.remove(5);
        shares.remove(3);
        shares.remove(7);
        shares.remove(1);

        let recovered = super::recover_secret(shares.as_mut_slice(), t).unwrap();

        assert_eq!(recovered, *poly.secret());
    }

    #[test]
    #[should_panic(expected = "Share: not enough shares to recover secret")]
    fn test_secret_recovery_delere_fail() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;
        let poly: PriPoly = PriPoly::new_pri_poly(t, None);
        let mut shares = poly.shares(n); // all priv keys of pri poly

        shares.remove(5);
        shares.remove(3);
        shares.remove(7);
        shares.remove(1);
        shares.remove(4);

        let _ = super::recover_secret(shares.as_mut_slice(), t).unwrap();
    }

    #[test]
    fn test_secret_poly_equal() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;

        let poly1: PriPoly = PriPoly::new_pri_poly(t, None);
        let poly2: PriPoly = PriPoly::new_pri_poly(t, None);
        let poly3: PriPoly = PriPoly::new_pri_poly(t, None);

        let poly12 = poly1.add(&poly2).unwrap();
        let poly13 = poly1.add(&poly3).unwrap();

        let poly123 = poly12.add(&poly3).unwrap();
        let poly132 = poly13.add(&poly2).unwrap();

        assert_eq!(poly123.equal(&poly132), true);
    }

    #[test]
    fn test_public_check() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;

        let poly: PriPoly = PriPoly::new_pri_poly(t, None);
        let shares = poly.shares(n); // all priv keys of pri poly
        let pub_poly = poly.commit(None);

        for p in shares.iter() {
            assert_eq!(pub_poly.check(p), true);
        }
    }

    #[test]
    fn test_public_recovery() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;

        let pri_poly: PriPoly = PriPoly::new_pri_poly(t, None);
        let pub_poly: PubPoly = pri_poly.commit(None);
        let mut pub_shares: Vec<PubShare<GE>> = pub_poly.shares(n);
        let mut pub_shares2: Vec<PubShare<GE>> = pub_poly.shares(n);

        let recovered = super::recover_commit(pub_shares.as_mut_slice(), t).unwrap();

        assert_eq!(recovered, pub_poly.commit());

        let poly_recovered = super::recover_pub_poly(pub_shares2.as_mut_slice(), t).unwrap();

        assert_eq!(pub_poly.equal(poly_recovered), true);
    }

    #[test]
    fn test_public_recovery_out_index() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;

        let pri_poly: PriPoly = PriPoly::new_pri_poly(t, None);
        let pub_poly: PubPoly = pri_poly.commit(None);
        let mut pub_shares: Vec<PubShare<GE>> = pub_poly.shares(n);

        let selected = &mut pub_shares[(n - t) as usize..];
        assert_eq!(selected.len() as u32, t);

        let recovered = super::recover_commit(selected, t).unwrap();

        assert_eq!(recovered, pub_poly.commit());

        let poly_recovered = super::recover_pub_poly(&mut pub_shares.as_mut_slice(), t).unwrap();
        assert_eq!(pub_poly.equal(poly_recovered), true);
    }

    #[test]
    fn test_public_recovery_delete() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;
        let poly: PriPoly = PriPoly::new_pri_poly(t, None);
        let pub_poly: PubPoly = poly.commit(None);
        let mut shares = pub_poly.shares(n); // all priv keys of pri poly

        shares.remove(5);
        shares.remove(3);
        shares.remove(7);
        shares.remove(1);

        let recovered = super::recover_commit(shares.as_mut_slice(), t).unwrap();

        assert_eq!(recovered, pub_poly.commit());
    }

    #[test]
    #[should_panic(
        expected = "Share: not enough good public shares to reconstruct secret commitment"
    )]
    fn test_public_recovery_delete_fail() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;
        let poly: PriPoly = PriPoly::new_pri_poly(t, None);
        let pub_poly: PubPoly = poly.commit(None);
        let mut shares = pub_poly.shares(n); // all priv keys of pri poly

        shares.remove(5);
        shares.remove(3);
        shares.remove(7);
        shares.remove(1);
        shares.remove(4);

        let _ = super::recover_commit(shares.as_mut_slice(), t).unwrap();
    }

    #[test]
    fn test_private_add() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;
        let poly1: PriPoly = PriPoly::new_pri_poly(t, None);
        let poly2: PriPoly = PriPoly::new_pri_poly(t, None);

        let poly12 = poly1.add(&poly2).unwrap();

        let poly1_s = poly1.secret();
        let poly2_s = poly2.secret();
        let poly12_s = poly1_s.add(&poly2_s.get_element());

        assert_eq!(poly12_s, *poly12.secret());
    }

    #[test]
    fn test_public_add() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;
        let generator: GE = ECPoint::generator();

        let g_scalar: FE = ECScalar::new_random();
        let g: GE = generator.scalar_mul(&g_scalar.get_element());
        let h_scalar: FE = ECScalar::new_random();
        let h: GE = generator.scalar_mul(&h_scalar.get_element());

        let p: PriPoly = PriPoly::new_pri_poly(t, None);
        let q: PriPoly = PriPoly::new_pri_poly(t, None);

        let p_commit = p.commit(Some(g));
        let q_commit = q.commit(Some(h));
        let y = q_commit.commit();

        let r = p_commit.add(&q_commit).unwrap();

        let mut shares = r.shares(n);
        let recovered = super::recover_commit(shares.as_mut_slice(), t).unwrap();

        let x = p_commit.commit();
        let z = x.add_point(&y.get_element());

        assert_eq!(recovered, z);
    }

    #[test]
    fn test_public_poly_equal() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;
        let generator: GE = ECPoint::generator();

        let g_scalar: FE = ECScalar::new_random();
        let g: GE = generator.scalar_mul(&g_scalar.get_element());

        let poly1: PriPoly = PriPoly::new_pri_poly(t, None);
        let poly2: PriPoly = PriPoly::new_pri_poly(t, None);
        let poly3: PriPoly = PriPoly::new_pri_poly(t, None);

        let commit1: PubPoly = poly1.commit(Some(g.clone()));
        let commit2: PubPoly = poly2.commit(Some(g.clone()));
        let commit3: PubPoly = poly3.commit(Some(g.clone()));

        let poly12: PubPoly = commit1.add(&commit2).unwrap();
        let poly13: PubPoly = commit1.add(&commit3).unwrap();

        let poly123: PubPoly = poly12.add(&commit3).unwrap();
        let poly132: PubPoly = poly13.add(&commit2).unwrap();

        assert_eq!(poly123.equal(poly132), true);
    }

    #[test]
    fn test_pri_poly_mul() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;

        let a: PriPoly = PriPoly::new_pri_poly(t, None);
        let b: PriPoly = PriPoly::new_pri_poly(t, None);

        let c = a.mul(b.clone());
        assert_eq!(
            (a.coeffs.len() + b.coeffs.len()) as u32 - 1,
            c.coeffs.len() as u32
        );
        let nul: FE = ECScalar::zero();
        for el in c.coeffs.iter() {
            assert_ne!(nul, *el);
        }

        let a0 = a.coeffs.get(0).unwrap();
        let b0 = b.coeffs.get(0).unwrap();
        let mul = b0.mul(&a0.get_element());
        let c0 = c.coeffs.get(0).unwrap();
        assert_eq!(*c0, mul);

        let at = a.coeffs.last().unwrap();
        let bt = b.coeffs.last().unwrap();
        let mul = at.mul(&bt.get_element());
        let ct = c.coeffs.last().unwrap();
        assert_eq!(*ct, mul);
    }

    #[test]
    fn test_recover_pri_poly() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;

        let pri_poly: PriPoly = PriPoly::new_pri_poly(t, None);
        let mut shares = pri_poly.shares(n);
        let mut shares2 = shares.clone();
        shares2.reverse();

        let recovered = super::recover_pri_poly(shares.as_mut_slice(), t).unwrap();
        let reverce_recovered = super::recover_pri_poly(shares2.as_mut_slice(), t).unwrap();

        for ind in 0..t {
            assert_eq!(recovered.eval(ind).v, pri_poly.eval(ind).v);
            assert_eq!(reverce_recovered.eval(ind).v, pri_poly.eval(ind).v);
        }
    }

    #[test]
    fn test_pri_poly_coefficients() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;

        let pri_poly: PriPoly = PriPoly::new_pri_poly(t, None);

        let coeffs = pri_poly.coefficients();
        assert_eq!(coeffs.len() as u32, t);

        let b = PriPoly::coefficients_to_pri_poly(coeffs);
        assert_eq!(pri_poly.coefficients(), b.coefficients());
    }

    #[test]
    fn test_refresh_dkg() {
        let n: u32 = 10;
        let t: u32 = n / 2 + 1;

        // Run an n-fold Pedersen VSS (= DKG)
        let mut pri_polys: Vec<PriPoly> = Vec::new();
        let mut pri_shares: BTreeMap<u32, Vec<PriShare<FE>>> = BTreeMap::new();
        let mut pub_polys: Vec<PubPoly> = Vec::new();
        let mut pub_shares: BTreeMap<u32, Vec<PubShare<GE>>> = BTreeMap::new();
        for el in 0..n {
            let p_poly: PriPoly = PriPoly::new_pri_poly(t, None);
            pri_polys.push(p_poly.clone());
            let p_share: Vec<PriShare<FE>> = p_poly.shares(n);
            pri_shares.insert(el.clone(), p_share);
            let pub_poly: PubPoly = p_poly.commit(None);
            pub_polys.push(pub_poly.clone());
            let pub_share: Vec<PubShare<GE>> = pub_poly.shares(n);
            pub_shares.insert(el, pub_share);
        }

        // Verify VSS shares
        for (map_key, map_value) in pri_shares.iter() {
            for (v_key, v_value) in map_value.iter().enumerate() {
                let generator: GE = ECPoint::generator();
                let sg = generator.scalar_mul(&v_value.v.get_element());
                assert_eq!(sg, pub_shares.get(map_key).unwrap().get(v_key).unwrap().v);
            }
        }

        // Create private DKG shares
        let mut dkg_shares: Vec<PriShare<FE>> = Vec::new();
        for i in 0..n {
            let mut acc: FE = ECScalar::zero();
            for j in 0..n {
                acc = acc.add(
                    &pri_shares
                        .get(&j)
                        .unwrap()
                        .get(i as usize)
                        .unwrap()
                        .v
                        .get_element(),
                );
            }
            dkg_shares.push(PriShare { i, v: acc });
        }

        // Create public DKG commitments (= verification vector)
        let mut dkg_commits: Vec<GE> = Vec::new();
        for i in 0..t {
            let mut acc: GE = super::zero_ge();

            for value in pub_polys.iter() {
                let (_, coeff) = value.info();
                acc = acc.add_point(&coeff.get(i as usize).unwrap().get_element());
            }
            dkg_commits.push(acc);
        }

        // Check that the private DKG shares verify against the public DKG commits
        let generator: GE = ECPoint::generator();
        let dkg_pub_poly: PubPoly = PubPoly::new_pub_poly(generator, dkg_commits.clone());
        for value in dkg_shares.iter() {
            assert_eq!(dkg_pub_poly.check(value), true);
        }

        // Start verifiable resharing process
        let mut sub_pri_polys: Vec<PriPoly> = Vec::new();
        let mut sub_pri_shares: BTreeMap<u32, Vec<PriShare<FE>>> = BTreeMap::new();
        let mut sub_pub_polys: Vec<PubPoly> = Vec::new();
        let mut sub_pub_shares: BTreeMap<u32, Vec<PubShare<GE>>> = BTreeMap::new();

        // Create subshares and subpolys
        for el in 0..n {
            let p_poly: PriPoly =
                PriPoly::new_pri_poly(t.clone(), Some(dkg_shares.get(el as usize).unwrap().v));
            sub_pri_polys.push(p_poly.clone());
            let p_share: Vec<PriShare<FE>> = p_poly.shares(n);
            sub_pri_shares.insert(el, p_share);
            let pub_poly: PubPoly = p_poly.commit(None);
            sub_pub_polys.push(pub_poly.clone());
            let pub_share: Vec<PubShare<GE>> = pub_poly.shares(n);
            sub_pub_shares.insert(el, pub_share);
            let test_scalar: FE = sub_pri_shares.get(&el).unwrap().get(0 as usize).unwrap().v;
            let generator: GE = ECPoint::generator();
            assert_eq!(
                generator.scalar_mul(&test_scalar.get_element()),
                sub_pub_shares.get(&el).unwrap().get(0 as usize).unwrap().v
            );
        }

        // Handout shares to new nodes column-wise and verify them
        let mut new_dkg_shares: Vec<PriShare<FE>> = Vec::new();
        for i in 0..n {
            let mut tmp_pri_shares: Vec<PriShare<FE>> = Vec::new(); // column-wise reshuffled sub-shares
            let mut tmp_pub_shares: Vec<PubShare<GE>> = Vec::new(); // public commitments to old DKG private shares
            for j in 0..n {
                // Check 1: Verify that the received individual private subshares s_ji
                // is correct by evaluating the public commitment vector
                tmp_pri_shares.push(PriShare {
                    i: j,
                    v: sub_pri_shares.get(&j).unwrap().get(i as usize).unwrap().v,
                }); // Shares that participant i gets from j
                let test_scalar: FE = tmp_pri_shares.get(j as usize).unwrap().v;
                let generator: GE = ECPoint::generator();
                assert_eq!(
                    generator.scalar_mul(&test_scalar.get_element()),
                    sub_pub_polys.get(j as usize).unwrap().eval(i).v
                );

                // Check 2: Verify that the received sub public shares are
                // commitments to the original secret
                tmp_pub_shares.push(dkg_pub_poly.eval(j));
                assert_eq!(
                    tmp_pub_shares.get(j as usize).unwrap().v,
                    sub_pub_polys.get(j as usize).unwrap().commit()
                );
            }
            // Check 3: Verify that the received public shares interpolate to the
            // original DKG public key
            let com = super::recover_commit(tmp_pub_shares.as_mut_slice(), t).unwrap();
            assert_eq!(*dkg_commits.get(0 as usize).unwrap(), com);

            // Compute the refreshed private DKG share of node i
            let s = super::recover_secret(tmp_pri_shares.as_mut_slice(), t).unwrap();
            new_dkg_shares.push(PriShare { i, v: s });
        }

        // Refresh the DKG commitments (= verification vector)
        let mut new_dkg_commits: Vec<GE> = Vec::new();
        for i in 0..t {
            let mut pub_shares: Vec<PubShare<GE>> = Vec::new();
            for j in 0..n {
                let (_, c) = sub_pub_polys.get(j as usize).unwrap().info();
                pub_shares.push(PubShare {
                    i: j,
                    v: *c.get(i as usize).unwrap(),
                });
            }
            let com = super::recover_commit(pub_shares.as_mut_slice(), t).unwrap();
            new_dkg_commits.push(com);
        }

        // Check that the old and new DKG public keys are the same
        assert_eq!(
            dkg_commits.get(0 as usize).unwrap(),
            new_dkg_commits.get(0 as usize).unwrap()
        );

        // Check that the old and new DKG private shares are different
        for (i, el) in dkg_shares.iter().enumerate() {
            assert_ne!(el.v, new_dkg_shares.get(i as usize).unwrap().v);
        }

        // Check that the refreshed private DKG shares verify against the refreshed public DKG commits
        let b: GE = ECPoint::generator();
        let q = PubPoly::new_pub_poly(b, new_dkg_commits);
        for el in new_dkg_shares.iter() {
            assert_eq!(q.check(el), true);
        }

        // Recover the private polynomial
        let refreshed_pri_poly = super::recover_pri_poly(new_dkg_shares.as_mut_slice(), t).unwrap();

        // Check that the secret and the corresponding (old) public commit match
        let generator: GE = ECPoint::generator();
        let p: GE = generator.scalar_mul(&refreshed_pri_poly.secret().get_element());
        assert_eq!(p, *dkg_commits.get(0 as usize).unwrap());
    }
}
