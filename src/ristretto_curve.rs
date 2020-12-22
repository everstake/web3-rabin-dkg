//! Ristretto curve - the cryptographic backend of the library

use crate::curve_traits::{ECPoint, ECScalar};
use crate::utils;
use std::convert::From;
use std::error::Error;
use std::fmt;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use hex::{decode, encode};
use serde::de;
use serde::de::Visitor;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};

pub const SECRET_KEY_SIZE: usize = 32;

pub type SK = Scalar;
pub type PK = CompressedRistretto;

#[derive(Clone, Debug, Copy)]
pub struct RistrettoScalar {
    purpose: &'static str,
    fe: SK,
}
#[derive(Clone, Debug, Copy)]
pub struct RistrettoCurvPoint {
    purpose: &'static str,
    ge: PK,
}
pub type GE = RistrettoCurvPoint;
pub type FE = RistrettoScalar;

impl From<u64> for RistrettoScalar {
    fn from(n: u64) -> Self {
        let mut v = n.to_le_bytes().to_vec();
        v.resize(SECRET_KEY_SIZE, 0);
        let bytes_array_32 = utils::arr32_from_slice(&v).expect("Wrong byte vec size");
        Self {
            purpose: "from_big_int",
            fe: SK::from_bytes_mod_order(bytes_array_32),
        }
    }
}

impl From<SK> for RistrettoScalar {
    fn from(scalar: SK) -> Self {
        Self {
            purpose: "from_scalar",
            fe: scalar,
        }
    }
}

impl ECScalar<SK> for RistrettoScalar {
    fn new_random() -> Self {
        Self {
            purpose: "random",
            fe: SK::random(&mut utils::rand_hack()),
        }
    }

    fn zero() -> Self {
        let q_fe: Scalar = Scalar::from_bytes_mod_order([0; SECRET_KEY_SIZE]);
        Self {
            purpose: "zero",
            fe: q_fe,
        }
    }

    fn get_element(&self) -> SK {
        self.fe
    }
    fn set_element(&mut self, element: SK) {
        self.fe = element
    }

    fn to_hex(&self) -> String {
        encode(self.get_element().to_bytes())
    }

    fn add(&self, other: &SK) -> Self {
        Self {
            purpose: "add",
            fe: self.get_element() + other,
        }
    }

    fn mul(&self, other: &SK) -> Self {
        Self {
            purpose: "mul",
            fe: self.get_element() * other,
        }
    }

    fn sub(&self, other: &SK) -> Self {
        Self {
            purpose: "sub",
            fe: self.get_element() - other,
        }
    }

    fn invert(&self) -> Self {
        let inv: SK = self.get_element().invert();
        Self {
            purpose: "invert",
            fe: inv,
        }
    }
}

impl Default for RistrettoScalar {
    fn default() -> Self {
        Self::zero()
    }
}

impl Serialize for RistrettoScalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for RistrettoScalar {
    fn deserialize<D>(deserializer: D) -> Result<RistrettoScalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(RistrettoScalarVisitor)
    }
}

struct RistrettoScalarVisitor;

impl<'de> Visitor<'de> for RistrettoScalarVisitor {
    type Value = RistrettoScalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("ristretto")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<RistrettoScalar, E> {
        let s_bytes: Vec<u8> = decode(s).expect("Failed in decoding");
        let b: [u8; 32] = utils::arr32_from_slice(&s_bytes).expect("Failed in array creation");
        let s: Scalar = Scalar::from_bytes_mod_order(b);
        Ok(RistrettoScalar {
            purpose: "from_bytes",
            fe: s,
        })
    }
}

impl PartialEq for RistrettoScalar {
    fn eq(&self, other: &RistrettoScalar) -> bool {
        self.get_element() == other.get_element()
    }
}

impl ECPoint<PK, SK> for RistrettoCurvPoint {
    fn generator() -> RistrettoCurvPoint {
        RistrettoCurvPoint {
            purpose: "base_fe",
            ge: RISTRETTO_BASEPOINT_COMPRESSED,
        }
    }

    fn pk_to_key_slice(&self) -> Vec<u8> {
        self.ge.to_bytes().to_vec()
    }

    fn get_element(&self) -> PK {
        self.ge
    }

    fn to_hex(&self) -> String {
        encode(self.pk_to_key_slice())
    }

    fn from_bytes(bytes: &[u8]) -> Result<RistrettoCurvPoint, Box<dyn Error>> {
        let mut bytes_vec = bytes.to_vec();
        if bytes_vec.len() < 32 {
            bytes_vec.resize(32, 0);
        }
        let r_point: PK = CompressedRistretto::from_slice(&bytes_vec[0..32]);
        let r_point_compress = r_point.decompress();
        let new_point = r_point_compress
            .map(|x| RistrettoCurvPoint {
                purpose: "random",
                ge: x.compress(),
            })
            .ok_or_else(|| simple_error!("Invalid Public Key"))?;
        Ok(new_point)
    }

    fn scalar_mul(&self, fe: &SK) -> RistrettoCurvPoint {
        let skpk = fe * (self.ge.decompress().unwrap());
        RistrettoCurvPoint {
            purpose: "scalar_point_mul",
            ge: skpk.compress(),
        }
    }

    fn add_point(&self, other: &PK) -> RistrettoCurvPoint {
        let pkpk = self.ge.decompress().unwrap() + other.decompress().unwrap();
        RistrettoCurvPoint {
            purpose: "combine",
            ge: pkpk.compress(),
        }
    }

    fn sub_point(&self, other: &PK) -> RistrettoCurvPoint {
        let pkpk = self.ge.decompress().unwrap() - other.decompress().unwrap();
        RistrettoCurvPoint {
            purpose: "sub",
            ge: pkpk.compress(),
        }
    }
}

impl Serialize for RistrettoCurvPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for RistrettoCurvPoint {
    fn deserialize<D>(deserializer: D) -> Result<RistrettoCurvPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(RistrettoCurvPointVisitor)
    }
}

struct RistrettoCurvPointVisitor;

impl<'de> Visitor<'de> for RistrettoCurvPointVisitor {
    type Value = RistrettoCurvPoint;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("RistrettoCurvPoint")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<RistrettoCurvPoint, E> {
        let s_bytes: Vec<u8> = decode(s).expect("Failed in decoding");
        let ge: CompressedRistretto = CompressedRistretto::from_slice(&s_bytes);
        Ok(RistrettoCurvPoint {
            purpose: "from_bytes",
            ge,
        })
    }
}

impl PartialEq for RistrettoCurvPoint {
    fn eq(&self, other: &RistrettoCurvPoint) -> bool {
        self.get_element() == other.get_element()
    }
}
