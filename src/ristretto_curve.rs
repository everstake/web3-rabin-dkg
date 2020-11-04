use std::error::Error;
use std::fmt;

use crate::curve_traits::{ECPoint, ECScalar};
use crate::utils;

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

impl ECScalar<SK> for RistrettoScalar {
    fn new_random() -> RistrettoScalar {
        RistrettoScalar {
            purpose: "random",
            fe: SK::random(&mut utils::rand_hack()),
        }
    }

    fn zero() -> RistrettoScalar {
        let q_fe: Scalar = Scalar::from_bytes_mod_order([0; SECRET_KEY_SIZE]);
        RistrettoScalar {
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

    fn from(n: u64) -> RistrettoScalar {
        let mut v: Vec<u8> = utils::to_32_vector(n as f64);
        let mut bytes_array_32: [u8; 32];
        let mut bytes_array_64: [u8; 64];
        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        if v.len() > SECRET_KEY_SIZE && v.len() < 2 * SECRET_KEY_SIZE {
            let mut template = vec![0; 2 * SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }
        if v.len() == SECRET_KEY_SIZE {
            bytes_array_32 = [0; SECRET_KEY_SIZE];
            let bytes = &v[..];
            bytes_array_32.copy_from_slice(&bytes);
            bytes_array_32.reverse();
            RistrettoScalar {
                purpose: "from_big_int",
                fe: SK::from_bytes_mod_order(bytes_array_32),
            }
        } else {
            bytes_array_64 = [0; 2 * SECRET_KEY_SIZE];
            let bytes = &v[..];
            bytes_array_64.copy_from_slice(&bytes);
            bytes_array_64.reverse();
            RistrettoScalar {
                purpose: "from_big_int",
                fe: SK::from_bytes_mod_order_wide(&bytes_array_64),
            }
        }
    }

    fn to_hex(&self) -> String {
        encode(self.get_element().to_bytes())
    }

    fn add(&self, other: &SK) -> RistrettoScalar {
        RistrettoScalar {
            purpose: "add",
            fe: self.get_element() + other,
        }
    }

    fn mul(&self, other: &SK) -> RistrettoScalar {
        RistrettoScalar {
            purpose: "mul",
            fe: self.get_element() * other,
        }
    }

    fn sub(&self, other: &SK) -> RistrettoScalar {
        RistrettoScalar {
            purpose: "sub",
            fe: self.get_element() - other,
        }
    }

    fn invert(&self) -> RistrettoScalar {
        let inv: SK = self.get_element().invert();
        RistrettoScalar {
            purpose: "invert",
            fe: inv,
        }
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
        let b: [u8; 32] = utils::from_slice(s_bytes.as_ref()).expect("Failed in array creation");
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
        let result = self.ge.to_bytes();
        result.to_vec()
    }

    fn get_element(&self) -> PK {
        self.ge
    }

    fn to_hex(&self) -> String {
        encode(self.pk_to_key_slice())
    }

    fn from_bytes(bytes: &[u8]) -> Result<RistrettoCurvPoint, Box<dyn Error>> {
        let bytes_vec = bytes.to_vec();
        let mut bytes_array_32 = [0u8; 32];
        let byte_len = bytes_vec.len();
        match byte_len {
            0..=32 => {
                let mut template = vec![0; 32 - bytes_vec.len()];
                template.extend_from_slice(&bytes);
                let bytes_vec = template;
                let bytes_slice = &bytes_vec[0..32];
                bytes_array_32.copy_from_slice(&bytes_slice);
                let r_point: PK = CompressedRistretto::from_slice(&bytes_array_32);
                let r_point_compress = r_point.decompress();
                match r_point_compress {
                    Some(x) => {
                        let new_point = RistrettoCurvPoint {
                            purpose: "random",
                            ge: x.compress(),
                        };
                        Ok(new_point)
                    }
                    None => bail!("Invalid Public Key"),
                }
            }

            _ => {
                let bytes_slice = &bytes_vec[0..32];
                bytes_array_32.copy_from_slice(&bytes_slice);
                let r_point: PK = CompressedRistretto::from_slice(&bytes_array_32);
                let r_point_compress = r_point.decompress();
                match r_point_compress {
                    Some(x) => {
                        let new_point = RistrettoCurvPoint {
                            purpose: "random",
                            ge: x.compress(),
                        };
                        Ok(new_point)
                    }
                    None => bail!("Invalid Public Key"),
                }
            }
        }
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
        let g: CompressedRistretto = CompressedRistretto::from_slice(s_bytes.as_ref());
        Ok(RistrettoCurvPoint {
            purpose: "from_bytes",
            ge: g,
        })
    }
}

impl PartialEq for RistrettoCurvPoint {
    fn eq(&self, other: &RistrettoCurvPoint) -> bool {
        self.get_element() == other.get_element()
    }
}
