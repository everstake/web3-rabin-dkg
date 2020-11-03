use std::error::Error;

pub trait ECScalar<SK> {
    fn new_random() -> Self;
    fn zero() -> Self;
    fn get_element(&self) -> SK;
    fn set_element(&mut self, element: SK);
    fn from(n: u64) -> Self;
    fn to_hex(&self) -> String;
    fn add(&self, other: &SK) -> Self;
    fn mul(&self, other: &SK) -> Self;
    fn sub(&self, other: &SK) -> Self;
    fn invert(&self) -> Self;
}

pub trait ECPoint<PK, SK>
where
    Self: Sized,
{
    fn generator() -> Self;
    fn pk_to_key_slice(&self) -> Vec<u8>;
    fn get_element(&self) -> PK;
    fn to_hex(&self) -> String;
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>>;
    fn scalar_mul(&self, fe: &SK) -> Self;
    fn add_point(&self, other: &PK) -> Self;
    fn sub_point(&self, other: &PK) -> Self;
}
