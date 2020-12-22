use core::ops::{Deref, DerefMut};
use slice_ext::{zero_bytes, SliceExt};
use IV;

#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ParameterBlock(pub [u64; 8]);

impl ParameterBlock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn digest_len(&self) -> u8 {
        self[0]
    }

    pub fn set_digest_len(mut self, digest_len: u8) -> Self {
        self[0] = digest_len;
        self
    }

    pub fn key_len(&self) -> u8 {
        self[1]
    }

    pub fn set_key_len(mut self, key_len: u8) -> Self {
        self[1] = key_len;
        self
    }

    pub fn fanout(&self) -> u8 {
        self[2]
    }

    pub fn set_fanout(mut self, fanout: u8) -> Self {
        self[2] = fanout;
        self
    }

    pub fn max_depth(&self) -> u8 {
        self[3]
    }

    pub fn set_max_depth(mut self, max_depth: u8) -> Self {
        self[3] = max_depth;
        self
    }

    pub fn max_leaf_len(&self) -> u32 {
        (self.0[0] >> 32) as u32
    }

    pub fn set_max_leaf_len(mut self, max_leaf_len: u32) -> Self {
        self[4..8].copy_from_slice([max_leaf_len].as_bytes());
        self
    }

    pub fn node_offset(&self) -> u64 {
        self.0[1]
    }

    pub fn set_node_offset(mut self, node_offset: u64) -> Self {
        self.0[1] = node_offset;
        self
    }

    pub fn node_depth(&self) -> u8 {
        self[16]
    }

    pub fn set_node_depth(mut self, node_depth: u8) -> Self {
        self[16] = node_depth;
        self
    }

    pub fn inner_len(&self) -> u8 {
        self[17]
    }

    pub fn set_inner_len(mut self, inner_len: u8) -> Self {
        self[17] = inner_len;
        self
    }

    pub fn salt(&self) -> &[u8] {
        &self[32..48]
    }

    pub fn set_salt(mut self, salt: &[u8]) -> Self {
        assert!(salt.len() <= 16, "salt length must be <= 16");
        self[32..32 + salt.len()].copy_from_slice(salt);
        zero_bytes(&mut self[32 + salt.len()..48]);
        self
    }

    pub fn personalization(&self) -> &[u8] {
        &self[48..64]
    }

    pub fn set_personalization(mut self, personalization: &[u8]) -> Self {
        assert!(
            personalization.len() <= 16,
            "personalization length must be <= 16"
        );

        self[48..48 + personalization.len()].copy_from_slice(personalization);
        zero_bytes(&mut self[48 + personalization.len()..64]);
        self
    }

    pub fn xor_with_iv(mut self) -> Self {
        for (a, b) in self.0.iter_mut().zip(IV.iter()) {
            *a ^= *b;
        }

        self
    }
}

impl AsRef<[u8]> for ParameterBlock {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl AsMut<[u8]> for ParameterBlock {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_bytes()
    }
}

impl Deref for ParameterBlock {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl DerefMut for ParameterBlock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}
