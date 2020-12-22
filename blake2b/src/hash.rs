use core::cmp::{Eq, PartialEq};
use core::convert::{AsMut, AsRef};
use core::fmt::{self, Debug, Formatter};
use core::hash::{self};
use core::ops::{Deref, DerefMut};
use slice_ext::SliceExt;

#[derive(Copy, Clone)]
pub struct Hash {
    hash: [u64; 8],
    len: usize,
}

impl Hash {
    pub(crate) fn new(hash: [u64; 8], len: usize) -> Self {
        Hash { hash, len }
    }

    pub fn length(&self) -> usize {
        self.len
    }

    pub(crate) fn into_inner(self) -> [u64; 8] {
        self.hash
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.hash.as_bytes()[..self.len]
    }
}

impl AsMut<[u8]> for Hash {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.hash.as_mut_bytes()[..self.len]
    }
}

impl Debug for Hash {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, fmt)
    }
}

impl Deref for Hash {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl DerefMut for Hash {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl Eq for Hash {}

impl hash::Hash for Hash {
    fn hash<H>(&self, hasher: &mut H)
    where
        H: hash::Hasher,
    {
        hasher.write(&**self);
    }
}

impl PartialEq for Hash {
    fn eq(&self, rhs: &Self) -> bool {
        self.as_ref() == rhs.as_ref()
    }
}

impl PartialEq<[u8]> for Hash {
    fn eq(&self, rhs: &[u8]) -> bool {
        self.as_ref() == rhs
    }
}
