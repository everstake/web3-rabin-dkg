use core::cmp::min;
use slice_ext::SliceExt;
use unbuffered;
use {Blake2b, Hash, ParameterBlock};

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Blake2xb {
    blake2b: Blake2b,
    parameter_block: ParameterBlock,
    len: u32,
}

pub struct Iter {
    parameter_block: ParameterBlock,
    block: [u64; 16],
    block_len: usize,
    max_out_len: u32,
    out_len: u32,
}

impl Blake2xb {
    pub fn new(len: Option<u32>) -> Self {
        Self::keyed(len, &[])
    }

    pub fn keyed(len: Option<u32>, key: &[u8]) -> Self {
        assert!(
            len.map(|len| len != 0 && len != u32::max_value())
                .unwrap_or(true),
            "len must be >= 1 and <= 2^32 - 2"
        );

        let parameter_block = ParameterBlock::new()
            .set_digest_len(64)
            .set_key_len(key.len() as u8)
            .set_fanout(1)
            .set_max_depth(1)
            .set_node_offset((len.unwrap_or(u32::max_value()) as u64) << 32); //>

        Self::with_parameter_block_keyed(len, key, parameter_block)
    }

    pub fn with_parameter_block_keyed(
        len: Option<u32>,
        key: &[u8],
        parameter_block: ParameterBlock,
    ) -> Self {
        assert!(
            len.map(|len| len != 0 && len != u32::max_value())
                .unwrap_or(true),
            "len must be >= 1 and <= 2^32 - 2"
        );

        Blake2xb {
            blake2b: Blake2b::with_parameter_block_keyed(64, key, parameter_block),
            parameter_block,
            len: len.unwrap_or(u32::max_value()),
        }
    }

    pub fn length(&self) -> usize {
        self.len as usize
    }

    pub fn update(&mut self, data: &[u8]) {
        self.blake2b.update(data);
    }

    pub fn finish(self) -> Iter {
        let mut block = [0; 16];
        block[..8].copy_from_slice(&self.blake2b.finish().into_inner());

        let parameter_block = self
            .parameter_block
            .set_key_len(0)
            .set_fanout(0)
            .set_max_depth(0)
            .set_max_leaf_len(64)
            .set_node_depth(0)
            .set_inner_len(64);

        Iter {
            parameter_block,
            block,
            block_len: 64,
            max_out_len: self.len,
            out_len: 0,
        }
    }
}

impl Iter {
    pub fn new(len: Option<u32>, seed: &[u8]) -> Self {
        let parameter_block = ParameterBlock::new().set_max_leaf_len(64).set_inner_len(64);

        Self::with_parameter_block(len, seed, parameter_block)
    }

    pub fn with_parameter_block(
        len: Option<u32>,
        seed: &[u8],
        parameter_block: ParameterBlock,
    ) -> Self {
        assert!(
            len.map(|len| len != 0 && len != u32::max_value())
                .unwrap_or(true),
            "len must be >= 1 and <= 2^32 - 2"
        );
        assert!(seed.len() <= 128, "seed length must be <= 128");

        let mut block = [0; 16];
        block.as_mut_bytes()[..seed.len()].copy_from_slice(seed);

        Iter {
            parameter_block,
            block,
            block_len: seed.len(),
            max_out_len: len.unwrap_or(u32::max_value()),
            out_len: 0,
        }
    }

    pub fn max_out_len(&self) -> usize {
        self.max_out_len as usize
    }

    pub fn out_len(&self) -> usize {
        self.out_len as usize
    }
}

impl Iterator for Iter {
    type Item = Hash;

    fn next(&mut self) -> Option<Self::Item> {
        if self.out_len == self.max_out_len {
            return None;
        }

        let len = min(self.max_out_len - self.out_len, 64);
        let parameter_block = self
            .parameter_block
            .clone()
            .set_digest_len(len as u8)
            .set_node_offset((self.out_len as u64 / 64) | ((self.max_out_len as u64) << 32)); //>

        self.out_len += len;
        Some(
            unbuffered::Blake2b::with_parameter_block(len as usize, parameter_block)
                .finish(&self.block, self.block_len),
        )
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let i = (self.max_out_len - self.out_len) as usize / 64
            + if self.max_out_len % 64 != 0 { 1 } else { 0 };
        (i, Some(i))
    }
}
