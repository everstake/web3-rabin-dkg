use slice_ext::SliceExt;
use {compress, Hash, ParameterBlock};

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Blake2b {
    hash: [u64; 8],
    #[cfg(i128)]
    counter: u128,
    #[cfg(not(i128))]
    counter: (u64, u64),
    len: usize,
}

impl Blake2b {
    pub fn new(len: usize) -> Self {
        Self::with_parameter_block(
            len,
            ParameterBlock::new()
                .set_digest_len(len as u8)
                .set_fanout(1)
                .set_max_depth(1),
        )
    }

    pub fn with_parameter_block(len: usize, parameter_block: ParameterBlock) -> Self {
        assert!(len >= 1 && len <= 64, "len must be >= 1 and <= 64");

        Blake2b {
            hash: parameter_block.xor_with_iv().0,
            counter: (0, 0),
            len,
        }
    }

    pub fn length(&self) -> usize {
        self.len
    }

    pub fn update(&mut self, block: &[u64; 16]) {
        #[cfg(i128)]
        self.counter
            .checked_add(128)
            .expect("blake2b counter overflowed");
        #[cfg(not(i128))]
        self.add_counter(128);

        compress(block, &mut self.hash, self.counter, (0, 0));
    }

    pub fn finish(mut self, block: &[u64; 16], len: usize) -> Hash {
        assert!(len <= 128);
        debug_assert!(block.as_bytes()[len..].iter().all(|&i| i == 0));

        #[cfg(i128)]
        self.counter
            .checked_add(len as u128)
            .expect("blake2b counter overflowed");
        #[cfg(not(i128))]
        self.add_counter(len as u64);

        compress(block, &mut self.hash, self.counter, (!0, 0));
        Hash::new(self.hash, self.len)
    }

    #[cfg(not(i128))]
    fn add_counter(&mut self, v: u64) {
        debug_assert!(v <= 128);

        let (v, b) = self.counter.0.overflowing_add(v);
        self.counter.0 = v;
        if b {
            self.counter.1 = self
                .counter
                .1
                .checked_add(1)
                .expect("blake2b counter overflowed");
        }
    }
}

impl Default for Blake2b {
    fn default() -> Self {
        Self::new(64)
    }
}
