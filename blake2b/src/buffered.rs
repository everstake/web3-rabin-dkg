use core::cmp::{min};
use {Hash, ParameterBlock};
use slice_ext::{SliceExt, zero_bytes};
use unbuffered;

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Blake2b {
	blake2b: unbuffered::Blake2b,
	buffer: [u64; 16],
	buf_len: usize
}

impl Blake2b {
	pub fn new(len: usize) -> Self {
		Self::keyed(len, &[])
	}

	pub fn keyed(len: usize, key: &[u8]) -> Self {
		Self::with_parameter_block_keyed(len, key, ParameterBlock::new().set_digest_len(len as u8).set_key_len(key.len() as u8).set_fanout(1).set_max_depth(1))
	}

	pub fn with_parameter_block(len: usize, parameter_block: ParameterBlock) -> Self {
		Self::with_parameter_block_keyed(len, &[], parameter_block)
	}

	pub fn with_parameter_block_keyed(len: usize, key: &[u8], parameter_block: ParameterBlock) -> Self {
		let mut blake2b = Blake2b {
			blake2b: unbuffered::Blake2b::with_parameter_block(len, parameter_block),
			buffer: [0; 16],
			buf_len: 0
		};

		if !key.is_empty() {
			blake2b.buffer.as_mut_bytes()[..key.len()].copy_from_slice(key);
			blake2b.buf_len = 128;
		}

		blake2b
	}

	pub fn len(&self) -> usize {
		self.blake2b.len()
	}

	pub fn update(&mut self, mut data: &[u8]) {
		while !data.is_empty() {
			if self.buf_len == 128 {
				self.blake2b.update(&self.buffer);
				self.buf_len = 0;
			}

			let len = min(128 - self.buf_len, data.len());
			self.buffer.as_mut_bytes()[self.buf_len..self.buf_len + len].copy_from_slice(&data[..len]);
			self.buf_len += len;

			data = &data[len..];
		}
	}

	pub fn finish(mut self) -> Hash {
		zero_bytes(&mut self.buffer.as_mut_bytes()[self.buf_len..]);
		self.blake2b.finish(&self.buffer, self.buf_len)
	}
}

impl Default for Blake2b {
	fn default() -> Self {
		Self::new(64)
	}
}