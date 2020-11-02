use core::mem::{size_of};
use core::ptr::{self};
use core::slice::{self};

pub trait SliceExt {
	fn as_bytes(&self) -> &[u8];
	fn as_mut_bytes(&mut self) -> &mut [u8];
}

macro_rules! implement_slice_ext {
	($ty:ty) => {
		impl SliceExt for [$ty] {
			fn as_bytes(&self) -> &[u8] {
				unsafe { slice::from_raw_parts(self.as_ptr() as *const u8, self.len() * size_of::<$ty>()) }
			}

			fn as_mut_bytes(&mut self) -> &mut [u8] {
				unsafe { slice::from_raw_parts_mut(self.as_mut_ptr() as *mut u8, self.len() * size_of::<$ty>()) }
			}
		}
	}
}

implement_slice_ext!(u64);
implement_slice_ext!(u32);

pub fn zero_bytes(bytes: &mut [u8]) {
	unsafe { ptr::write_bytes(bytes.as_mut_ptr(), 0, bytes.len()) }
}