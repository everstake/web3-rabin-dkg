use core::ops::{Add, BitXor};

#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
pub struct u64x4(pub u64, pub u64, pub u64, pub u64);

impl u64x4 {
    pub fn rotate_right(self, r: u64) -> Self {
        debug_assert!(r <= 64);

        let l = 64 - r;
        u64x4(self.0 >> r, self.1 >> r, self.2 >> r, self.3 >> r)
            ^ u64x4(self.0 << l, self.1 << l, self.2 << l, self.3 << l)
    }

    pub fn shuffle_left_1(self) -> Self {
        u64x4(self.1, self.2, self.3, self.0)
    }

    pub fn shuffle_left_2(self) -> Self {
        u64x4(self.2, self.3, self.0, self.1)
    }

    pub fn shuffle_left_3(self) -> Self {
        u64x4(self.3, self.0, self.1, self.2)
    }

    pub fn shuffle_right_1(self) -> Self {
        self.shuffle_left_3()
    }

    pub fn shuffle_right_2(self) -> Self {
        self.shuffle_left_2()
    }

    pub fn shuffle_right_3(self) -> Self {
        self.shuffle_left_1()
    }
}

impl Add for u64x4 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        u64x4(
            self.0.wrapping_add(rhs.0),
            self.1.wrapping_add(rhs.1),
            self.2.wrapping_add(rhs.2),
            self.3.wrapping_add(rhs.3),
        )
    }
}

impl BitXor<u64x4> for u64x4 {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        u64x4(
            self.0 ^ rhs.0,
            self.1 ^ rhs.1,
            self.2 ^ rhs.2,
            self.3 ^ rhs.3,
        )
    }
}
