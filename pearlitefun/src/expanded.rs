#![feature(derive_clone_copy)]
#![feature(core_panic)]
#![feature(libstd_sys_internals)]

#![feature(prelude_import)]
// #[prelude_import]
// use std::prelude::rust_2021::*;
// #[macro_use]
// extern crate std;
extern crate core;
use core::*;
#[cfg(not(feature = "hacspec"))]
extern crate hacspec_lib;
#[cfg(not(feature = "hacspec"))]
extern crate creusot_contracts;
#[cfg(not(feature = "hacspec"))]
pub use creusot_contracts::*;
pub use creusot_contracts::ensures;
pub use creusot_contracts::requires;
pub use creusot_contracts::logic;
pub use creusot_contracts::predicate;
pub use creusot_contracts::pearlite;
pub use creusot_contracts::trusted;
pub use hacspec_lib::*;
pub use hacspec_lib::Seq;
pub struct FieldCanvas {
    b: [u8; (256 + 7) / 8],
    sign: Sign,
    signed: bool,
}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::clone::Clone for FieldCanvas {
    #[inline]
    fn clone(&self) -> FieldCanvas {
        {
            let _: ::core::clone::AssertParamIsClone<[u8; (256 + 7) / 8]>;
            let _: ::core::clone::AssertParamIsClone<Sign>;
            let _: ::core::clone::AssertParamIsClone<bool>;
            *self
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::marker::Copy for FieldCanvas {}
impl FieldCanvas {
    fn max() -> BigInt {
        BigInt::from(1u32).shl(256) - BigInt::one()
    }
    pub fn max_value() -> Self {
        Self::from(Self::max())
    }
    fn hex_string_to_bytes(s: &str) -> Vec<u8> {
        let s = s.to_string();
        let mut b: Vec<u8> = Vec::new();
        {
            let mut i = 0;
            if s.len() % 2 != 0 {
                i += 1;
                b.push(u8::from_str_radix(&s[0..1], 16).unwrap());
            }
            while i < s.len() {
                b.push(u8::from_str_radix(&s[i..i + 2], 16).unwrap());
                i += 2;
            }
        }
        b
    }
    #[allow(dead_code)]
    pub fn from_literal(x: u64) -> Self {
        let big_x = BigInt::from(x);
        big_x.into()
    }
    #[allow(dead_code)]
    pub fn from_signed_literal(x: i64) -> Self {
        let big_x = BigInt::from(x as u64);
        big_x.into()
    }
    /// Returns 2 to the power of the argument
    #[allow(dead_code)]
    pub fn pow2(x: usize) -> FieldCanvas {
        BigInt::from(1u32).shl(x).into()
    }
    /// Gets the `i`-th least significant bit of this integer.
    #[allow(dead_code)]
    pub fn bit(self, i: usize) -> bool {
        let bigint: BigInt = self.into();
        let tmp: BigInt = bigint >> i;
        (tmp & BigInt::one()).to_bytes_le().1[0] == 1
    }
}
impl From<BigUint> for FieldCanvas {
    fn from(x: BigUint) -> FieldCanvas {
        Self::from(BigInt::from(x))
    }
}
impl From<BigInt> for FieldCanvas {
    #[cfg(not(feature = "std"))]
    fn from(x: BigInt) -> FieldCanvas {
        let (sign, repr) = x.to_bytes_be();
        let mut out: [u8; (256 + 7) / 8] = core::convert::TryInto::<[u8; (256 + 7) / 8]>::try_into(
            ::alloc::vec::from_elem(0u8, (256 + 7) / 8),
        )
        .unwrap();
        let upper = out.as_ref().len();
        let lower = upper - repr.len();
        out[lower..upper].copy_from_slice(&repr);
        FieldCanvas {
            b: out,
            sign: sign,
            signed: false,
        }
    }
}
impl Default for FieldCanvas {
    #[cfg(not(feature = "std"))]
    fn default() -> FieldCanvas {
        FieldCanvas {
            b: core::convert::TryInto::<[u8; (256 + 7) / 8]>::try_into(::alloc::vec::from_elem(
                0u8,
                (256 + 7) / 8,
            ))
            .unwrap(),
            sign: Sign::Plus,
            signed: false,
        }
    }
}
impl Into<BigInt> for FieldCanvas {
    fn into(self) -> BigInt {
        BigInt::from_bytes_be(self.sign, self.b.as_ref())
    }
}
impl Into<BigUint> for FieldCanvas {
    fn into(self) -> BigUint {
        BigUint::from_bytes_be(self.b.as_ref())
    }
}
impl FieldCanvas {
    #[allow(dead_code)]
    pub fn from_hex(s: &str) -> Self {
        BigInt::from_bytes_be(Sign::Plus, &Self::hex_string_to_bytes(s)).into()
    }
    #[cfg(not(feature = "std"))]
    #[allow(dead_code)]
    pub fn from_be_bytes(v: &[u8]) -> Self {
        if true {
            if !(v.len() <= (256 + 7) / 8) {
                {
                    :: std :: rt :: begin_panic ("from_be_bytes: lenght of bytes should be lesser than the lenght of the canvas")
                }
            };
        };
        let mut repr = core::convert::TryInto::<[u8; (256 + 7) / 8]>::try_into(
            ::alloc::vec::from_elem(0u8, (256 + 7) / 8),
        )
        .unwrap();
        let upper = repr.as_ref().len();
        let lower = upper - v.len();
        repr[lower..upper].copy_from_slice(&v);
        FieldCanvas {
            b: repr,
            sign: Sign::Plus,
            signed: false,
        }
    }
    #[cfg(not(feature = "std"))]
    #[allow(dead_code)]
    pub fn from_le_bytes(v: &[u8]) -> Self {
        if true {
            if !(v.len() <= (256 + 7) / 8) {
                {
                    :: std :: rt :: begin_panic ("from_be_bytes: lenght of bytes should be lesser than the lenght of the canvas")
                }
            };
        };
        let mut repr = core::convert::TryInto::<[u8; (256 + 7) / 8]>::try_into(
            ::alloc::vec::from_elem(0u8, (256 + 7) / 8),
        )
        .unwrap();
        let upper = repr.as_ref().len();
        let lower = upper - v.len();
        repr[lower..upper].copy_from_slice(&v);
        BigInt::from_bytes_le(Sign::Plus, repr.as_ref()).into()
    }
    #[allow(dead_code)]
    pub fn to_be_bytes(self) -> [u8; (256 + 7) / 8] {
        self.b
    }
    #[cfg(not(feature = "std"))]
    #[allow(dead_code)]
    pub fn to_le_bytes(self) -> [u8; (256 + 7) / 8] {
        let x = BigInt::from_bytes_be(Sign::Plus, self.b.as_ref());
        let (_, x_s) = x.to_bytes_le();
        let mut repr = core::convert::TryInto::<[u8; (256 + 7) / 8]>::try_into(
            ::alloc::vec::from_elem(0u8, (256 + 7) / 8),
        )
        .unwrap();
        repr[0..x_s.len()].copy_from_slice(&x_s);
        repr
    }
    /// Produces a new integer which is all ones if the two arguments are equal and
    /// all zeroes otherwise.
    /// **NOTE:** This is not constant time but `BigInt` generally isn't.
    #[inline]
    pub fn comp_eq(self, rhs: Self) -> Self {
        if self.is_eq(&rhs) {
            let one = Self::from_literal(1);
            (one << (256 - 1)) - one
        } else {
            Self::default()
        }
    }
    /// Produces a new integer which is all ones if the first argument is different from
    /// the second argument, and all zeroes otherwise.
    /// **NOTE:** This is not constant time but `BigInt` generally isn't.
    #[inline]
    pub fn comp_ne(self, rhs: Self) -> Self {
        if self.is_ne(&rhs) {
            let one = Self::from_literal(1);
            (one << (256 - 1)) - one
        } else {
            Self::default()
        }
    }
    /// Produces a new integer which is all ones if the first argument is greater than or
    /// equal to the second argument, and all zeroes otherwise.
    /// **NOTE:** This is not constant time but `BigInt` generally isn't.
    #[inline]
    pub fn comp_gte(self, rhs: Self) -> Self {
        if self.is_gte(&rhs) {
            let one = Self::from_literal(1);
            (one << (256 - 1)) - one
        } else {
            Self::default()
        }
    }
    /// Produces a new integer which is all ones if the first argument is strictly greater
    /// than the second argument, and all zeroes otherwise.
    /// **NOTE:** This is not constant time but `BigInt` generally isn't.
    #[inline]
    pub fn comp_gt(self, rhs: Self) -> Self {
        if self.is_gt(&rhs) {
            let one = Self::from_literal(1);
            (one << (256 - 1)) - one
        } else {
            Self::default()
        }
    }
    /// Produces a new integer which is all ones if the first argument is less than or
    /// equal to the second argument, and all zeroes otherwise.
    /// **NOTE:** This is not constant time but `BigInt` generally isn't.
    #[inline]
    pub fn comp_lte(self, rhs: Self) -> Self {
        if self.is_lte(&rhs) {
            let one = Self::from_literal(1);
            (one << (256 - 1)) - one
        } else {
            Self::default()
        }
    }
    /// Produces a new integer which is all ones if the first argument is strictly less than
    /// the second argument, and all zeroes otherwise.
    /// **NOTE:** This is not constant time but `BigInt` generally isn't.
    #[inline]
    pub fn comp_lt(self, rhs: Self) -> Self {
        if self.is_lt(&rhs) {
            let one = Self::from_literal(1);
            (one << (256 - 1)) - one
        } else {
            Self::default()
        }
    }
}
impl FieldCanvas {
    #[allow(dead_code)]
    pub fn inv(self, modval: Self) -> Self {
        let biguintmodval: BigInt = modval.into();
        let m = &biguintmodval - BigInt::from(2u32);
        let s: BigInt = (self).into();
        s.modpow(&m, &biguintmodval).into()
    }
    #[allow(dead_code)]
    pub fn pow_felem(self, exp: Self, modval: Self) -> Self {
        let a: BigInt = self.into();
        let b: BigInt = exp.into();
        let m: BigInt = modval.into();
        let c: BigInt = a.modpow(&b, &m);
        c.into()
    }
    /// Returns self to the power of the argument.
    /// The exponent is a u128.
    #[allow(dead_code)]
    pub fn pow(self, exp: u64, modval: Self) -> Self {
        self.pow_felem(BigInt::from(exp).into(), modval)
    }
    fn rem(self, n: Self) -> Self {
        self % n
    }
}
/// **Warning**: panics on overflow.
impl Add for FieldCanvas {
    type Output = FieldCanvas;
    fn add(self, rhs: FieldCanvas) -> FieldCanvas {
        let a: BigInt = self.into();
        let b: BigInt = rhs.into();
        let c = a + b;
        c.into()
    }
}
/// **Warning**: panics on underflow.
impl Sub for FieldCanvas {
    type Output = FieldCanvas;
    fn sub(self, rhs: FieldCanvas) -> FieldCanvas {
        let a: BigInt = self.into();
        let b: BigInt = rhs.into();
        let c = if self.signed {
            a - b
        } else {
            a.checked_sub(&b).unwrap()
        };
        c.into()
    }
}
/// **Warning**: panics on overflow.
impl Mul for FieldCanvas {
    type Output = FieldCanvas;
    fn mul(self, rhs: FieldCanvas) -> FieldCanvas {
        let a: BigInt = self.into();
        let b: BigInt = rhs.into();
        let c = a * b;
        c.into()
    }
}
/// **Warning**: panics on division by 0.
impl Div for FieldCanvas {
    type Output = FieldCanvas;
    fn div(self, rhs: FieldCanvas) -> FieldCanvas {
        let a: BigInt = self.into();
        let b: BigInt = rhs.into();
        let c = a / b;
        c.into()
    }
}
/// **Warning**: panics on division by 0.
impl Rem for FieldCanvas {
    type Output = FieldCanvas;
    fn rem(self, rhs: FieldCanvas) -> FieldCanvas {
        let a: BigInt = self.into();
        let b: BigInt = rhs.into();
        let c = a % b;
        c.into()
    }
}
impl Not for FieldCanvas {
    type Output = FieldCanvas;
    fn not(self) -> Self::Output {
        ::core::panicking::panic("not implemented");
    }
}
impl BitOr for FieldCanvas {
    type Output = FieldCanvas;
    fn bitor(self, rhs: Self) -> Self::Output {
        let a: BigInt = self.into();
        let b: BigInt = rhs.into();
        (a | b).into()
    }
}
impl BitXor for FieldCanvas {
    type Output = FieldCanvas;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let a: BigInt = self.into();
        let b: BigInt = rhs.into();
        (a ^ b).into()
    }
}
impl BitAnd for FieldCanvas {
    type Output = FieldCanvas;
    fn bitand(self, rhs: Self) -> Self::Output {
        let a: BigInt = self.into();
        let b: BigInt = rhs.into();
        (a & b).into()
    }
}
impl Shr<usize> for FieldCanvas {
    type Output = FieldCanvas;
    fn shr(self, rhs: usize) -> Self::Output {
        let a: BigInt = self.into();
        let b = rhs as usize;
        (a >> b).into()
    }
}
impl Shl<usize> for FieldCanvas {
    type Output = FieldCanvas;
    fn shl(self, rhs: usize) -> Self::Output {
        let a: BigInt = self.into();
        let b = rhs as usize;
        (a << b).into()
    }
}
impl PartialEq for FieldCanvas {
    #[cfg(not(feature = "std"))]
    fn eq(&self, rhs: &FieldCanvas) -> bool {
        match (*self).cmp(rhs) {
            core::cmp::Ordering::Equal => true,
            _ => false,
        }
    }
}
impl FieldCanvas {
    #[cfg(not(feature = "std"))]
    fn is_eq(&self, rhs: &FieldCanvas) -> bool {
        match (*self).cmp(rhs) {
            core::cmp::Ordering::Equal => true,
            _ => false,
        }
    }
    fn is_ne(&self, rhs: &FieldCanvas) -> bool {
        (*self).is_eq(rhs)
    }
    #[cfg(not(feature = "std"))]
    fn is_lt(&self, rhs: &FieldCanvas) -> bool {
        match (*self).cmp(rhs) {
            core::cmp::Ordering::Less => true,
            _ => false,
        }
    }
    #[cfg(not(feature = "std"))]
    fn is_gt(&self, rhs: &FieldCanvas) -> bool {
        match (*self).cmp(rhs) {
            core::cmp::Ordering::Greater => true,
            _ => false,
        }
    }
    fn is_lte(&self, rhs: &FieldCanvas) -> bool {
        (*self).is_eq(rhs) || (*self).is_lt(rhs)
    }
    fn is_gte(&self, rhs: &FieldCanvas) -> bool {
        (*self).is_eq(rhs) || (*self).is_gt(rhs)
    }
}
impl Eq for FieldCanvas {}
impl PartialOrd for FieldCanvas {
    #[cfg(not(feature = "std"))]
    fn partial_cmp(&self, other: &FieldCanvas) -> Option<core::cmp::Ordering> {
        Some((*self).cmp(other))
    }
}
impl Ord for FieldCanvas {
    #[cfg(not(feature = "std"))]
    fn cmp(&self, other: &FieldCanvas) -> core::cmp::Ordering {
        let signed_cmp = (*self).signed.cmp(&(*other).signed);
        match signed_cmp {
            core::cmp::Ordering::Equal => (),
            _ => {
                return signed_cmp;
            }
        };
        match ((*self).sign, (*other).sign) {
            (Sign::Minus, Sign::Minus) => (*other).b.cmp(&(*self).b),
            (Sign::Minus, _) => core::cmp::Ordering::Less,
            (Sign::NoSign, Sign::NoSign) => core::cmp::Ordering::Equal,
            (Sign::Plus, Sign::Plus) => (*self).b.cmp(&(*other).b),
            (Sign::Plus, _) => core::cmp::Ordering::Greater,
            (Sign::NoSign, Sign::Minus) => core::cmp::Ordering::Greater,
            (Sign::NoSign, Sign::Plus) => core::cmp::Ordering::Less,
        }
    }
}
impl FieldCanvas {
    pub fn from_byte_seq_be<A: SeqTrait<U8>>(s: &A) -> FieldCanvas {
        let mut temp = Vec::new();
        let len = s.len();
        let mut i = 0;
        while i < len {
            temp.push(U8::declassify(s[i]));
            i += 1;
        }
        FieldCanvas::from_be_bytes(temp.as_slice())
    }
    pub fn from_public_byte_seq_be<A: SeqTrait<u8>>(s: A) -> FieldCanvas {
        let mut temp = Vec::new();
        let len = s.len();
        let mut i = 0;
        while i < len {
            temp.push(s[i]);
            i += 1;
        }
        FieldCanvas::from_be_bytes(temp.as_slice())
    }
    pub fn to_byte_seq_be(self) -> hacspec_lib::Seq<U8> {
        let mut temp = Vec::new();
        let len = self.to_be_bytes().as_ref().len();
        let mut i = 0;
        while i < len {
            let te: u8 = self.to_be_bytes().as_ref()[i];
            temp.push(U8::classify(te));
            i += 1;
        }
        hacspec_lib::Seq::from_vec(temp)
    }
}
impl NumericCopy for FieldCanvas {}
impl UnsignedInteger for FieldCanvas {}
impl UnsignedIntegerCopy for FieldCanvas {}
impl Integer for FieldCanvas {
    fn NUM_BITS() -> usize {
        256
    }
    #[inline]
    fn ZERO() -> Self {
        Self::from_literal(0)
    }
    #[inline]
    fn ONE() -> Self {
        Self::from_literal(1)
    }
    #[inline]
    fn TWO() -> Self {
        Self::from_literal(2)
    }
    #[inline]
    fn from_literal(val: u64) -> Self {
        Self::from_literal(val)
    }
    #[inline]
    fn from_hex_string(s: &String) -> Self {
        Self::from_hex(&s.replace("0x", ""))
    }
    #[cfg(not(feature = "hacspec"))]
    /// Get bit `i` of this integer.
    #[inline]
    fn get_bit(self, i: usize) -> Self {
        (self >> i) & Self::ONE()
    }
    #[cfg(not(feature = "hacspec"))]
    /// Set bit `i` of this integer to `b` and return the result.
    /// Bit `b` has to be `0` or `1`.
    #[inline]
    fn set_bit(self, b: Self, i: usize) -> Self {
        if true {
            if !(b.clone().equal(Self::ONE()) || b.clone().equal(Self::ZERO())) {
                :: core :: panicking :: panic ("assertion failed: b.clone().equal(Self::ONE()) || b.clone().equal(Self::ZERO())")
            };
        };
        let tmp1 = Self::from_literal(!(1 << i));
        let tmp2 = b << i;
        (self & tmp1) | tmp2
    }
    /// Set bit `pos` of this integer to bit `yi` of integer `y`.
    #[inline]
    fn set(self, pos: usize, y: Self, yi: usize) -> Self {
        let b = y.get_bit(yi);
        self.set_bit(b, pos)
    }
    #[cfg(not(feature = "hacspec"))]
    fn rotate_left(self, n: usize) -> Self {
        if !(n < Self::NUM_BITS()) {
            ::core::panicking::panic("assertion failed: n < Self::NUM_BITS()")
        };
        (self.clone() << n) | (self >> ((-(n as i32) as usize) & (Self::NUM_BITS() - 1)))
    }
    #[cfg(not(feature = "hacspec"))]
    fn rotate_right(self, n: usize) -> Self {
        if !(n < Self::NUM_BITS()) {
            ::core::panicking::panic("assertion failed: n < Self::NUM_BITS()")
        };
        (self.clone() >> n) | (self << ((-(n as i32) as usize) & (Self::NUM_BITS() - 1)))
    }
}
impl ModNumeric for FieldCanvas {
    /// (self - rhs) % n.
    fn sub_mod(self, rhs: Self, n: Self) -> Self {
        (self - rhs) % n
    }
    /// `(self + rhs) % n`
    fn add_mod(self, rhs: Self, n: Self) -> Self {
        (self + rhs) % n
    }
    /// `(self * rhs) % n`
    fn mul_mod(self, rhs: Self, n: Self) -> Self {
        (self * rhs) % n
    }
    /// `(self ^ exp) % n`
    fn pow_mod(self, exp: Self, n: Self) -> Self {
        self.pow_felem(exp, n)
    }
    /// `self % n`
    fn modulo(self, n: Self) -> Self {
        self % n
    }
    /// `self % n` that always returns a positive integer
    fn signed_modulo(self, n: Self) -> Self {
        self.modulo(n)
    }
    /// `|self|`
    fn absolute(self) -> Self {
        self
    }
}
impl Numeric for FieldCanvas {
    /// Return largest value that can be represented.
    fn max_val() -> Self {
        FieldCanvas::max_value()
    }
    fn wrap_add(self, rhs: Self) -> Self {
        self + rhs
    }
    fn wrap_sub(self, rhs: Self) -> Self {
        self - rhs
    }
    fn wrap_mul(self, rhs: Self) -> Self {
        self * rhs
    }
    fn wrap_div(self, rhs: Self) -> Self {
        self / rhs
    }
    /// `self ^ exp` where `exp` is a `u32`.
    fn exp(self, exp: u32) -> Self {
        self.pow(exp.into(), Self::max_val())
    }
    /// `self ^ exp` where `exp` is a `Self`.
    fn pow_self(self, exp: Self) -> Self {
        self.pow_felem(exp.into(), Self::max_val())
    }
    /// Division.
    fn divide(self, rhs: Self) -> Self {
        self / rhs
    }
    /// Invert self modulo n.
    fn inv(self, n: Self) -> Self {
        FieldCanvas::inv(self, n)
    }
    fn equal(self, other: Self) -> bool {
        self.is_eq(&other)
    }
    fn greater_than(self, other: Self) -> bool {
        self > other
    }
    fn greater_than_or_qual(self, other: Self) -> bool {
        self >= other
    }
    fn less_than(self, other: Self) -> bool {
        self < other
    }
    fn less_than_or_equal(self, other: Self) -> bool {
        self >= other
    }
    fn not_equal_bm(self, other: Self) -> Self {
        if !self.equal(other) {
            Self::max_val()
        } else {
            Self::from_literal(0)
        }
    }
    fn equal_bm(self, other: Self) -> Self {
        if self.equal(other) {
            Self::max_val()
        } else {
            Self::from_literal(0)
        }
    }
    fn greater_than_bm(self, other: Self) -> Self {
        if self.greater_than(other) {
            Self::max_val()
        } else {
            Self::from_literal(0)
        }
    }
    fn greater_than_or_equal_bm(self, other: Self) -> Self {
        if self.greater_than_or_qual(other) {
            Self::max_val()
        } else {
            Self::from_literal(0)
        }
    }
    fn less_than_bm(self, other: Self) -> Self {
        if self.less_than(other) {
            Self::max_val()
        } else {
            Self::from_literal(0)
        }
    }
    fn less_than_or_equal_bm(self, other: Self) -> Self {
        if self.less_than_or_equal(other) {
            Self::max_val()
        } else {
            Self::from_literal(0)
        }
    }
}
pub struct Ed25519FieldElement(FieldCanvas);
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::clone::Clone for Ed25519FieldElement {
    #[inline]
    fn clone(&self) -> Ed25519FieldElement {
        {
            let _: ::core::clone::AssertParamIsClone<FieldCanvas>;
            *self
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::marker::Copy for Ed25519FieldElement {}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::default::Default for Ed25519FieldElement {
    #[inline]
    fn default() -> Ed25519FieldElement {
        Ed25519FieldElement(::core::default::Default::default())
    }
}
impl From<FieldCanvas> for Ed25519FieldElement {
    fn from(x: FieldCanvas) -> Ed25519FieldElement {
        Ed25519FieldElement(x.rem(FieldCanvas::from_hex(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
        )))
    }
}
impl Into<FieldCanvas> for Ed25519FieldElement {
    fn into(self) -> FieldCanvas {
        self.0
    }
}
impl Ed25519FieldElement {
    pub fn from_canvas(x: FieldCanvas) -> Ed25519FieldElement {
        Ed25519FieldElement(x.rem(FieldCanvas::from_hex(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
        )))
    }
    pub fn into_canvas(self) -> FieldCanvas {
        self.0
    }
    pub fn max() -> FieldCanvas {
        FieldCanvas::from_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
    }
    pub fn declassify(self) -> BigInt {
        let a: FieldCanvas = self.into();
        a.into()
    }
    #[allow(dead_code)]
    pub fn from_hex(s: &str) -> Self {
        FieldCanvas::from_hex(s).into()
    }
    #[allow(dead_code)]
    pub fn from_be_bytes(v: &[u8]) -> Self {
        FieldCanvas::from_be_bytes(v).into()
    }
    #[allow(dead_code)]
    pub fn to_be_bytes(self) -> Vec<u8> {
        FieldCanvas::to_be_bytes(self.into()).as_ref().to_vec()
    }
    #[allow(dead_code)]
    pub fn from_le_bytes(v: &[u8]) -> Self {
        FieldCanvas::from_le_bytes(v).into()
    }
    #[allow(dead_code)]
    pub fn to_le_bytes(self) -> Vec<u8> {
        FieldCanvas::to_le_bytes(self.into()).as_ref().to_vec()
    }
    /// Gets the `i`-th least significant bit of this integer.
    #[allow(dead_code)]
    pub fn bit(self, i: usize) -> bool {
        FieldCanvas::bit(self.into(), i)
    }
    #[allow(dead_code)]
    pub fn from_literal(x: u64) -> Self {
        let big_x = BigUint::from(x);
        Ed25519FieldElement(big_x.into())
    }
    #[allow(dead_code)]
    pub fn from_signed_literal(x: i64) -> Self {
        let big_x = BigUint::from(x as u64);
        Ed25519FieldElement(big_x.into())
    }
    #[inline]
    pub fn comp_eq(self, rhs: Self) -> Self {
        let x: FieldCanvas = self.into();
        x.comp_eq(rhs.into()).into()
    }
    #[inline]
    pub fn comp_ne(self, rhs: Self) -> Self {
        let x: FieldCanvas = self.into();
        x.comp_ne(rhs.into()).into()
    }
    #[inline]
    pub fn comp_gte(self, rhs: Self) -> Self {
        let x: FieldCanvas = self.into();
        x.comp_gte(rhs.into()).into()
    }
    #[inline]
    pub fn comp_gt(self, rhs: Self) -> Self {
        let x: FieldCanvas = self.into();
        x.comp_gt(rhs.into()).into()
    }
    #[inline]
    pub fn comp_lte(self, rhs: Self) -> Self {
        let x: FieldCanvas = self.into();
        x.comp_lte(rhs.into()).into()
    }
    #[inline]
    pub fn comp_lt(self, rhs: Self) -> Self {
        let x: FieldCanvas = self.into();
        x.comp_lt(rhs.into()).into()
    }
}
impl PartialOrd for Ed25519FieldElement {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Ed25519FieldElement {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}
impl PartialEq for Ed25519FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.0.is_eq(&other.0)
    }
}
impl Eq for Ed25519FieldElement {}
impl Ed25519FieldElement {
    fn is_eq(&self, rhs: &Ed25519FieldElement) -> bool {
        self.0.is_eq(&rhs.0)
    }
    fn add_commut(x: Ed25519FieldElement, y: Ed25519FieldElement) -> bool {
        Ed25519FieldElement::add(x, y).is_eq(&(Ed25519FieldElement::add(y, x)))
    }
    fn mul_commut(x: Ed25519FieldElement, y: Ed25519FieldElement) -> bool {
        Ed25519FieldElement::mul(x, y).is_eq(&(Ed25519FieldElement::mul(y, x)))
    }
    fn add_assoc(x: Ed25519FieldElement, y: Ed25519FieldElement, z: Ed25519FieldElement) -> bool {
        let xy = Ed25519FieldElement::add(x, y);
        let yz = Ed25519FieldElement::add(y, z);
        Ed25519FieldElement::add(x, yz).is_eq(&(Ed25519FieldElement::add(xy, z)))
    }
    fn mul_assoc(x: Ed25519FieldElement, y: Ed25519FieldElement, z: Ed25519FieldElement) -> bool {
        let xy = Ed25519FieldElement::mul(x, y);
        let yz = Ed25519FieldElement::mul(y, z);
        Ed25519FieldElement::mul(x, yz).is_eq(&(Ed25519FieldElement::mul(xy, z)))
    }
    fn add_ident(x: Ed25519FieldElement) -> bool {
        Ed25519FieldElement::add(x, Ed25519FieldElement::ZERO()).is_eq(&x)
    }
    fn mul_ident(x: Ed25519FieldElement) -> bool {
        Ed25519FieldElement::mul(x, Ed25519FieldElement::ZERO()).is_eq(&x)
    }
    fn distrib(x: Ed25519FieldElement, y: Ed25519FieldElement, z: Ed25519FieldElement) -> bool {
        let xy = Ed25519FieldElement::mul(x, y);
        let xz = Ed25519FieldElement::mul(x, z);
        let yz = Ed25519FieldElement::add(y, z);
        Ed25519FieldElement::mul(x, yz).is_eq(&(Ed25519FieldElement::add(xy, xz)))
    }
    fn add(self, rhs: Ed25519FieldElement) -> Ed25519FieldElement {
        let a: FieldCanvas = self.into();
        let b: FieldCanvas = rhs.into();
        let a: BigUint = a.into();
        let b: BigUint = b.into();
        let c: BigUint = a + b;
        let max: BigUint = FieldCanvas::from_hex(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
        )
        .into();
        let d: BigUint = c % max;
        let d: FieldCanvas = d.into();
        d.into()
    }
    fn mul(self, rhs: Ed25519FieldElement) -> Ed25519FieldElement {
        let a: FieldCanvas = self.into();
        let b: FieldCanvas = rhs.into();
        let a: BigUint = a.into();
        let b: BigUint = b.into();
        let c: BigUint = a * b;
        let max: BigUint = FieldCanvas::from_hex(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
        )
        .into();
        let d: BigUint = c % max;
        let d: FieldCanvas = d.into();
        d.into()
    }
}
/// **Warning**: wraps on overflow.
impl Add for Ed25519FieldElement {
    type Output = Ed25519FieldElement;
    fn add(self, rhs: Ed25519FieldElement) -> Ed25519FieldElement {
        Ed25519FieldElement::add(self, rhs)
    }
}
/// **Warning**: wraps on underflow.
impl Sub for Ed25519FieldElement {
    type Output = Ed25519FieldElement;
    fn sub(self, rhs: Ed25519FieldElement) -> Ed25519FieldElement {
        let a: FieldCanvas = self.into();
        let b: FieldCanvas = rhs.into();
        let a: BigUint = a.into();
        let b: BigUint = b.into();
        let max: BigUint = FieldCanvas::from_hex(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
        )
        .into();
        let c: BigUint = if b > a { max.clone() - b + a } else { a - b };
        let d: BigUint = c % max;
        let d: FieldCanvas = d.into();
        d.into()
    }
}
/// **Warning**: wraps on overflow.
impl Mul for Ed25519FieldElement {
    type Output = Ed25519FieldElement;
    fn mul(self, rhs: Ed25519FieldElement) -> Ed25519FieldElement {
        Ed25519FieldElement::add(self, rhs)
    }
}
/// **Warning**: panics on division by 0.
impl Div for Ed25519FieldElement {
    type Output = Ed25519FieldElement;
    fn div(self, rhs: Ed25519FieldElement) -> Ed25519FieldElement {
        let a: FieldCanvas = self.into();
        let b: FieldCanvas = rhs.into();
        let a: BigUint = a.into();
        let b: BigUint = b.into();
        let c: BigUint = a / b;
        let max: BigUint = FieldCanvas::from_hex(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
        )
        .into();
        let d: BigUint = c % max;
        let d: FieldCanvas = d.into();
        d.into()
    }
}
/// **Warning**: panics on division by 0.
impl Rem for Ed25519FieldElement {
    type Output = Ed25519FieldElement;
    fn rem(self, rhs: Ed25519FieldElement) -> Ed25519FieldElement {
        let a: FieldCanvas = self.into();
        let b: FieldCanvas = rhs.into();
        let a: BigUint = a.into();
        let b: BigUint = b.into();
        let c: BigUint = a % b;
        let max: BigUint = FieldCanvas::from_hex(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
        )
        .into();
        let d: BigUint = c % max;
        let d: FieldCanvas = d.into();
        d.into()
    }
}
impl Not for Ed25519FieldElement {
    type Output = Ed25519FieldElement;
    fn not(self) -> Self::Output {
        let a: FieldCanvas = self.into();
        (!a).into()
    }
}
impl BitOr for Ed25519FieldElement {
    type Output = Ed25519FieldElement;
    fn bitor(self, rhs: Self) -> Self::Output {
        let a: FieldCanvas = self.into();
        let b: FieldCanvas = rhs.into();
        (a | b).into()
    }
}
impl BitXor for Ed25519FieldElement {
    type Output = Ed25519FieldElement;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let a: FieldCanvas = self.into();
        let b: FieldCanvas = rhs.into();
        (a ^ b).into()
    }
}
impl BitAnd for Ed25519FieldElement {
    type Output = Ed25519FieldElement;
    fn bitand(self, rhs: Self) -> Self::Output {
        let a: FieldCanvas = self.into();
        let b: FieldCanvas = rhs.into();
        (a & b).into()
    }
}
impl Shr<usize> for Ed25519FieldElement {
    type Output = Ed25519FieldElement;
    fn shr(self, rhs: usize) -> Self::Output {
        let a: FieldCanvas = self.into();
        (a >> rhs).into()
    }
}
impl Shl<usize> for Ed25519FieldElement {
    type Output = Ed25519FieldElement;
    fn shl(self, rhs: usize) -> Self::Output {
        let a: FieldCanvas = self.into();
        (a << rhs).into()
    }
}
impl Ed25519FieldElement {
    #[allow(dead_code)]
    pub fn inv(self) -> Self {
        let base: FieldCanvas = self.into();
        base.inv(Self::max()).into()
    }
    #[allow(dead_code)]
    pub fn pow_felem(self, exp: Self) -> Self {
        let base: FieldCanvas = self.into();
        base.pow_felem(exp.into(), Self::max()).into()
    }
    /// Returns self to the power of the argument.
    /// The exponent is a u128.
    #[allow(dead_code)]
    pub fn pow(self, exp: u64) -> Self {
        let base: FieldCanvas = self.into();
        base.pow(exp, Self::max()).into()
    }
    /// Returns 2 to the power of the argument
    #[allow(dead_code)]
    pub fn pow2(x: usize) -> Ed25519FieldElement {
        FieldCanvas::pow2(x).into()
    }
}
impl Ed25519FieldElement {
    pub fn from_byte_seq_be<A: SeqTrait<U8>>(s: &A) -> Ed25519FieldElement {
        let mut temp = Vec::new();
        let len = s.len();
        let mut i = 0;
        while i < len {
            temp.push(U8::declassify(s[i]));
            i += 1;
        }
        FieldCanvas::from_be_bytes(temp.as_slice()).into()
    }
    pub fn from_public_byte_seq_be<A: SeqTrait<u8>>(s: A) -> Ed25519FieldElement {
        let mut temp = Vec::new();
        let len = s.len();
        let mut i = 0;
        while i < len {
            temp.push(s[i]);
            i += 1;
        }
        FieldCanvas::from_be_bytes(temp.as_slice()).into()
    }
    pub fn to_byte_seq_be(self) -> hacspec_lib::Seq<U8> {
        let mut temp = Vec::new();
        let len = self.to_be_bytes().len();
        let mut i = 0;
        while i < len {
            temp.push(U8::classify(self.to_be_bytes()[i]));
            i += 1;
        }
        hacspec_lib::Seq::from_vec(temp)
    }
    pub fn to_public_byte_seq_be(self) -> hacspec_lib::Seq<u8> {
        hacspec_lib::Seq::from_vec(self.to_be_bytes())
    }
    pub fn from_byte_seq_le<A: SeqTrait<U8>>(s: A) -> Ed25519FieldElement {
        let mut temp = Vec::new();
        let len = s.len();
        let mut i = 0;
        while i < len {
            temp.push(U8::declassify(s[i]));
            i += 1;
        }
        FieldCanvas::from_le_bytes(temp.as_slice()).into()
    }
    pub fn from_public_byte_seq_le<A: SeqTrait<u8>>(s: A) -> Ed25519FieldElement {
        let mut temp = Vec::new();
        let len = s.len();
        let mut i = 0;
        while i < len {
            temp.push(s[i]);
            i += 1;
        }
        FieldCanvas::from_le_bytes(temp.as_slice()).into()
    }
    pub fn to_byte_seq_le(self) -> hacspec_lib::Seq<U8> {
        let mut temp = Vec::new();
        let len = self.to_le_bytes().len();
        let mut i = 0;
        while i < len {
            temp.push(U8::classify(self.to_le_bytes()[i]));
            i += 1;
        }
        hacspec_lib::Seq::from_vec(temp)
    }
    pub fn to_public_byte_seq_le(self) -> hacspec_lib::Seq<u8> {
        hacspec_lib::Seq::from_vec(self.to_le_bytes())
    }
    pub fn from_secret_literal(x: U64) -> Ed25519FieldElement {
        FieldCanvas::from_literal(U64::declassify(x)).into()
    }
}
impl NumericCopy for Ed25519FieldElement {}
impl UnsignedInteger for Ed25519FieldElement {}
impl UnsignedIntegerCopy for Ed25519FieldElement {}
impl Integer for Ed25519FieldElement {
    fn NUM_BITS() -> usize {
        256
    }
    #[inline]
    fn ZERO() -> Self {
        Self::from_literal(0)
    }
    #[inline]
    fn ONE() -> Self {
        Self::from_literal(1)
    }
    #[inline]
    fn TWO() -> Self {
        Self::from_literal(2)
    }
    #[inline]
    fn from_literal(val: u64) -> Self {
        Self::from_literal(val)
    }
    #[inline]
    fn from_hex_string(s: &String) -> Self {
        Self::from_hex(&s.replace("0x", ""))
    }
    /// Get bit `i` of this integer.
    #[inline]
    fn get_bit(self, i: usize) -> Self {
        (self >> i) & Self::ONE()
    }
    /// Set bit `i` of this integer to `b` and return the result.
    /// Bit `b` has to be `0` or `1`.
    #[inline]
    fn set_bit(self, b: Self, i: usize) -> Self {
        if true {
            if !(b.clone().equal(Self::ONE()) || b.clone().equal(Self::ZERO())) {
                :: core :: panicking :: panic ("assertion failed: b.clone().equal(Self::ONE()) || b.clone().equal(Self::ZERO())")
            };
        };
        let tmp1 = Self::from_literal(!(1 << i));
        let tmp2 = b << i;
        (self & tmp1) | tmp2
    }
    /// Set bit `pos` of this integer to bit `yi` of integer `y`.
    #[inline]
    fn set(self, pos: usize, y: Self, yi: usize) -> Self {
        let b = y.get_bit(yi);
        self.set_bit(b, pos)
    }
    fn rotate_left(self, n: usize) -> Self {
        if !(n < Self::NUM_BITS()) {
            ::core::panicking::panic("assertion failed: n < Self::NUM_BITS()")
        };
        (self.clone() << n) | (self >> ((-(n as i32) as usize) & (Self::NUM_BITS() - 1)))
    }
    fn rotate_right(self, n: usize) -> Self {
        if !(n < Self::NUM_BITS()) {
            ::core::panicking::panic("assertion failed: n < Self::NUM_BITS()")
        };
        (self.clone() >> n) | (self << ((-(n as i32) as usize) & (Self::NUM_BITS() - 1)))
    }
}
impl ModNumeric for Ed25519FieldElement {
    /// (self - rhs) % n.
    fn sub_mod(self, rhs: Self, n: Self) -> Self {
        self - rhs
    }
    /// `(self + rhs) % n`
    fn add_mod(self, rhs: Self, n: Self) -> Self {
        self + rhs
    }
    /// `(self * rhs) % n`
    fn mul_mod(self, rhs: Self, n: Self) -> Self {
        self * rhs
    }
    /// `(self ^ exp) % n`
    fn pow_mod(self, exp: Self, n: Self) -> Self {
        self.pow_felem(exp)
    }
    /// `self % n`
    fn modulo(self, n: Self) -> Self {
        self % n
    }
    /// `self % n` that always returns a positive integer
    fn signed_modulo(self, n: Self) -> Self {
        self.modulo(n)
    }
    /// `|self|`
    fn absolute(self) -> Self {
        self
    }
}
impl Numeric for Ed25519FieldElement {
    /// Return largest value that can be represented.
    fn max_val() -> Self {
        (Self::max() - FieldCanvas::from_literal(1)).into()
    }
    fn wrap_add(self, rhs: Self) -> Self {
        self + rhs
    }
    fn wrap_sub(self, rhs: Self) -> Self {
        self - rhs
    }
    fn wrap_mul(self, rhs: Self) -> Self {
        self * rhs
    }
    fn wrap_div(self, rhs: Self) -> Self {
        self / rhs
    }
    /// `self ^ exp` where `exp` is a `u32`.
    fn exp(self, exp: u32) -> Self {
        self.pow(exp.into())
    }
    /// `self ^ exp` where `exp` is a `Self`.
    fn pow_self(self, exp: Self) -> Self {
        self.pow_felem(exp)
    }
    /// Division.
    fn divide(self, rhs: Self) -> Self {
        self / rhs
    }
    /// Invert self modulo n.
    /// **NOTE:** `n` is ignored and inversion is done with respect to
    ///            the modulus.
    fn inv(self, n: Self) -> Self {
        self.inv()
    }
    fn equal(self, other: Self) -> bool {
        self.equal(other)
    }
    fn greater_than(self, other: Self) -> bool {
        self > other
    }
    fn greater_than_or_qual(self, other: Self) -> bool {
        self >= other
    }
    fn less_than(self, other: Self) -> bool {
        self < other
    }
    fn less_than_or_equal(self, other: Self) -> bool {
        self <= other
    }
    fn not_equal_bm(self, other: Self) -> Self {
        if self != other {
            (Self::ONE() << (256 - 1)) - Self::ONE()
        } else {
            Self::ZERO()
        }
    }
    fn equal_bm(self, other: Self) -> Self {
        if self.equal(other) {
            (Self::ONE() << (256 - 1)) - Self::ONE()
        } else {
            Self::ZERO()
        }
    }
    fn greater_than_bm(self, other: Self) -> Self {
        if self > other {
            (Self::ONE() << (256 - 1)) - Self::ONE()
        } else {
            Self::ZERO()
        }
    }
    fn greater_than_or_equal_bm(self, other: Self) -> Self {
        if self >= other {
            (Self::ONE() << (256 - 1)) - Self::ONE()
        } else {
            Self::ZERO()
        }
    }
    fn less_than_bm(self, other: Self) -> Self {
        if self < other {
            (Self::ONE() << (256 - 1)) - Self::ONE()
        } else {
            Self::ZERO()
        }
    }
    fn less_than_or_equal_bm(self, other: Self) -> Self {
        if self <= other {
            (Self::ONE() << (256 - 1)) - Self::ONE()
        } else {
            Self::ZERO()
        }
    }
}
pub fn sqrt(a: Ed25519FieldElement) -> Option<Ed25519FieldElement> {
    let p3_8 = Ed25519FieldElement::from_hex(
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
    );
    let p1_4 = Ed25519FieldElement::from_hex(
        "0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb",
    );
    let x_c = a.pow_self(p3_8);
    let mut result: Option<Ed25519FieldElement> = Option::<Ed25519FieldElement>::None;
    if (x_c * x_c).is_eq(&a) {
        result = Some(x_c);
    };
    if (x_c * x_c).is_eq(&(Ed25519FieldElement::ZERO() - a)) {
        let x = Ed25519FieldElement::TWO().pow_self(p1_4) * x_c;
        result = Some(x);
    }
    result
}
fn cmov(a: Ed25519FieldElement, b: Ed25519FieldElement, c: bool) -> Ed25519FieldElement {
    if c {
        b
    } else {
        a
    }
}
pub fn monty_to_edw(
    s: Ed25519FieldElement,
    t: Ed25519FieldElement,
) -> (Ed25519FieldElement, Ed25519FieldElement) {
    let one = Ed25519FieldElement::ONE();
    let zero = Ed25519FieldElement::ZERO();
    let tv1 = s + one;
    let tv2 = tv1 * t;
    let tv2 = tv2.inv();
    let v = tv2 * tv1;
    let v = v * s;
    let w = tv2 * t;
    let tv1 = s - one;
    let w = w * tv1;
    let e = tv2.is_eq(&zero);
    let w = cmov(w, one, e);
    let funnum = zero - Ed25519FieldElement::from_literal(486664);
    let sq = sqrt(funnum);
    let v = v * sq.unwrap();
    (v, w)
}
