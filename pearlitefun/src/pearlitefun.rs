#[cfg(not(feature = "hacspec"))]
extern crate hacspec_lib;

#[cfg(feature = "hacspec")]
use hacspec_attributes::*;

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

// bytes!(SerializedScalar, 32);

// #[rustfmt::skip]
// (p+3)/8
// const CONSTANT_P3_8: SerializedScalar = SerializedScalar(secret_array!(
//     U8, 
//     [
//         0xfeu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//         0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//         0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//         0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0x0fu8 
//     ]
// ));

// #[rustfmt::skip]
// (p-1)/4
// const CONSTANT_P1_4: SerializedScalar = SerializedScalar(secret_array!(
//     U8, 
//     [
//         0xfbu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//         0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//         0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//         0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0x1fu8 
//     ]
// ));

public_nat_mod!(
    type_name: Ed25519FieldElement,
    type_of_canvas: FieldCanvas,
    bit_size_of_field: 256,
    modulo_value: "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
);

// not possible in creusot
// pub fn P3_8() -> SerializedScalar {
//     SerializedScalar(secret_array!(
//         U8, 
//         [
//             0xfeu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//             0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//             0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//             0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0x0fu8 
//         ]
//     ))
// }

// #[trusted]
// fn mul(y:Int, x:Int) -> Int {
//     y * x
// }

// #[logic]
// #[trusted]
// fn sqr(x: creusot_contracts::Int) -> creusot_contracts::Int { mul(x, x) }

pub fn sqrt(a: Ed25519FieldElement) -> Option<Ed25519FieldElement> {
    let p3_8 = Ed25519FieldElement::from_hex("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
    let p1_4 = Ed25519FieldElement::from_hex("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb");

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

#[predicate]
fn sum_one(a: u32, b: u32) -> bool {
    a + b == b
}

#[ensures(sum_one(a,b))]
fn cmov_u32(
    a: u32, b: u32, c: bool
) -> u32 {
    if c {
        b
    } else {
        a
    }
}

// #[predicate]
// fn sum_one_hac(a: Ed25519FieldElement, b: Ed25519FieldElement) -> bool {
//     a + b > b
// }

// #[predicate]
// fn sum_one_hac(a: Ed25519FieldElement, b: Ed25519FieldElement) -> bool {
//     a + b == b
// }

// #[ensures(sum_one_hac(a,b))]
#[ensures(if c {result == b} else {result == a})]
fn cmov(
    a: Ed25519FieldElement, b: Ed25519FieldElement, c: bool
) -> Ed25519FieldElement {
    if c {
        b
    } else {
        a
    }
}

// #[trusted]
// fn sum_one_hactrust(a: Ed25519FieldElement, b: Ed25519FieldElement) -> bool {
//     a + b == b
// }

// #[ensures(sum_one_hactrust(s, t))]
pub fn monty_to_edw(
    s: Ed25519FieldElement, t: Ed25519FieldElement
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
