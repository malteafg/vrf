#[cfg(not(feature = "hacspec"))]
extern crate hacspec_lib;

#[cfg(feature = "hacspec")]
use hacspec_attributes::*;

#[cfg(not(feature = "hacspec"))]
extern crate creusot_contracts;
#[cfg(not(feature = "hacspec"))]
pub use creusot_contracts::*;
pub use creusot_contracts::ensures;

pub use hacspec_lib::*;
pub use hacspec_lib::Seq;

// bytes!(SerializedScalar, 32);

// #[rustfmt::skip]
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

// pub type EdPoint = (
//     Ed25519FieldElement,
//     Ed25519FieldElement,
//     Ed25519FieldElement,
//     Ed25519FieldElement,
// );

// #[ensures(result == 42u32)]
// fn the_answer() -> u32 {
//     return 42u32
// }

// #[ensures(if c {result === b} else {result === a})]
// fn cmov(
//     a: Ed25519FieldElement, b: Ed25519FieldElement, c: bool
// ) -> Ed25519FieldElement {
//     if c {
//         b
//     } else {
//         a
//     }
// }

// pub fn sqrt(a: Ed25519FieldElement) -> Option<Ed25519FieldElement> {
//     #[rustfmt::skip]
//     let CONSTANT_P3_8: SerializedScalar = SerializedScalar(secret_array!(
//         U8, 
//         [
//             0xfeu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//             0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//             0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//             0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0x0fu8 
//         ]
//     ));

//     #[rustfmt::skip]
//     let CONSTANT_P1_4: SerializedScalar = SerializedScalar(secret_array!(
//         U8, 
//         [
//             0xfbu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//             0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//             0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 
//             0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0xffu8, 0x1fu8 
//         ]
//     ));

//     let p3_8 = Ed25519FieldElement::from_byte_seq_le(CONSTANT_P3_8);
//     let p1_4 = Ed25519FieldElement::from_byte_seq_le(CONSTANT_P1_4);

//     let x_c = a.pow_self(p3_8);
//     let mut result: Option<Ed25519FieldElement> = Option::<Ed25519FieldElement>::None;
//     if x_c * x_c == a {
//         result = Some(x_c);
//     };
//     if x_c * x_c == Ed25519FieldElement::ZERO() - a {
//         let x = Ed25519FieldElement::TWO().pow_self(p1_4) * x_c;
//         result = Some(x);
//     }
//     result
// }

// pub fn normalize(p: EdPoint) -> EdPoint {
//     let px = p.0 * p.2.inv();
//     let py = p.1 * p.2.inv();
//     let pz = Ed25519FieldElement::ONE();
//     let pt = px * py;
//     (px, py, pz, pt)
// }

// // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#appendix-D.1-13
// pub fn monty_to_edw(p: EdPoint) -> EdPoint {
//     let (s, t, _, _) = normalize(p);
//     let one = Ed25519FieldElement::ONE();
//     let zero = Ed25519FieldElement::ZERO();

//     let tv1 = s + one;
//     let tv2 = tv1 * t;
//     let tv2 = tv2.inv();
//     let v = tv2 * tv1;
//     let v = v * s;
//     let w = tv2 * t;
//     let tv1 = s - one;
//     let w = w * tv1;
//     let e = tv2 == zero;
//     let w = cmov(w, one, e);
//     let funnum = zero - Ed25519FieldElement::from_literal(486664);
//     let sq = sqrt(funnum);
//     let v = v * sq.unwrap();
    
//     (v, w, one, v * w)
// }

// // does not convert the identity point
// // NOTE: takes an EdPoint even though it converts a Curve25519 point
// fn fake_monty_to_edw(p: EdPoint) -> EdPoint {
//     let (s, t, _, _) = normalize(p);
//     let tinv = t.pow_self(Ed25519FieldElement::from_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb"));
//     let one = Ed25519FieldElement::ONE();
//     let funnum = Ed25519FieldElement::ZERO() - Ed25519FieldElement::from_literal(486664);
//     let sq = sqrt(funnum);

//     let v = (s * tinv) * sq.unwrap();
//     let w = (s - one) * (s + one).inv();

//     (v, w, one, v * w)
// }
