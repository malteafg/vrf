use hacspec_lib::*;
use ed25519_hash::*;
use hacspec_ed25519::*;

use h2c_rust_ref::{GetHashToCurve, SUITES_EDWARDS};
use redox_ecc::ellipticcurve::Encode;

extern crate quickcheck;
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[quickcheck]
// #[ignore]
fn test_equiv_armfazh(msg: String) -> bool {
    let dst = b"QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_NU_";
    let msg: &[u8] = msg.as_bytes();
    let suite = SUITES_EDWARDS["edwards25519_XMD:SHA-512_ELL2_NU_"].get(dst);
    let mut q = suite.hash(msg);
    q.normalize(); // make q into p

    // convert to hacspec ed point
    let parmfazh = q.encode(true);
    let parmfazh = ByteSeq::from_public_slice(&parmfazh);
    let parmfazh = decode(parmfazh).unwrap();

    let u = ed_hash_to_field(
        &ByteSeq::from_public_slice(msg),
        &ByteSeq::from_public_slice(dst),
        1
    );

    // compute normal
    let st = map_to_curve_elligator2(u[0]);
    let q = monty_to_edw(st);
    let pnormal = ed_clear_cofactor(q);
    let pnormal = normalize(pnormal);

    // compute straight
    let st = map_to_curve_elligator2_straight(u[0]);
    let q = monty_to_edw(st);
    let pstraight = ed_clear_cofactor(q);
    let pstraight = normalize(pstraight);

    // compute optimized
    let q = map_to_curve_elligator2_edwards25519(u[0]);
    let poptim = ed_clear_cofactor(q);
    let poptim = normalize(poptim);

    // normalize
    (parmfazh == poptim) & 
    (parmfazh == pstraight) & 
    (parmfazh == pnormal) &
    (pstraight == pnormal) &
    (pstraight == poptim) &
    (pnormal == poptim)
}
