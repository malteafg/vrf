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
    let p1 = q.encode(true);
    let p1 = ByteSeq::from_public_slice(&p1);
    let p1 = decode(p1).unwrap();

    // compute our implementation point
    let p2: EdPoint = ed_encode_to_curve(
        &ByteSeq::from_public_slice(msg),
        &ByteSeq::from_public_slice(dst),
    );

    // normalize
    let px = p2.0 * p2.2.inv();
    let py = p2.1 * p2.2.inv();
    let pz = Ed25519FieldElement::ONE();
    let pt = px * py;
    let p2 = (px, py, pz, pt);

    p1 == p2
}
