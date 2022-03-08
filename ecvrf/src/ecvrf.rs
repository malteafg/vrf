use hacspec_lib::*;

pub enum Error {
    InvalidLength,
    MessageTooLarge,
    InvalidProof,
}

pub type ByteSeqResult = Result<ByteSeq, Error>;

// ECVRF =======================================================================

pub fn ecvrf_prove(sk: ByteSeq, alpha: &ByteSeq, 
    encode_to_curve_salt: Option<ByteSeq>) -> ByteSeq {
    ByteSeq::new(0)
}

pub fn ecvrf_proof_to_hash(pi: &ByteSeq) -> ByteSeqResult {
    Ok(ByteSeq::new(0))
}

pub fn ecvrf_verify(pk: ByteSeq, alpha: &ByteSeq, pi: &ByteSeq,
    encode_to_curve_salt: Option<ByteSeq>, validate_key: Option<ByteSeq>,
    ) -> ByteSeqResult {
    Ok(ByteSeq::new(0))
}

// AUXILLIARY FUNCTIONS ========================================================
// Note that section 5.5 also uses a point_to_string function.

// See section 5.4.1
// u32 is placeholder for curve point
fn ecvrf_encode_to_curve(encode_to_curve_salt: &ByteSeq, alpha: &ByteSeq) 
    -> u32 {
    0
}

// See section 5.4.2
// See RFC6979, section 3.2
// See RFC8032, section 5.1.6
// Both implementations should probably be available
fn ecvrf_nonce_generation(sk: ByteSeq, h_string: &ByteSeq) -> u128 {
    0
}

// See section 5.4.3
// u32 is placeholder for curve point
fn ecvrf_challenge_generation(p1: u32, p2: u32, p3: u32, p4: u32, p5: u32) 
    -> u128 {
        0
}

// See section 5.4.4
// u64 is placeholder for result of curvepoint
fn ecvrf_decode_proof(pi: &ByteSeq) -> (u64, u128, u128) {
    (0, 0, 0)
}

// See section 5.4.5
// y is a public key ie a point on the curve
fn ecvrf_validate_key(y: u32) -> bool {
    false
}

// TESTING =====================================================================

#[cfg(test)]
extern crate quickcheck;

#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[cfg(test)]
use quickcheck::*;

#[cfg(test)]
mod tests {
    use super::*;

}