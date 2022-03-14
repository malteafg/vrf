use hacspec_lib::*;
use hacspec_ed25519::*;
use hacspec_sha512::*;

pub enum Error {
    InvalidLength,
    MessageTooLarge,
    InvalidProof,
}

pub type ByteSeqResult = Result<ByteSeq, Error>;

// ECVRF =======================================================================

pub fn ecvrf_prove(
    sk: SecretKey, alpha: &ByteSeq, encode_to_curve_salt: Option<ByteSeq>
) -> ByteSeq {
    ByteSeq::new(0)
}

pub fn ecvrf_proof_to_hash(pi: &ByteSeq) -> ByteSeqResult {
    Ok(ByteSeq::new(0))
}

pub fn ecvrf_verify(
    pk: PublicKey, alpha: &ByteSeq, pi: &ByteSeq, 
    encode_to_curve_salt: Option<ByteSeq>, validate_key: Option<ByteSeq>
) -> ByteSeqResult {
    Ok(ByteSeq::new(0))
}

// AUXILLIARY FUNCTIONS ========================================================
// Note that section 5.5 also uses a point_to_string function.

// See section 5.4.1
// Note that this should not be used when alpha should remain secret
fn ecvrf_encode_to_curve(
    encode_to_curve_salt: &ByteSeq, alpha: &ByteSeq
) -> EdPoint {
    let ctr = 0;
    let encode_to_curve_domain_separator_front = ByteSeq::new(1);
    let encode_to_curve_domain_separator_back = ByteSeq::new(0);

    for i in 1..256 {
        let ctr_string = ByteSeq::new(i);
        let suite_string = ByteSeq::new(3);
        let hash_string = sha512(&suite_string
            .concat(&encode_to_curve_domain_separator_front)
            .concat(encode_to_curve_salt)
            .concat(alpha)
            .concat(&ctr_string)
            .concat(&encode_to_curve_domain_separator_back));
        // let h = decompress(&hash_string);
        
    }
    panic!()
}

// See section 5.4.2
// See RFC6979, section 3.2
// See RFC8032, section 5.1.6
// Both implementations should probably be available
// 
// This implements 5.1.6 of RFC8032
// TODO BigScalar or Scalar?
fn ecvrf_nonce_generation(sk: SecretKey, h_string: &ByteSeq) -> BigScalar {
    let hashed_sk_string = sha512(&sk.to_le_bytes());
    let truncated_hashed_sk_string = hashed_sk_string.slice(32,32);
    let k_string = sha512(&truncated_hashed_sk_string.concat(h_string));
    
    // TODO check is this the correct q value?
    BigScalar::from_byte_seq_le(k_string)
}

// See section 5.4.3
// cLen defined as 16 by ciphersuite
// TODO Can we use compressedEdPoint?
// TODO can we just use BigScalar?
fn ecvrf_challenge_generation(
    p1: CompressedEdPoint, p2: CompressedEdPoint, p3: CompressedEdPoint,
    p4: CompressedEdPoint, p5: CompressedEdPoint
) -> BigScalar {
    let challenge_generation_domain_separator_front = ByteSeq::new(2);
    let challenge_generation_domain_separator_back = ByteSeq::new(0);
    let suite_string = ByteSeq::new(3);
    let string = suite_string
        .concat(&challenge_generation_domain_separator_front)
        .concat(&p1.to_le_bytes())
        .concat(&p2.to_le_bytes())
        .concat(&p3.to_le_bytes())
        .concat(&p4.to_le_bytes())
        .concat(&p5.to_le_bytes())
        .concat(&challenge_generation_domain_separator_back);
    let c_string = sha512(&string);
    let truncated_c_string = c_string.slice(0,15);
    BigScalar::from_byte_seq_le(truncated_c_string)
}

// See section 5.4.4
// u64 is placeholder for result of curvepoint
// TODO how to string_to_point?
fn ecvrf_decode_proof(pi: &ByteSeq) -> (u64, u128, u128) {
    (0, 0, 0)
}

// See section 5.4.5
// y is a public key ie a point on the curve
fn ecvrf_validate_key(y: PublicKey) -> bool {
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