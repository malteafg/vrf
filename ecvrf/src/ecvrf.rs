use hacspec_lib::*;
use hacspec_ed25519::*;
use hacspec_sha512::*;
use ed25519_hash::*;

pub enum Error {
    InvalidLength,
    MessageTooLarge,
    InvalidProof,
    InvalidPublicKey,
    FailedDecompression,
}

pub type ByteSeqResult = Result<ByteSeq, Error>;
pub type ProofResult = Result<(EdPoint, Scalar, Scalar), Error>;
// TODO a bit weird to use a bool result
pub type BoolResult = Result<bool, Error>;

// These three are defined by the ECVRF-EDWARDS25519-SHA512-TAI suite
const C_LEN: usize = 16usize;
const PT_LEN: usize = 32usize;
const Q_LEN: usize = 32usize;
const SUITE_INT: usize = 4usize;
    
// ECVRF =======================================================================

// We use ciphersuite 4 so encode_to_curve_salt is part of the ciphersuite
pub fn ecvrf_prove(
    sk: SecretKey, alpha: &ByteSeq
) -> ByteSeqResult {
    let base = decompress(BASE).ok_or(Error::FailedDecompression)?;
    
    // TODO use better secret_expand function?
    // STEP 1
    let (x, _) = secret_expand(sk);
    let x = Scalar::from_byte_seq_le(x);
    let pk = decompress(secret_to_public(sk)).ok_or(Error::InvalidPublicKey)?;

    // STEP 2
    let encode_to_curve_salt = compress(pk).slice(0,32);
    let h = ecvrf_encode_to_curve_h2c_suite(&encode_to_curve_salt, alpha);

    // STEP 3
    let h_string = compress(h).slice(0,32);

    // STEP 4
    let gamma = point_mul(x, h);

    // STEP 5
    let k = ecvrf_nonce_generation(sk, &h_string);

    // STEP 6
    let c = ecvrf_challenge_generation(
        pk, h, gamma, point_mul(k, base), 
        point_mul(k, h));

    // STEP 7
    let s = k + c * x;

    // STEP 8 and 9
    ByteSeqResult::Ok(compress(gamma)
        .concat(&Scalar::to_byte_seq_le(c).slice(0, C_LEN))
        .concat(&Scalar::to_byte_seq_le(s).slice(0, Q_LEN)).slice(0,32))
}

pub fn ecvrf_proof_to_hash(pi: &ByteSeq) -> ByteSeqResult {
    // STEP 1, 2 and 3
    let (gamma, _, _) = ecvrf_decode_proof(pi)?;

    // STEP 4 + 5
    let proof_to_hash_domain_separator_front = ByteSeq::new(3);
    let proof_to_hash_domain_separator_back = ByteSeq::new(0);

    // STEP 6
    let suite_string = ByteSeq::new(SUITE_INT);
    ByteSeqResult::Ok(sha512(&suite_string
        .concat(&proof_to_hash_domain_separator_front)
        .concat(&compress(point_mul_by_cofactor(gamma)).slice(0,32))
        // slice because sha512 returns digest instead of byteseq
        .concat(&proof_to_hash_domain_separator_back)).slice(0,64))
}

// We use ciphersuite 4 so encode_to_curve_salt is part of the ciphersuite
pub fn ecvrf_verify(
    pk: PublicKey, alpha: &ByteSeq, pi: &ByteSeq, validate_key: bool
) -> ByteSeqResult {
    let base = decompress(BASE).ok_or(Error::FailedDecompression)?;

    // STEP 1 and 2
    let y = decompress(pk).ok_or(Error::InvalidPublicKey)?;
    
    // STEP 3
    if validate_key {
        ecvrf_validate_key(pk)?;
    } 

    // STEP 4, 5 and 6
    let (gamma, c, s) = ecvrf_decode_proof(pi)?;

    // STEP 7
    let encode_to_curve_salt = compress(y).slice(0,32);
    let h = ecvrf_encode_to_curve_h2c_suite(&encode_to_curve_salt, alpha);

    // STEP 8
    let u = point_add(point_mul(s, base), point_neg(point_mul(c,y)));

    // STEP 9
    let v = point_add(point_mul(s, h), point_neg(point_mul(c,gamma)));

    // STEP 10
    let c_prime = ecvrf_challenge_generation(y, h, gamma, u, v);
    
    // STEP 11
    if c == c_prime {
        ecvrf_proof_to_hash(pi)
    } else {
        ByteSeqResult::Err(Error::InvalidLength)
    }
}

// AUXILLIARY FUNCTIONS ========================================================
// Note that section 5.5 also uses a point_to_string function.

// See section 5.4.1
// For ciphersuite 3
// Note that this should not be used when alpha should remain secret
// Panics occasionally with very low probability
// Not in hacspec
// fn ecvrf_encode_to_curve_try_and_increment(
//     encode_to_curve_salt: &ByteSeq, alpha: &ByteSeq
// ) -> EdPoint {
//     let encode_to_curve_domain_separator_front = ByteSeq::new(1);
//     let encode_to_curve_domain_separator_back = ByteSeq::new(0);

//     let mut h: Option<EdPoint> = None;

//     // TODO can we have while loops in hacspec?
//     for ctr in 1..256 {
//         if h == None {
//             let ctr_string = ByteSeq::new(ctr);
//             let suite_string = ByteSeq::new(SUITE_INT);
//             let hash_string = sha512(&suite_string
//                 .concat(&encode_to_curve_domain_separator_front)
//                 .concat(encode_to_curve_salt)
//                 .concat(alpha)
//                 .concat(&ctr_string)
//                 .concat(&encode_to_curve_domain_separator_back));
//             // TODO do not use decode, slice somehow instead
//             h = decode(hash_string.slice(0,64));
//         }
//     }
//     let h = h.unwrap();
//     point_mul_by_cofactor(h)
// }

// See section 5.4.1.2
fn ecvrf_encode_to_curve_h2c_suite(
    encode_to_curve_salt: &ByteSeq, alpha: &ByteSeq
) -> EdPoint {
    let string_to_be_hashed = encode_to_curve_salt.concat(alpha);
    let suite_string = ByteSeq::new(SUITE_INT);
    // TODO Faked, fix later:
    let dst = suite_string;
    ed_hash_to_curve(&string_to_be_hashed, &dst)
}

// See section 5.4.2
// See RFC6979, section 3.2
// See RFC8032, section 5.1.6
// Both implementations should probably be available
// 
// This implements 5.1.6 of RFC8032
fn ecvrf_nonce_generation(sk: SecretKey, h_string: &ByteSeq) -> Scalar {
    let hashed_sk_string = sha512(&sk.to_le_bytes());
    let truncated_hashed_sk_string = hashed_sk_string.slice(32,32);
    let k_string = sha512(&truncated_hashed_sk_string.concat(h_string));
    
    // TODO check is this the correct q value?
    Scalar::from_byte_seq_le(k_string)
}

// See section 5.4.3
fn ecvrf_challenge_generation(
    p1: EdPoint, p2: EdPoint, p3: EdPoint, p4: EdPoint, p5: EdPoint
) -> Scalar {
    let challenge_generation_domain_separator_front = ByteSeq::new(2);
    let challenge_generation_domain_separator_back = ByteSeq::new(0);
    let suite_string = ByteSeq::new(SUITE_INT);
    let string = suite_string
        .concat(&challenge_generation_domain_separator_front)
        .concat(&compress(p1).slice(0,32))
        .concat(&compress(p2).slice(0,32))
        .concat(&compress(p3).slice(0,32))
        .concat(&compress(p4).slice(0,32))
        .concat(&compress(p5).slice(0,32))
        .concat(&challenge_generation_domain_separator_back);
    let c_string = sha512(&string);
    let truncated_c_string = c_string.slice(0, C_LEN-1);
    Scalar::from_byte_seq_le(truncated_c_string)
}

// See section 5.4.4
fn ecvrf_decode_proof(pi: &ByteSeq) -> ProofResult {
    let gamma_string = pi.slice(0, PT_LEN);
    let c_string = pi.slice(PT_LEN, C_LEN);
    let s_string = pi.slice(PT_LEN + C_LEN, Q_LEN);
    let gamma = decompress(CompressedEdPoint::from_slice(&gamma_string, 0, 32));
    
    let gamma = gamma.ok_or(Error::InvalidProof)?;

    let c = Scalar::from_byte_seq_le(c_string);
    let s = Scalar::from_byte_seq_le(s_string);
    // TODO check if s (before mod q) is bigger than q

    ProofResult::Ok((gamma, c, s))
}

// See section 5.4.5
fn ecvrf_validate_key(y: PublicKey) -> BoolResult {
    let y = decompress(y).ok_or(Error::InvalidPublicKey)?;
    let y_prime = point_mul_by_cofactor(y);
    if is_identity(y_prime) {
        BoolResult::Err(Error::InvalidPublicKey)
    } else {
        BoolResult::Ok(true)
    }
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