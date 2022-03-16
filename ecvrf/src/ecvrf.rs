use hacspec_lib::*;
use hacspec_ed25519::*;
use hacspec_sha512::*;
use ed25519_hash::*;

pub enum Error {
    InvalidLength,
    MessageTooLarge,
    InvalidProof,
    InvalidPublicKey,
}

pub type ByteSeqResult = Result<ByteSeq, Error>;

// These three are defined by the ECVRF-EDWARDS25519-SHA512-TAI suite
const C_LEN: usize = 16usize;
const PT_LEN: usize = 32usize;
const Q_LEN: usize = 32usize;
const SUITE_INT: usize = 3usize;
    
// ECVRF =======================================================================

// TODO check if encode_to_curve_salt should be parameterized
pub fn ecvrf_prove(
    sk: SecretKey, alpha: &ByteSeq
) -> ByteSeq {
    let base = decompress(BASE).unwrap();
    
    // TODO use better secret_expand function?
    // STEP 1
    let (x, _) = secret_expand(sk);
    let x = Scalar::from_byte_seq_le(x);
    let pk = secret_to_public(sk);

    // STEP 2
    let encode_to_curve_salt = secret_to_public_string(sk);
    let h = ecvrf_encode_to_curve_try_and_increment(
        &encode_to_curve_salt, alpha);

    // STEP 3
    let h_string = encode(h);

    // STEP 4
    let gamma = point_mul(x, h);

    // STEP 5
    let k = ecvrf_nonce_generation(sk, &h_string);

    // STEP 6
    // TODO fix decompress such that it does not panic
    let c = ecvrf_challenge_generation(
        decompress(pk).unwrap(), h, gamma, point_mul(k, base), 
        point_mul(k, h));

    // STEP 7
    let s = k + c * x;

    // STEP 8 and 9
    encode(gamma)
        .concat(&Scalar::to_byte_seq_le(c).slice(0, C_LEN))
        .concat(&Scalar::to_byte_seq_le(s).slice(0, Q_LEN))
}

pub fn ecvrf_proof_to_hash(pi: &ByteSeq) -> ByteSeqResult {
    // STEP 1, 2 (it panics if invalid) and 3
    // TODO fix decode proof such that it doesn't panic
    // TODO should c and d from decode proof not be used?
    let (gamma, _, _) = ecvrf_decode_proof(pi);

    // STEP 4 + 5
    let proof_to_hash_domain_separator_front = ByteSeq::new(3);
    let proof_to_hash_domain_separator_back = ByteSeq::new(0);

    // STEP 6
    let suite_string = ByteSeq::new(SUITE_INT);
    ByteSeqResult::Ok(sha512(&suite_string
        .concat(&proof_to_hash_domain_separator_front)
        .concat(&encode(point_mul_by_cofactor(gamma)))
        .concat(&proof_to_hash_domain_separator_back)).slice(0,64))
}

// TODO add validate_key stuff
// TODO check if encode_to_curve_salt should be parameterized
// TODO remove secret key once we know how to byte array to byte seq
pub fn ecvrf_verify(
    pk: PublicKey, alpha: &ByteSeq, pi: &ByteSeq, validate_key: bool,
    sk: SecretKey
) -> ByteSeqResult {
    let base = decompress(BASE).unwrap();

    // STEP 1 and 2 (it panics if invalid)
    // TODO return invalid instead of panic
    let pk_string = secret_to_public_string(sk);
    let y = decode(pk_string).unwrap();
    
    // STEP 3
    // TODO probably not hacspec, result?
    let mut result = ByteSeqResult::Ok(ByteSeq::new(0));
    if validate_key {
        if !ecvrf_validate_key(pk) {
            result = ByteSeqResult::Err(Error::InvalidPublicKey)
        }
    } else {
        // STEP 4, 5 (it panics if invalid) and 6
        // TODO fix decode proof such that it doesn't panic
        let (gamma, c, s) = ecvrf_decode_proof(pi);

        // STEP 7
        // TODO this is stupid remove code duplication
        let pk_string = secret_to_public_string(sk);
        let h = ecvrf_encode_to_curve_try_and_increment(&pk_string, alpha);

        // STEP 8
        let u = point_add(point_mul(s, base), point_neg(point_mul(c,y)));

        // STEP 9
        let v = point_add(point_mul(s, h), point_neg(point_mul(c,gamma)));

        // STEP 10
        let c_prime = ecvrf_challenge_generation(y, h, gamma, u, v);
        
        // STEP 11, result sketchy, result type
        if c == c_prime {
            result = ecvrf_proof_to_hash(pi)
        } else {
            result = ByteSeqResult::Err(Error::InvalidLength)
        }
    }
    result
}

// AUXILLIARY FUNCTIONS ========================================================
// Note that section 5.5 also uses a point_to_string function.

// See section 5.4.1
// For use in cipher suite 3
// Note that this should not be used when alpha should remain secret
// Panics occasionally with very low probability
fn ecvrf_encode_to_curve_try_and_increment(
    encode_to_curve_salt: &ByteSeq, alpha: &ByteSeq
) -> EdPoint {
    let encode_to_curve_domain_separator_front = ByteSeq::new(1);
    let encode_to_curve_domain_separator_back = ByteSeq::new(0);

    let mut h: Option<EdPoint> = None;

    // TODO can we have while loops in hacspec?
    for ctr in 1..256 {
        if h == None {
            let ctr_string = ByteSeq::new(ctr);
            let suite_string = ByteSeq::new(SUITE_INT);
            let hash_string = sha512(&suite_string
                .concat(&encode_to_curve_domain_separator_front)
                .concat(encode_to_curve_salt)
                .concat(alpha)
                .concat(&ctr_string)
                .concat(&encode_to_curve_domain_separator_back));
            
            h = decode(hash_string.slice(0,64));
        }
    }
    let h = h.unwrap();
    point_mul_by_cofactor(h)
}

// For use in cipher suite 4, not currently used
fn ecvrf_encode_to_curve_h2c_suite(
    encode_to_curve_salt: &ByteSeq, alpha: &ByteSeq
) -> EdPoint {
    let string_to_be_hashed = encode_to_curve_salt.concat(alpha);
    let suite_string = ByteSeq::new(SUITE_INT);
    // TODO is it the correct h2c_suite_ID_string
    // let dst = ByteSeq::from_literal("ECVRF_")
    //     .concat(&ByteSeq::from_literal("edwards25519_XMD:SHA-512_ELL2_RO_"))
    // TODO fix this, this is stupid
    let dst = ByteSeq::new(0)
        .concat(&ByteSeq::new(1))
        .concat(&suite_string);
    ed_hash_to_curve(&string_to_be_hashed, &dst)
}

// See section 5.4.2
// See RFC6979, section 3.2
// See RFC8032, section 5.1.6
// Both implementations should probably be available
// 
// This implements 5.1.6 of RFC8032
// TODO BigScalar or Scalar?
fn ecvrf_nonce_generation(sk: SecretKey, h_string: &ByteSeq) -> Scalar {
    // TODO should this be le bytes?
    let hashed_sk_string = sha512(&sk.to_le_bytes());
    let truncated_hashed_sk_string = hashed_sk_string.slice(32,32);
    let k_string = sha512(&truncated_hashed_sk_string.concat(h_string));
    
    // TODO check is this the correct q value?
    // TODO does mod q happen automatically?
    Scalar::from_byte_seq_le(k_string)
}

// See section 5.4.3
// cLen defined as 16 by ciphersuite
// TODO Can we use compressedEdPoint?
// TODO can we just use BigScalar?
fn ecvrf_challenge_generation(
    p1: EdPoint, p2: EdPoint, p3: EdPoint, p4: EdPoint, p5: EdPoint
) -> Scalar {
    let challenge_generation_domain_separator_front = ByteSeq::new(2);
    let challenge_generation_domain_separator_back = ByteSeq::new(0);
    let suite_string = ByteSeq::new(SUITE_INT);
    let string = suite_string
        .concat(&challenge_generation_domain_separator_front)
        .concat(&compress(p1).to_le_bytes())
        .concat(&compress(p2).to_le_bytes())
        .concat(&compress(p3).to_le_bytes())
        .concat(&compress(p4).to_le_bytes())
        .concat(&compress(p5).to_le_bytes())
        .concat(&challenge_generation_domain_separator_back);
    let c_string = sha512(&string);
    let truncated_c_string = c_string.slice(0,15);
    // TODO should this be le bytes? does it mod q? Should be BigInteger?
    Scalar::from_byte_seq_le(truncated_c_string)
}

// See section 5.4.4
// Panics if decoding of point fails
// Should it be BigInteger instead of Scalar?
fn ecvrf_decode_proof(pi: &ByteSeq) -> (EdPoint, Scalar, Scalar) {
    let gamma_string = pi.slice(0, PT_LEN);
    let c_string = pi.slice(PT_LEN, C_LEN);
    let s_string = pi.slice(PT_LEN + C_LEN, Q_LEN);
    let gamma = decode(gamma_string);
    
    // panics if invalid
    let gamma = gamma.unwrap();

    // Scalar not good?
    // How can s be bigger than q? It comes from 32 bytes?
    let c = Scalar::from_byte_seq_le(c_string);
    let s = Scalar::from_byte_seq_le(s_string);
    // TODO check if s (before mod q) is bigger than q

    (gamma, c, s)
}

// See section 5.4.5
// y is a public key ie a point on the curve
fn ecvrf_validate_key(y: PublicKey) -> bool {
    // TODO panics instead of returning false, false instead of invalid
    let y_prime = point_mul_by_cofactor(decompress(y).unwrap());
    !is_identity(y_prime)
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