use hacspec_lib::*;
use hacspec_ed25519::*;
use hacspec_sha512::*;
use ed25519_hash::*;

#[derive(Debug)]
pub enum Errorec {
    FailedVerify,
    MessageTooLarge,
    InvalidProof,
    InvalidPublicKey,
    FailedDecompression,
}

pub type ByteSeqResult = Result<ByteSeq, Errorec>;
pub type ProofResult = Result<(EdPoint, Scalar, Scalar), Errorec>;
// TODO a bit weird to use a bool result
pub type BoolResult = Result<bool, Errorec>;

// These three are defined by the ECVRF-EDWARDS25519-SHA512-TAI suite
const C_LEN: usize = 16usize;
const PT_LEN: usize = 32usize;
const Q_LEN: usize = 32usize;
const SUITE_INT: usize = 4usize;

fn suite_string() -> ByteSeq { intbyte(SUITE_INT) }
    
// ECVRF =======================================================================

// We use ciphersuite 4 so encode_to_curve_salt is part of the ciphersuite
pub fn ecvrf_prove(
    sk: SecretKey, alpha: &ByteSeq
) -> ByteSeqResult {
    let base = decompress(BASE).ok_or(Errorec::FailedDecompression)?;
    
    // STEP 1
    let (x, _) = secret_expand(sk);
    let x = Scalar::from_byte_seq_le(x);
    let pk = secret_to_public(sk);
    let y = decompress(secret_to_public(sk)).ok_or(Errorec::InvalidPublicKey)?;
    let pkd = decompress(pk).unwrap();
    assert_eq!(point_mul(x, base), pkd);

    // STEP 2
    let encode_to_curve_salt = pk.slice(0,32);
    let h = ecvrf_encode_to_curve_h2c_suite(
        &encode_to_curve_salt, alpha);

    // STEP 3
    let h_string = encode(h);

    // STEP 4
    let gamma = point_mul(x, h);

    // STEP 5
    let k = ecvrf_nonce_generation(sk, &h_string);

    // STEP 6
    let c = ecvrf_challenge_generation(
        y, h, gamma, point_mul(k, base), 
        point_mul(k, h));

    // STEP 7
    let s = k + c * x;

    // STEP 8 and 9
    ByteSeqResult::Ok(encode(gamma)
        .concat(&Scalar::to_byte_seq_le(c).slice(0, C_LEN))
        .concat(&Scalar::to_byte_seq_le(s).slice(0, Q_LEN))
                .slice(0, C_LEN + Q_LEN + PT_LEN))
}

pub fn ecvrf_proof_to_hash(pi: &ByteSeq) -> ByteSeqResult {
    // STEP 1, 2 and 3
    let (gamma, _, _) = ecvrf_decode_proof(pi)?;

    // STEP 4 + 5
    let proof_to_hash_domain_separator_front = intbyte(3);
    let proof_to_hash_domain_separator_back = intbyte(0);

    // STEP 6
    ByteSeqResult::Ok(sha512(&suite_string()
        .concat(&proof_to_hash_domain_separator_front)
        .concat(&encode(point_mul_by_cofactor(gamma)))
        // .concat(&compress(point_mul_by_cofactor(gamma)).slice(0,32))
        // slice because sha512 returns digest instead of byteseq
        .concat(&proof_to_hash_domain_separator_back)).slice(0,64))
}

// We use ciphersuite 4 so encode_to_curve_salt is part of the ciphersuite
pub fn ecvrf_verify(
    pk: PublicKey, alpha: &ByteSeq, pi: &ByteSeq, validate_key: bool
) -> ByteSeqResult {
    let base = decompress(BASE).ok_or(Errorec::FailedDecompression)?;

    // STEP 1 and 2
    let y = decompress(pk).ok_or(Errorec::InvalidPublicKey)?;
    
    // STEP 3
    if validate_key {
        ecvrf_validate_key(pk)?;
    } 

    // STEP 4, 5 and 6
    let (gamma, c, s) = ecvrf_decode_proof(pi)?;

    // STEP 7
    let encode_to_curve_salt = pk.slice(0,32);
    let h = ecvrf_encode_to_curve_h2c_suite(
        &encode_to_curve_salt, alpha);

    // TODO point mul uses scalar
    // STEP 8
    let u = point_add(point_mul(s, base), point_neg(point_mul(c,y)));

    // STEP 9
    let v = point_add(point_mul(s, h), point_neg(point_mul(c,gamma)));

    // STEP 10
    let c_prime = ecvrf_challenge_generation(y, h, gamma, u, v);

    assert_eq!(c, c_prime);
    
    // STEP 11
    // print!("\nc:       {} \n", c);
    // print!("c_prime: {} \n", c_prime);
    if c == c_prime {
        ecvrf_proof_to_hash(pi)
    } else {
        ByteSeqResult::Err(Errorec::FailedVerify)
    }
}

// AUXILLIARY FUNCTIONS ========================================================
// Note that section 5.5 also uses a point_to_string function.

// See section 5.4.1
// For ciphersuite 3
// Note that this should not be used when alpha should remain secret
// Panics occasionally with very low probability
fn ecvrf_encode_to_curve_try_and_increment(
    encode_to_curve_salt: &ByteSeq, alpha: &ByteSeq
) -> EdPoint {
    let encode_to_curve_domain_separator_front = intbyte(1);
    let encode_to_curve_domain_separator_back = intbyte(0);

    let mut h: Option<EdPoint> = Option::<EdPoint>::None;

    // TODO can we have while loops in hacspec?
    for ctr in 1..256 {
        // this h 'inexisting variable'? hacspec not happy
        if h == Option::<EdPoint>::None {
        // if true {
            let ctr_string = intbyte(ctr);
            let hash_string = sha512(&suite_string()
                .concat(&encode_to_curve_domain_separator_front)
                .concat(encode_to_curve_salt)
                .concat(alpha)
                .concat(&ctr_string)
                .concat(&encode_to_curve_domain_separator_back));
            h = decompress(CompressedEdPoint::from_slice(&hash_string, 0, 32));
        }
    }
    let h = h.unwrap();
    point_mul_by_cofactor(h)
}

// See section 5.4.1.2
fn ecvrf_encode_to_curve_h2c_suite(
    encode_to_curve_salt: &ByteSeq, alpha: &ByteSeq
) -> EdPoint {
    let string_to_be_hashed = encode_to_curve_salt.concat(alpha);
    // TODO Faked, fix later:
    let dst = suite_string();
    ed_encode_to_curve(&string_to_be_hashed, &dst)
}

// See section 5.4.2
// See RFC6979, section 3.2
// See RFC8032, section 5.1.6
// Both implementations should probably be available
// 
// This implements 5.1.6 of RFC8032
fn ecvrf_nonce_generation(
    sk: SecretKey, h_string: &ByteSeq
) -> Scalar {
    let hashed_sk_string = sha512(&sk.to_le_bytes());
    let truncated_hashed_sk_string = hashed_sk_string.slice(32,32);
    let k_string = sha512(&truncated_hashed_sk_string.concat(h_string));
    
    // TODO is slice correct? Probably yes, it is le, print to test
    let nonce = BigScalar::from_byte_seq_le(k_string);
    let nonceseq = nonce.to_byte_seq_le().slice(0, 32);
    Scalar::from_byte_seq_le(nonceseq)
}

// See section 5.4.3
fn ecvrf_challenge_generation(
    p1: EdPoint, p2: EdPoint, p3: EdPoint, p4: EdPoint, p5: EdPoint
) -> Scalar {
    let challenge_generation_domain_separator_front = intbyte(2);
    let challenge_generation_domain_separator_back = intbyte(0);
    let string = suite_string()
        .concat(&challenge_generation_domain_separator_front)
        // .concat(&compress(p1).slice(0,32))
        // .concat(&compress(p2).slice(0,32))
        // .concat(&compress(p3).slice(0,32))
        // .concat(&compress(p4).slice(0,32))
        // .concat(&compress(p5).slice(0,32))
        .concat(&encode(p1))
        .concat(&encode(p2))
        .concat(&encode(p3))
        .concat(&encode(p4))
        .concat(&encode(p5))
        .concat(&challenge_generation_domain_separator_back);
    let c_string = sha512(&string);
    let truncated_c_string = c_string.slice(0, C_LEN);
    // TODO should not be a problem as scalar mod is bigger than 2^128-1
    Scalar::from_byte_seq_le(truncated_c_string)
}

// See section 5.4.4
fn ecvrf_decode_proof(pi: &ByteSeq) -> ProofResult {
    println!("pi: {}", pi.to_hex());
    let gamma_string = pi.slice(0, PT_LEN);
    let c_string = pi.slice(PT_LEN, C_LEN);
    let s_string = pi.slice(PT_LEN + C_LEN, Q_LEN);
    let gamma = decompress(CompressedEdPoint::from_slice(&gamma_string, 0, 32))
                .ok_or(Errorec::InvalidProof)?;

    let c = Scalar::from_byte_seq_le(c_string);
    let s = Scalar::from_byte_seq_le(s_string);
    // This is definitely wrong see step 8 of decode proof
    // TODO check if s (before mod q) is bigger than q

    ProofResult::Ok((gamma, c, s))
}

// See section 5.4.5
fn ecvrf_validate_key(y: PublicKey) -> BoolResult {
    let y = decompress(y).ok_or(Errorec::InvalidPublicKey)?;
    let y_prime = point_mul_by_cofactor(y);
    if is_identity(y_prime) {
        BoolResult::Err(Errorec::InvalidPublicKey)
    } else {
        BoolResult::Ok(true)
    }
}

// Note, only one byte is allowed
fn intbyte(y: usize) -> ByteSeq {
    let mut x = Ed25519FieldElement::ZERO();
    for _ctr in 0..y {
        x = x + Ed25519FieldElement::ONE();
    }
    x.to_byte_seq_be().slice(31,1)
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

    #[derive(Clone, Copy, Debug)]
    struct Keyp {sk: SecretKey, pk: PublicKey}
    #[derive(Clone, Copy, Debug)]
    struct Wrapper(Ed25519FieldElement);

    impl Arbitrary for Wrapper {
        fn arbitrary(g: &mut Gen) -> Wrapper {
            const NUM_BYTES: u32 = 31;
            let mut a: [u8; NUM_BYTES as usize] = [0; NUM_BYTES as usize];
            for i in 0..NUM_BYTES as usize {
                a[i] = u8::arbitrary(g);
            }
            Wrapper(Ed25519FieldElement::from_byte_seq_be(
                &Seq::<U8>::from_public_slice(&a)))
        }
    }
    
    public_nat_mod!(
        type_name: KeyInt,
        type_of_canvas: KeyCanvas,
        bit_size_of_field: 256,
        modulo_value: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );

    impl Arbitrary for Keyp {
        fn arbitrary(g: &mut Gen) -> Keyp {
            const NUM_BYTES: u32 = 32;
            let mut a: [u8; NUM_BYTES as usize] = [0; NUM_BYTES as usize];
            for i in 0..NUM_BYTES as usize {
                a[i] = u8::arbitrary(g);
            }

            let bs = KeyInt::from_byte_seq_be(
                &Seq::<U8>::from_public_slice(&a));
            let bss = bs.to_byte_seq_be();
            let sk = SerializedScalar::from_slice(&bss, 0, 32);

            let pk = secret_to_public(sk);
            Keyp {sk, pk}
        }
    }

    #[quickcheck]
    // #[ignore]
    fn ecvrf(kp: Keyp, alpha: Wrapper) -> bool {
        let alpha = alpha.0.to_byte_seq_be();
        let pi = ecvrf_prove(kp.sk, &alpha).unwrap();
        let beta = ecvrf_proof_to_hash(&pi).unwrap();
        println!("\n\n       {}\n\n", beta.to_hex());
        let beta_prime = ecvrf_verify(kp.pk, &alpha, &pi, true).unwrap();
        println!("\n\nbeta_prime: {}\nbeta:       {}\n\n", beta_prime.to_hex(), beta.to_hex());
        beta_prime == beta
    }
    
    #[quickcheck]
    #[ignore]
    fn neg_ecvrf(kp: Keyp, fake: Keyp, alpha: Wrapper) -> bool {
        let alpha = alpha.0.to_byte_seq_be();
        let pi = ecvrf_prove(kp.sk, &alpha).unwrap();
        match ecvrf_verify(fake.pk, &alpha, &pi, true) {
            Ok(_beta_prime) => panic!(),
            Err(e) => matches!(e, Errorec::FailedVerify),
        }
    }

    #[test]
    fn unit_ecvrf() {
        let alpha = ByteSeq::from_public_slice(b"");
        let secret = ByteSeq::from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public = ByteSeq::from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let pitest = ByteSeq::from_hex("7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f14adf9a3cd8b8412d9038531e865c341cafa73589b023d14311c331a9ad15ff2fb37831e00f0acaa6d73bc9997b06501");

        let sk = SerializedScalar::from_slice(&secret, 0, 32);
        let pk = secret_to_public(sk);
        let pkstr = secret_to_public_string(sk);
        assert_eq!(public, pkstr);
        
        let pi = ecvrf_prove(sk, &alpha).unwrap();
        assert_eq!(pi, pitest);

        let beta = ecvrf_proof_to_hash(&pi).unwrap();
        let beta_prime = ecvrf_verify(pk, &alpha, &pi, true).unwrap();
        assert_eq!(beta_prime, beta);
    }

}