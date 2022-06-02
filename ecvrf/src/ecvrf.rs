// Cipher suite = ECVRF-EDWARDS25519-SHA512-ELL2, methods for ECVRF-EDWARDS25519-SHA512-TAI present
// Based on section 5 of https://datatracker.ietf.org/doc/draft-irtf-cfrg-vrf/

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

public_nat_mod!(
    type_name: LargeMod,
    type_of_canvas: LargeModCanvas,
    bit_size_of_field: 256,
    modulo_value: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
);

array!(ArrLargeMod, 4, U64);
const Q: ArrLargeMod = ArrLargeMod(secret_array!(
    U64,
    [
        0x7fffffffffffffffu64,
        0xffffffffffffffffu64,
        0xffffffffffffffffu64,
        0xffffffffffffffedu64
    ]
));

const C_LEN: usize = 16usize;
const PT_LEN: usize = 32usize;
const Q_LEN: usize = 32usize;

bytes!(IntByte, 1);
#[rustfmt::skip]
const ZERO: IntByte = IntByte(secret_array!(U8,  [0x00u8]));
#[rustfmt::skip]
const ONE: IntByte = IntByte(secret_array!(U8,  [0x01u8]));
#[rustfmt::skip]
const TWO: IntByte = IntByte(secret_array!(U8,  [0x02u8]));
#[rustfmt::skip]
const THREE: IntByte = IntByte(secret_array!(U8,  [0x03u8]));
#[rustfmt::skip]
const FOUR: IntByte = IntByte(secret_array!(U8,  [0x04u8]));

const SUITE_STRING: IntByte = FOUR;

bytes!(DST, 39);
#[rustfmt::skip]
// "ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_"
const H2C_SUITE_ID_STRING: DST = DST(secret_array!(
    U8, 
    [
        0x45u8, 0x43u8, 0x56u8, 0x52u8, 0x46u8, 0x5fu8,
        0x65u8, 0x64u8, 0x77u8, 0x61u8, 0x72u8, 0x64u8, 0x73u8, 0x32u8, 
        0x35u8, 0x35u8, 0x31u8, 0x39u8, 0x5fu8, 0x58u8, 0x4du8, 0x44u8, 
        0x3au8, 0x53u8, 0x48u8, 0x41u8, 0x2du8, 0x35u8, 0x31u8, 0x32u8, 
        0x5fu8, 0x45u8, 0x4cu8, 0x4cu8, 0x32u8, 0x5fu8, 0x4eu8, 0x55u8 ,
        0x5fu8
    ]
));

// See section 5.4.1 for ciphersuite 3
// Note that this should not be used when alpha should remain secret
// Panics occasionally with very low probability
fn ecvrf_encode_to_curve_try_and_increment(
    encode_to_curve_salt: &ByteSeq, alpha: &ByteSeq
) -> EdPoint {
    let mut h: Option<EdPoint> = Option::<EdPoint>::None;
    for ctr in 1..256 {
        if h.clone() == Option::<EdPoint>::None {
            let ctr_string = intbyte(ctr-1);
            let hash_string = sha512(&SUITE_STRING
                .concat(&ONE)
                .concat(encode_to_curve_salt)
                .concat(alpha)
                .concat(&ctr_string)
                .concat(&ZERO));
            h = decompress(CompressedEdPoint::from_slice(&hash_string, 0, 32));
        }
    }
    let h = h.unwrap();
    point_mul_by_cofactor(h)
}

// Note, only one byte is allowed
fn intbyte(y: usize) -> ByteSeq {
    let mut x = Ed25519FieldElement::ZERO();
    for _ctr in 0..y {
        x = x + Ed25519FieldElement::ONE();
    }
    x.to_byte_seq_be().slice(31,1)
}

// See section 5.4.1.2
fn ecvrf_encode_to_curve_h2c_suite(
    encode_to_curve_salt: &ByteSeq, alpha: &ByteSeq
) -> EdPoint {
    let string_to_be_hashed = encode_to_curve_salt.concat(alpha);
    let dst = H2C_SUITE_ID_STRING.concat(&SUITE_STRING);
    ed_encode_to_curve(&string_to_be_hashed, &dst)
}

// See section 5.4.2
// See RFC6979, section 3.2
// See RFC8032, section 5.1.6
// This implements 5.1.6 of RFC8032
fn ecvrf_nonce_generation(
    sk: SecretKey, h_string: &ByteSeq
) -> Scalar {
    let hashed_sk_string = sha512(&sk.to_le_bytes());
    let truncated_hashed_sk_string = hashed_sk_string.slice(32,32);
    let k_string = sha512(&truncated_hashed_sk_string.concat(h_string));
    
    let nonce = BigScalar::from_byte_seq_le(k_string);
    let nonceseq = nonce.to_byte_seq_le().slice(0, 32);
    Scalar::from_byte_seq_le(nonceseq)
}

// See section 5.4.3
fn ecvrf_challenge_generation(
    p1: EdPoint, p2: EdPoint, p3: EdPoint, p4: EdPoint, p5: EdPoint
) -> Scalar {
    let string = SUITE_STRING
        .concat(&TWO)
        .concat(&encode(p1))
        .concat(&encode(p2))
        .concat(&encode(p3))
        .concat(&encode(p4))
        .concat(&encode(p5))
        .concat(&ZERO);

    let c_string = sha512(&string);
    let truncated_c_string= c_string.slice(0, C_LEN).concat(&ByteSeq::new(16));    
    Scalar::from_byte_seq_le(truncated_c_string)
}

// See section 5.4.4
fn ecvrf_decode_proof(pi: &ByteSeq) -> ProofResult {
    let gamma_string = pi.slice(0, PT_LEN);
    let c_string = pi.slice(PT_LEN, C_LEN);
    let s_string = pi.slice(PT_LEN + C_LEN, Q_LEN);
    let gamma = decompress(CompressedEdPoint::from_slice(&gamma_string, 0, 32))
                .ok_or(Errorec::InvalidProof)?;

    let c = Scalar::from_byte_seq_le(c_string.concat(&ByteSeq::new(16)));
    let s = Scalar::from_byte_seq_le(s_string.clone());

    let s_test = LargeMod::from_byte_seq_le(s_string);
    let q = LargeMod::from_byte_seq_be(&Q.to_be_bytes());
    if s_test > q {
        ProofResult::Err(Errorec::InvalidProof)
    } else {
        ProofResult::Ok((gamma, c, s))
    }
}

// See section 5.4.5
pub type BoolResult = Result<bool, Errorec>;
fn ecvrf_validate_key(y: PublicKey) -> BoolResult {
    let y = decompress(y).ok_or(Errorec::InvalidPublicKey)?;
    let y_prime = point_mul_by_cofactor(y);
    if is_identity(y_prime) {
        BoolResult::Err(Errorec::InvalidPublicKey)
    } else {
        BoolResult::Ok(true)
    }
}

pub fn ecvrf_prove(
    sk: SecretKey, alpha: &ByteSeq
) -> ByteSeqResult {
    let b = decompress(BASE).ok_or(Errorec::FailedDecompression)?;
    
    // STEP 1
    let (x, _) = secret_expand(sk);
    let x = Scalar::from_byte_seq_le(x);
    let y = point_mul(x, b);
    let pk = compresser(y);

    // STEP 2
    let encode_to_curve_salt = pk.slice(0,32);
    let h = ecvrf_encode_to_curve_h2c_suite(&encode_to_curve_salt, alpha);

    // STEP 3
    let h_string = encode(h);

    // STEP 4
    let gamma = point_mul(x, h);

    // STEP 5
    let k = ecvrf_nonce_generation(sk, &h_string);

    // STEP 6
    let u = point_mul(k, b);
    let v = point_mul(k, h);
    let c = ecvrf_challenge_generation(y, h, gamma, u, v);

    // STEP 7
    let s = k + (c * x);

    // STEP 8 and 9
    ByteSeqResult::Ok(encode(gamma)
        .concat(&Scalar::to_byte_seq_le(c).slice(0, C_LEN))
        .concat(&Scalar::to_byte_seq_le(s).slice(0, Q_LEN))
                .slice(0, C_LEN + Q_LEN + PT_LEN))
}

pub fn ecvrf_proof_to_hash(pi: &ByteSeq) -> ByteSeqResult {
    // STEP 1, 2 and 3
    let (gamma, _, _) = ecvrf_decode_proof(pi)?;

    // STEP 4 + 5 + 6
    ByteSeqResult::Ok(sha512(&SUITE_STRING
        .concat(&THREE)
        .concat(&encode(point_mul_by_cofactor(gamma)))
        .concat(&ZERO)).slice(0,64))
}

pub fn ecvrf_verify(
    pk: PublicKey, alpha: &ByteSeq, pi: &ByteSeq, validate_key: bool
) -> ByteSeqResult {
    let b = decompress(BASE).ok_or(Errorec::FailedDecompression)?;

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
    let h = ecvrf_encode_to_curve_h2c_suite(&encode_to_curve_salt, alpha);

    // STEP 8
    let u = point_add(point_mul(s, b), point_neg(point_mul(c, y)));

    // STEP 9
    let v = point_add(point_mul(s, h), point_neg(point_mul(c, gamma)));

    // STEP 10
    let c_prime = ecvrf_challenge_generation(y, h, gamma, u, v);

    // STEP 11
    if c == c_prime {
        ecvrf_proof_to_hash(pi)
    } else {
        ByteSeqResult::Err(Errorec::FailedVerify)
    }
}

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    use quickcheck::*;
    
    #[derive(Clone, Copy, Debug)]
    struct Keyp {sk: SecretKey, pk: PublicKey}
    #[derive(Clone, Copy, Debug)]
    struct Wrapper(Ed25519FieldElement);

    impl Arbitrary for Wrapper {
        fn arbitrary(g: &mut Gen) -> Wrapper {
            const NUM_BYTES: u32 = 32;
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
    #[ignore]
    fn ecvrf(kp: Keyp, alpha: Wrapper) -> bool {
        let alpha = alpha.0.to_byte_seq_be();
        let pi = ecvrf_prove(kp.sk, &alpha).unwrap();
        let beta = ecvrf_proof_to_hash(&pi).unwrap();
        let beta_prime = ecvrf_verify(kp.pk, &alpha, &pi, true).unwrap();
        beta_prime == beta
    }
    
    #[quickcheck]
    #[ignore]
    fn neg_ecvrf(kp: Keyp, fake: Keyp, alpha: Wrapper) -> bool {
        let alpha = alpha.0.to_byte_seq_be();
        let pi = ecvrf_prove(kp.sk, &alpha).unwrap();
        match ecvrf_verify(fake.pk, &alpha, &pi, true) {
            Ok(_beta_prime) => false,
            Err(e) => matches!(e, Errorec::FailedVerify),
        }
    }

    #[quickcheck]
    #[ignore]
    fn neg_alpha_ecvrf(kp: Keyp, alpha: Wrapper, fake_alpha: Wrapper) -> bool {
        let alpha = alpha.0.to_byte_seq_be();
        let fake_alpha = fake_alpha.0.to_byte_seq_be();
        let pi = ecvrf_prove(kp.sk, &alpha).unwrap();
        match ecvrf_verify(kp.pk, &fake_alpha, &pi, true) {
            Ok(_beta_prime) => false,
            Err(e) => matches!(e, Errorec::FailedVerify),
        }
    }

    // #[test]
    // fn unit_ecvrf_ell2() {
    //     let alpha = ByteSeq::from_public_slice(b"");
    //     let secret = ByteSeq::from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    //     let public = ByteSeq::from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    //     let pitest = ByteSeq::from_hex("7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f14adf9a3cd8b8412d9038531e865c341cafa73589b023d14311c331a9ad15ff2fb37831e00f0acaa6d73bc9997b06501");
    //     let betatest = ByteSeq::from_hex("9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cccf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54");

    //     let sk = SerializedScalar::from_slice(&secret, 0, 32);
    //     let pk = secret_to_public(sk);
    //     let pkstr = secret_to_public_string(sk);
    //     assert_eq!(public, pkstr);
        
    //     let pi = ecvrf_prove(sk, &alpha).unwrap();
    //     assert_eq!(pi, pitest);

    //     let beta = ecvrf_proof_to_hash(&pi).unwrap();
    //     assert_eq!(beta, betatest);

    //     let beta_prime = ecvrf_verify(pk, &alpha, &pi, true).unwrap();
    //     assert_eq!(beta_prime, beta);
    // }
    
   #[test]
   fn unit_ecvrf_tai() {
       let alpha = ByteSeq::from_public_slice(b"");
       let secret = ByteSeq::from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
       let public = ByteSeq::from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
       let pitest = ByteSeq::from_hex("8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805");
       let betatest = ByteSeq::from_hex("90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae");

       let sk = SerializedScalar::from_slice(&secret, 0, 32);
       let pk = secret_to_public(sk);
       let pkstr = secret_to_public_string(sk);
       assert_eq!(public, pkstr);
       
       let pi = ecvrf_prove(sk, &alpha).unwrap();
       assert_eq!(pi, pitest);

       let beta = ecvrf_proof_to_hash(&pi).unwrap();
       assert_eq!(beta, betatest);

       let beta_prime = ecvrf_verify(pk, &alpha, &pi, true).unwrap();
       assert_eq!(beta_prime, beta);
   }

}