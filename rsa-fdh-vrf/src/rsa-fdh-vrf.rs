use hacspec_lib::*;
use hacspec_sha256::*;
use rsa::*;

// VRF stuff ===================================================================

fn vrf_mgf1(n: RSAInt, alpha: &ByteSeq) -> ByteSeqResult {
    let suite_string = i2osp(RSAInt::from_literal(1u128), 1u32)?;
    let mgf_domain_separator = i2osp(RSAInt::from_literal(1u128), 1u32)?;

    let mgf_salt1 = i2osp(RSAInt::from_literal(4u128), 1u32)?;
    let mgf_salt2 = i2osp(n, BYTE_SIZE)?;
    let mgf_salt = mgf_salt1.concat(&mgf_salt2);
    let mgf_string = suite_string
        .concat(&mgf_domain_separator
        .concat(&mgf_salt
        .concat(alpha)));
    let mgf = mgf1(&mgf_string, BYTE_SIZE as usize - 1usize)?;
    ByteSeqResult::Ok(mgf)
}

// Cipher suite = RSA-FDH-VRF-SHA256, TODO: extend to others
// MGF_salt currently part of cipher suite, could be optional input
// Input: Secret Key, alpha string in ByteSeq
// Output: pi_string proof that beta was calculated correctly
pub fn prove(sk: SK, alpha: &ByteSeq) -> ByteSeqResult {
    let (n, _d) = sk;

    // STEP 1 and 2
    let em = vrf_mgf1(n, alpha)?;

    // STEP 3
    let m = os2ip(&em);

    // STEP 4
    let s = rsasp1(sk, m)?;

    // STEP 5 and 6
    i2osp(s, BYTE_SIZE)
}

// Input: pi_string calculated in prove, or from verify
// Output: beta_string
pub fn proof_to_hash(pi_string: &ByteSeq) -> ByteSeqResult {
    let suite_string = i2osp(RSAInt::from_literal(1u128), 1u32)?;

    // STEP 1
    let proof_to_hash_domain_separator = i2osp(
        RSAInt::from_literal(2u128), 1u32)?;

    // STEP 2
    let hash_string = suite_string
        .concat(&proof_to_hash_domain_separator
        .concat(pi_string));

    // STEP 3
    // TODO this is stupid
    // sha256(&hash_string)
    ByteSeqResult::Ok(sha256(&hash_string).slice(0,32))
}

// TODO check if we should include mgf_salt
// Input: Private Key, alpha_string, pi_string
// Output: Verified beta string
pub fn verify(pk: PK, alpha: &ByteSeq, pi_string: &ByteSeq) -> ByteSeqResult {
    let (n, _e) = pk;

    // STEP 1
    let s = os2ip(pi_string);

    // STEP 2
    let m = rsavp1(pk, s)?;

    // STEP 3 and 4
    let em_prime = vrf_mgf1(n, alpha)?;

    // STEP 5
    let m_prime = os2ip(&em_prime);

    // STEP 6
    let mut result = ByteSeqResult::Ok(ByteSeq::new(0));
    if m == m_prime {
        let output = proof_to_hash(pi_string)?;
        result = ByteSeqResult::Ok(output)
    } else {
        result = ByteSeqResult::Err(Error::InvalidProof)
    }
    result
}

// TESTING =====================================================================
#[cfg(test)]
extern crate quickcheck;

#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[cfg(test)]
extern crate glass_pumpkin;

#[cfg(test)]
use num_bigint::{BigInt,Sign};

#[cfg(test)]
use glass_pumpkin::prime;

#[cfg(test)]
use quickcheck::*;

#[cfg(test)]
mod tests {
    use super::*;

// KEYGEN ======================================================================
    // Taken from https://asecuritysite.com/rust/rsa01/ 
    fn modinv(a0: BigInt, m0: BigInt) -> BigInt {
        if m0 == one() {return one()}
        let (mut a, mut m, mut x0, mut inv) = 
            (a0, m0.clone(), zero(), one());
        while a > one() {
            inv -= (&a / &m) * &x0;
            a = &a % &m;
            std::mem::swap(&mut a, &mut m);
            std::mem::swap(&mut x0, &mut inv)
        }
        if inv < zero() { inv += m0 }
        inv
    }

    fn rsa_key_gen() -> KeyPair {
        let p = BigInt::from_biguint(Sign::Plus,
            prime::new((BIT_SIZE / 2) as usize).unwrap());
        let q = BigInt::from_biguint(Sign::Plus,
            prime::new((BIT_SIZE / 2) as usize).unwrap());

        let n = RSAInt::from(p.clone()* q.clone());

        let e = BigInt::parse_bytes(b"65537", 10).unwrap();
        let totient = (p - BigInt::one()) * (q - BigInt::one());
        let d = modinv(e.clone(), totient.clone());
        
        ((n, RSAInt::from(e)), (n, RSAInt::from(d)))
    }

// QUICKCHECK ==================================================================
    #[derive(Clone, Copy, Debug)]
    struct Keyp {n: RSAInt, d: RSAInt, e: RSAInt}
    #[derive(Clone, Copy, Debug)]
    struct Wrapper(RSAInt);

    impl Arbitrary for Wrapper {
        fn arbitrary(g: &mut Gen) -> Wrapper {
            const NUM_BYTES: u32 = 127;
            let mut a: [u8; NUM_BYTES as usize] = [0; NUM_BYTES as usize];
            for i in 0..NUM_BYTES as usize {
                a[i] = u8::arbitrary(g);
            }
            Wrapper(RSAInt::from_byte_seq_be(&Seq::<U8>::from_public_slice(&a)))
        }
    }

    impl Arbitrary for Keyp {
        fn arbitrary(_g: &mut Gen) -> Keyp {
            let ((n, e), (_n, d)) = rsa_key_gen();
            Keyp {n,d,e}
        }
    }

// VRF TESTS ===================================================================

    #[quickcheck]
    #[ignore]
    fn rsafhdvrf(kp: Keyp, alpha: Wrapper) -> bool {
        let alpha = i2osp(alpha.0, BYTE_SIZE).unwrap();
        let pi = prove((kp.n, kp.d), &alpha).unwrap();
        let beta = proof_to_hash(&pi).unwrap();
        let beta_prime = verify((kp.n, kp.e), &alpha, &pi).unwrap();
        beta_prime == beta
    }
    
    #[quickcheck]
    #[ignore]
    fn negrsafhdvrf(kp: Keyp, fake: Keyp, alpha: Wrapper) -> bool {
        let alpha = i2osp(alpha.0, BYTE_SIZE).unwrap();
        let pi = prove((kp.n, kp.d), &alpha).unwrap();
        match verify((fake.n, fake.e), &alpha, &pi) {
            Ok(_beta_prime) => panic!(),
            Err(e) => matches!(e, Error::InvalidProof 
                                | Error::MessageTooLargeVerify),
        }
    }

    #[test]
    fn unitrsafhdvrf() {
        let (pk, sk) = rsa_key_gen();
        let alpha = ByteSeq::from_hex("abcdef");
        match prove(sk, &alpha) {
            Ok(pi) => {
                match proof_to_hash(&pi) {
                    Ok(beta) => {
                        match verify(pk, &alpha, &pi) {
                            Ok(beta_v) => assert_eq!(beta, beta_v),
                            Err(_e) => panic!(),
                        }
                    },
                    Err(_e) => panic!(),
                }
            }
            Err(_e) => panic!(),
        }
    }

    #[test]
    fn negunitrsafhdvrf() {
        let (_pk, sk) = rsa_key_gen();
        let (fakepk, _fakesk) = rsa_key_gen();
        let alpha = ByteSeq::from_hex("abcdef");
        match prove(sk, &alpha) {
            Ok(pi) => {
                match proof_to_hash(&pi) {
                    Ok(_beta) => {
                        match verify(fakepk, &alpha, &pi) {
                            Ok(_beta_v) => panic!(),
                            Err(e) => assert!(matches!(e, Error::InvalidProof)),
                        }
                    },
                    Err(_e) => panic!(),
                }
            }
            Err(_e) => panic!(),
        }
    }

    #[test]
    fn test() {
        match i2osp(RSAInt::from_literal(1), 1) {
            Ok(v) => println!("{}", v.to_hex()),
            Err(_e) => panic!()
        }
    } 
}

