use hacspec_lib::*;
use hacspec_sha256::*;

// RSA =========================================================================

pub const BIT_SIZE: u32  = 1024u32;
pub const BYTE_SIZE: u32 = 1024u32 / 8u32;
const HLEN: usize = 32usize; // sha256 / 8 = 32
// const suite_string: ByteSeq = ByteSeq::from_hex("01");
unsigned_public_integer!(RSAInt, 1024);

pub enum Error {
    InvalidLength,
    MessageTooLarge,
    InvalidProof,
}

pub type PK = (RSAInt, RSAInt);
pub type SK = (RSAInt, RSAInt);
pub type KeyPair = (PK, SK);
pub type ByteSeqResult = Result<ByteSeq, Error>;
pub type RSAIntResult = Result<RSAInt, Error>;

pub fn i2osp(x: RSAInt, x_len: u32) -> ByteSeqResult {
    if x >= (RSAInt::exp(RSAInt::from_literal(256u128), x_len)) 
            && x_len != BYTE_SIZE {
        ByteSeqResult::Err(Error::InvalidLength)
    } else {
        ByteSeqResult::Ok(RSAInt::to_byte_seq_be(x)
            .slice((BYTE_SIZE - x_len) as usize, x_len as usize))
    }
}

pub fn os2ip(x: &ByteSeq) -> RSAInt {
    RSAInt::from_byte_seq_be(x)
}

pub fn mgf1(mgf_seed: &ByteSeq, mask_len: usize) -> ByteSeqResult {
    let mut result = ByteSeqResult::Ok(ByteSeq::new(0));
    if mask_len >= 2usize^32usize * HLEN {
        result = ByteSeqResult::Err(Error::InvalidLength)
    } else {
        let mut t = ByteSeq::new(0);
        for i in 0..((mask_len + 32) / 32) {
            let x = i2osp(RSAInt::from_literal(
                i as u128), 4u32)?;
            t = t.concat(&sha256(&mgf_seed.concat(&x)));
        }
        result = ByteSeqResult::Ok(t.slice(0, mask_len))
    }
    result
}

pub fn rsaep(pk: PK, m: RSAInt) -> RSAIntResult {
    let (n, e) = pk;
    if m > n - RSAInt::ONE() {
        RSAIntResult::Err(Error::MessageTooLarge)
    } else {
        RSAIntResult::Ok(m.pow_mod(e, n))
    }
}

pub fn rsadp(sk: SK, c: RSAInt) -> RSAIntResult {
    let (n, d) = sk;
    if c > n - RSAInt::ONE() {
        RSAIntResult::Err(Error::MessageTooLarge)
    } else {
        RSAIntResult::Ok(c.pow_mod(d, n))
    }
}

pub fn rsasp1(sk: SK, m: RSAInt) -> RSAIntResult {
    let (n, d) = sk;
    if m > n - RSAInt::ONE() {
        RSAIntResult::Err(Error::MessageTooLarge)
    } else {
        RSAIntResult::Ok(m.pow_mod(d, n))
    }
}

pub fn rsavp1(pk: PK, s: RSAInt) -> RSAIntResult {
    let (n, e) = pk;
    if s > n - RSAInt::ONE() {
        RSAIntResult::Err(Error::MessageTooLarge)
    } else {
        RSAIntResult::Ok(s.pow_mod(e, n))
    }
}

// VRF stuff ===================================================================

fn rsa_fdh_vrf_mgf1(n: RSAInt, alpha: &ByteSeq) -> ByteSeqResult {
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
    let em = rsa_fdh_vrf_mgf1(n, alpha)?;

    // STEP 3
    let m = os2ip(&em);

    // STEP 4
    let s = rsasp1(sk, m)?;

    // STEP 5
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
    let sha_digest = sha256(&hash_string);

    // STEP 3
    // TODO this is stupid
    // sha256(&hash_string)
    ByteSeqResult::Ok(sha_digest.slice(0,32))
}

// TODO check if we should include mgf_salt
// Input: Private Key, alpha_string, pi_string
// Output: Verified beta string
pub fn verify(pk: PK, alpha: &ByteSeq, pi_string: &ByteSeq) -> ByteSeqResult {
    let (n, _e) = pk;

    // STEP 1
    let s = os2ip(pi_string);

    // STEP 2, TODO: maybe output 'INVALID'??
    let m = rsavp1(pk, s)?;

    // STEP 3 and 4
    let em_prime = rsa_fdh_vrf_mgf1(n, alpha)?;

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

// TODO check what we should do for the ciphersuites (different hash functions)

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

    impl Arbitrary for RSAInt {
        fn arbitrary(g: &mut Gen) -> RSAInt {
            const NUM_BYTES: u32 = 127;
            let mut a: [u8; NUM_BYTES as usize] = [0; NUM_BYTES as usize];
            for i in 0..NUM_BYTES as usize {
                a[i] = u8::arbitrary(g);
            }
            RSAInt::from_byte_seq_be(&Seq::<U8>::from_public_slice(&a))
        }
    }

    impl Arbitrary for Keyp {
        fn arbitrary(_g: &mut Gen) -> Keyp {
            let ((n, e), (_n, d)) = rsa_key_gen();
            Keyp {n,d,e}
        }
    }

// RSA TESTS ===================================================================
    #[quickcheck]
    fn i2os2i(x: RSAInt) -> bool {
        match i2osp(x, 128) {
            Ok(i) => x == os2ip(&i),
            Err(_e) => panic!(),
        }
    }

    #[quickcheck]
    #[ignore]
    fn rsaeprsadp(x: RSAInt, kp: Keyp) -> bool {
        match rsaep((kp.n, kp.e), x) {
            Ok(i) => 
                match rsadp((kp.n, kp.d), i) {
                    Ok(i) => i == x,
                    Err(_e) => panic!(),
                }
            Err(_e) => panic!(),
        }
    }

    #[quickcheck]
    #[ignore]
    fn rsasp1rsavp1(x: RSAInt, kp: Keyp) -> bool {
        match rsasp1((kp.n, kp.d), x) {
            Ok(s) => 
                match rsavp1((kp.n, kp.e), s) {
                    Ok(i) => i == x,
                    Err(_e) => panic!(),
                }
            Err(_e) => panic!(),
        }
    }

    #[quickcheck]
    #[ignore]
    fn neg_rsaeprsadp(x: RSAInt, y: RSAInt, kp: Keyp) -> bool {
        match rsaep((kp.n, kp.e), x) {
            Ok(_i) => 
                match rsadp((kp.n, kp.d), y) {
                    Ok(i) => i != x,
                    Err(_e) => panic!(),
                }
            Err(_e) => panic!(),
        }
    }

    #[quickcheck]
    #[ignore]
    fn neg_rsasp1rsavp1(x: RSAInt, y: RSAInt, kp: Keyp) -> bool {
        match rsasp1((kp.n, kp.d), x) {
            Ok(_i) => 
                match rsavp1((kp.n, kp.e), y) {
                    Ok(i) => i != x,
                    Err(_e) => panic!(),
                }
            Err(_e) => panic!(),
        }
    }

    #[quickcheck]
    #[ignore]
    fn negkey_rsaeprsadp(x: RSAInt, kp: Keyp, fake: Keyp) -> bool {
        match rsaep((kp.n, kp.e), x) {
            Ok(_i) => 
                match rsadp((fake.n, fake.d), x) {
                    Ok(i) => i != x,
                    Err(_e) => panic!(),
                }
            Err(_e) => panic!(),
        }
    }

    #[quickcheck]
    #[ignore]
    fn negkey_rsasp1rsavp1(x: RSAInt, kp: Keyp, fake: Keyp) -> bool {
        match rsasp1((kp.n, kp.d), x) {
            Ok(_i) => 
                match rsavp1((fake.n, fake.e), x) {
                    Ok(i) => i != x,
                    Err(_e) => panic!(),
                }
            Err(_e) => panic!(),
        }
    }

    #[test]
    fn uniti2os2i() {
        let x = RSAInt::from_literal(12341234);
        match i2osp(x, 3) {
            Ok(i) => assert_eq!(os2ip(&i), x),
            Err(_e) => panic!(),
        }
    }

    #[test]
    fn unitos2i2os() {
        let x = ByteSeq::from_hex("abcdef");
        match i2osp(os2ip(&x), 3) {
            Ok(i) => assert_eq!(i, x),
            Err(_e) => panic!(),
        }
    }

    #[test]
    fn unitrsaeprsadp() {
        let (pk, sk) = rsa_key_gen();
        let x = os2ip(&ByteSeq::from_hex("abcdef"));
        match rsaep(pk, x) {
            Ok(i) => 
                match rsadp(sk, i) {
                    Ok(i) => assert_eq!(i, x),
                    Err(_e) => panic!(),
                }
            Err(_e) => panic!(),
        }
    }

    #[test]
    fn unitrsasp1rsavp1() {
        let (pk, sk) = rsa_key_gen();
        let x = os2ip(&ByteSeq::from_hex("abcdef"));
        match rsasp1(sk, x) {
            Ok(i) => 
                match rsavp1(pk, i) {
                    Ok(i) => assert_eq!(i, x),
                    Err(_e) => panic!(),
                }
            Err(_e) => panic!(),
        }
    }

    #[test]
    fn unitrsasp1rsavp1_large_num() {
        let (pk, sk) = rsa_key_gen();
        let x = os2ip(&ByteSeq::from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0"));
        match rsasp1(sk, x) {
            Ok(i) => 
                match rsavp1(pk, i) {
                    Ok(i) => assert_eq!(i, x),
                    Err(_e) => panic!(),
                }
            Err(_e) => panic!(),
        }
    }

// VRF TESTS ===================================================================

    #[quickcheck]
    #[ignore]
    fn rsafhdvrf(kp: Keyp, alpha: RSAInt) -> bool {
        match i2osp(alpha, BYTE_SIZE) {
            Ok(alpha) => {
                match prove((kp.n, kp.d), &alpha) {
                    Ok(pi) => {
                        match proof_to_hash(&pi) {
                            Ok(beta) => {
                                match verify((kp.n, kp.e), &alpha, &pi) {
                                    Ok(beta_v) => beta == beta_v,
                                    Err(_e) => panic!(),
                                }
                            },
                            Err(_e) => panic!(),
                        }
                    }
                    Err(_e) => panic!(),
                }
            }
            Err(_e) => panic!(),
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
}

