use hacspec_lib::*;
use hacspec_sha256::*;

unsigned_public_integer!(RSAInt, 1024);

pub type PK = (RSAInt, RSAInt);
pub type SK = (RSAInt, RSAInt);
pub type KeyPair = (PK, SK);

pub fn i2osp(x: RSAInt, x_len: usize) -> ByteSeq {
    // TODO check x_len thingy
    RSAInt::to_byte_seq_be(x).slice(128-x_len, x_len)
}

pub fn os2ip(x: &ByteSeq) -> RSAInt {
    RSAInt::from_byte_seq_be(x)
}

// Probably not hacspec usize to u128 unwrap
pub fn mgf1(mgf_seed: &ByteSeq, mask_len: usize) -> ByteSeq {
    // TODO check if mask_len is loo large
    // TODO should probably not be mutable
    let mut t = ByteSeq::new(0);
    for i in 0..((mask_len + 32 - 1) / 32 - 1) {
        let x = i2osp(RSAInt::from_literal(
            u128::try_from(i).unwrap()), 4);
        t = t.concat(&sha256(&mgf_seed.concat(&x)));
    }
    t.slice(0, mask_len)
}

pub fn rsaep(pk: PK, m: RSAInt) -> RSAInt {
    // TODO check that message is smaller than n
    m.pow_mod(pk.0, pk.1)
}

pub fn rsadp(sk: SK, c: RSAInt) -> RSAInt {
    // TODO check that ciphertext is smaller than n
    c.pow_mod(sk.0, sk.1)
}

pub fn rsasp1(sk: SK, m: RSAInt) -> RSAInt {
    // TODO check that message is smaller than n
    m.pow_mod(sk.0, sk.1)
}

pub fn rsavp1(pk: PK, s: RSAInt) -> RSAInt {
    // TODO check that signature is smaller than n
    s.pow_mod(pk.0, pk.1)
}

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

    impl Arbitrary for RSAInt {
        fn arbitrary(g: &mut Gen) -> RSAInt {
            let mut a: [u8; 128] = [0; 128];
            for i in 0..128 {
                a[i] = u8::arbitrary(g);
            }
            RSAInt::from_byte_seq_be(&Seq::<U8>::from_public_slice(&a))
        }
    }

    // impl Arbitrary for ByteSeq {
    //     fn arbitrary(g: &mut Gen) -> ByteSeq {

    //     }
    // }

    #[quickcheck]
    fn i2os2i(x: RSAInt) -> bool {
        x == os2ip(&i2osp(x, 128))
    }

    // #[quickcheck]
    // fn os2i2os(x: ByteSeq) -> bool {
    //     x == i2osp(os2ip(&x), 10)
    // }

    #[test]
    fn uniti2os2i() {
        let x = RSAInt::from_literal(12341234);
        assert_eq!(os2ip(&i2osp(x, 3)), x)
    }

    #[test]
    fn unitos2i2os() {
        let x = ByteSeq::from_hex("abcdef");
        assert_eq!(i2osp(os2ip(&x), 3), x)
    }

    // #[test]
    // fn rsaeprsadp() {
    //     unimplemented!()
    // }

    // perhaps check properties on the numbers of rsa keys
}
