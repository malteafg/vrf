use hacspec_lib::*;
use hacspec_ed25519::*;
use hacspec_sha512::*;
use hacspec_curve25519::*;

const B_IN_BYTES: usize = 64usize;
const S_IN_BYTES: usize = 128usize;
const L: usize = 48usize;
const J: u128 = 486662u128;
const K: u128 = 1u128;
const Z: u128 = 2u128;

array!(ArrEd25519FieldElement, 4, U64);

public_nat_mod!(
    type_name: EdFieldHash,
    type_of_canvas: EdFieldHashCanvas,
    bit_size_of_field: 512,
    modulo_value: "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
    // modulo_value: "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"
);

// (p - 1) / 2
const P_1_2: ArrEd25519FieldElement = ArrEd25519FieldElement(secret_array!(
    U64,
    [
        0x3fffffffffffffffu64,
        0xffffffffffffffffu64,
        0xffffffffffffffffu64,
        0xfffffffffffffff6u64
    ]
));

// (p + 3) / 8
const P_3_8: ArrEd25519FieldElement = ArrEd25519FieldElement(secret_array!(
    U64,
    [
        0x0fffffffffffffffu64,
        0xffffffffffffffffu64,
        0xffffffffffffffffu64,
        0xfffffffffffffffeu64
    ]
));

// (p - 5) / 8
const P_5_8: ArrEd25519FieldElement = ArrEd25519FieldElement(secret_array!(
    U64,
    [
        0x0fffffffffffffffu64,
        0xffffffffffffffffu64,
        0xffffffffffffffffu64,
        0xfffffffffffffffdu64
    ]
));

// taken from bls12-381-hash.rs
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5.4.1
pub fn expand_message_xmd(
    msg: &ByteSeq, dst: &ByteSeq, len_in_bytes: usize
) -> ByteSeq {
    let ell = (len_in_bytes + B_IN_BYTES - 1) / B_IN_BYTES; // ceil(len_in_bytes / b_in_bytes)
                                                            // must be that ell <= 255
    let dst_prime = dst.push(&U8_from_usize(dst.len())); // DST || I2OSP(len(DST), 1)
    let z_pad = ByteSeq::new(S_IN_BYTES); // I2OSP(0, s_in_bytes)
    let mut l_i_b_str = ByteSeq::new(2);
    l_i_b_str[0] = U8_from_usize(len_in_bytes / 256);
    l_i_b_str[1] = U8_from_usize(len_in_bytes); // I2OSP(len_in_bytes, 2)

    let msg_prime = z_pad
        .concat(msg)
        .concat(&l_i_b_str)
        .concat(&ByteSeq::new(1))
        .concat(&dst_prime); // Z_pad || msg || l_i_b_str || 0 || dst_prime
    
    let b_0 = ByteSeq::from_seq(&hash(&msg_prime)); // H(msg_prime)
    let mut b_i = ByteSeq::from_seq(&hash(&b_0.push(&U8(1u8))
        .concat(&dst_prime))); // H(b_0 || 1 || dst_prime)
    let mut uniform_bytes = ByteSeq::from_seq(&b_i);

    for i in 2..(ell + 1) {
        let t = ByteSeq::from_seq(&b_0);
        b_i = ByteSeq::from_seq(&hash(&(t ^ b_i).push(&U8_from_usize(i))
            .concat(&dst_prime))); //H((b_0 ^ b_(i-1)) || 1 || dst_prime)
        uniform_bytes = uniform_bytes.concat(&b_i);
    }
    uniform_bytes.truncate(len_in_bytes)
}

// adapted from bls12-381-hash.rs
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5.3
pub fn ed_hash_to_field(
    msg: &ByteSeq, dst: &ByteSeq, count: usize
) -> Seq<Ed25519FieldElement> {
    let len_in_bytes = count * L; // count * m * L
    let uniform_bytes = expand_message_xmd(msg, dst, len_in_bytes);
    // let uniform_bytes = ByteSeq::from_hex("d620782a206d9de584b74e23ae5ee1db5ca5298b3fc527c4867f049dee6dd419b3674967bd614890f621c128d72269ae");
    let mut output = Seq::<Ed25519FieldElement>::new(count);

    for i in 0..count {
        // m = 1, so no loop
        let elm_offset = L * i; // L * (j + i * m)
        let tv = uniform_bytes.slice(elm_offset, L); //substr(uniform_bytes, elm_offset, L)
        let u_i = Ed25519FieldElement::from_byte_seq_be(
            &EdFieldHash::from_byte_seq_be(&tv).to_byte_seq_be().slice(32,32)); // OS2IP(tv) mod p
        output[i] = u_i;
    }
    output
}

// adapted from bls12-381-hash.rs
fn ed_is_square(x: Ed25519FieldElement) -> bool {
    let c1 = Ed25519FieldElement::from_byte_seq_be(&P_1_2.to_be_bytes()); // (p - 1) / 2
    let tv = x.pow_self(c1);
    tv == Ed25519FieldElement::ZERO() || tv == Ed25519FieldElement::ONE()
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-4.1-5
fn sgn0_m_eq_1(x: Ed25519FieldElement) -> bool {
    x % Ed25519FieldElement::TWO() == Ed25519FieldElement::ONE()
}

// adapted from bls12-381-hash.rs
fn ed_clear_cofactor(x: EdPoint) -> EdPoint {
    point_mul_by_cofactor(x)
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-6.7.1
fn map_to_curve_elligator2(u: Ed25519FieldElement) -> Point {
    let j = Ed25519FieldElement::from_literal(J);
    let k = Ed25519FieldElement::from_literal(K);
    let z = Ed25519FieldElement::from_literal(Z);
    let one = Ed25519FieldElement::ONE();
    let zero = Ed25519FieldElement::ZERO();

    let mut x1 = (zero - j) * (one + (z * u * u)).inv();
    // println!("u: {}", u);
    // println!("uu: {}", (one + (z * u * u)));
    if x1 == zero {
        x1 = zero - j;
    }
    let gx1 = (x1 * x1 * x1) + (j * x1 * x1) + x1;
    // println!("gx1: {}", gx1);
    let x2 = zero - (x1 - j);
    let gx2 = (x2 * x2 * x2) + j * (x2 * x2) + x2;
    let mut x = zero;
    let mut y = zero;
    if ed_is_square(gx1) {
        x = x1;
        // TODO what to do with unwrap?
        y = sqrt(gx1).unwrap();
        if sgn0_m_eq_1(y) {
            y = zero - y;
        }
    } else {
        // println!("square gx1");
        x = x2;
        y = sqrt(gx2).unwrap();
        if !sgn0_m_eq_1(y) {
            y = zero - y;
        }
    }
    let s = x * k;
    let t = y * k;

    // TODO this is stupid
    (X25519FieldElement::from_byte_seq_be(&s.to_byte_seq_be()),
    X25519FieldElement::from_byte_seq_be(&t.to_byte_seq_be()))
}

fn cmov(
    a: Ed25519FieldElement, b: Ed25519FieldElement, c: bool
) -> Ed25519FieldElement {
    if c {
        b
    } else {
        a
    }
}

fn xor(a: bool, b: bool) -> bool {
    if a {
        if b {
            false
        } else {
            true
        }
    } else {
        if b {
            true
        } else {
            false
        }
    }
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#name-elligator-2-method-3
fn map_to_curve_elligator2_straight(u: Ed25519FieldElement) -> Point {
    let j = Ed25519FieldElement::from_literal(J);
    let z = Ed25519FieldElement::from_literal(Z);
    let one = Ed25519FieldElement::ONE();
    let zero = Ed25519FieldElement::ZERO();

    let tv1 = u * u;
    let tv1 = z * tv1;
    let e1 = tv1 == zero - one;
    let tv1 = cmov(tv1, zero, e1);
    let x1 = tv1 + one;
    // println!("x1: {}", x1);
    let x1 = x1.inv();
    // println!("x1': {}", x1);
    let x1 = (zero - j) * x1;
    let gx1 = x1 + j;
    let gx1 = gx1 * x1;
    let gx1 = gx1 + one;
    let gx1 = gx1 * x1;
    let x2 = zero - x1 - j;
    let gx2 = tv1 * gx1;
    let e2 = ed_is_square(gx1);
    let x = cmov(x2, x1, e2);
    let y2 = cmov(gx2, gx1, e2);
    let y = sqrt(y2).unwrap();
    let e3 = sgn0_m_eq_1(y);
    let y = cmov(y, zero - y, xor(e2, e3));
    let s = x;
    let t = y;
    
    (X25519FieldElement::from_byte_seq_be(&s.to_byte_seq_be()),
    X25519FieldElement::from_byte_seq_be(&t.to_byte_seq_be()))
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#appendix-D.1-13
fn monty_to_edw(p: Point) -> EdPoint {
    let (s,t) = p;
    let one = X25519FieldElement::ONE();
    let zero = X25519FieldElement::ZERO();

    let tv1 = s + one;
    let tv2 = tv1 * t;
    let tv2 = tv2.inv();
    let v = tv2 * tv1;
    let v = v * s;
    let w = tv2 * t;
    let tv1 = s - one;
    let mut w = w * tv1;
    let e = tv2 == zero;
    // TODO check if this is constant time implementation
    if e {
        w = one
    }
    
    (Ed25519FieldElement::from_byte_seq_be(&v.to_byte_seq_be()),
    Ed25519FieldElement::from_byte_seq_be(&w.to_byte_seq_be()),
    Ed25519FieldElement::from_byte_seq_be(&one.to_byte_seq_be()),
    Ed25519FieldElement::from_byte_seq_be(&(v * w).to_byte_seq_be()))
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-6.8.2
fn map_to_curve_elligator2_edwards(u: Ed25519FieldElement) -> EdPoint {
    let st = map_to_curve_elligator2_straight(u);
    // monty_to_edw gives the extended homogeneous coordinates
    monty_to_edw(st)
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#name-curve25519-q-5-mod-8-k-1
// NOTE: returns a curve25519 point, even though represented as EdPoint
fn map_to_curve_elligator2_curve25519(u: Ed25519FieldElement) -> EdPoint {
    let j = Ed25519FieldElement::from_literal(J);
    let z = Ed25519FieldElement::from_literal(Z);
    let zero = Ed25519FieldElement::ZERO();
    let one = Ed25519FieldElement::ONE();
    let two = Ed25519FieldElement::TWO();
    
    let c1 = Ed25519FieldElement::from_byte_seq_be(&P_3_8.to_be_bytes());
    let c2 = two.pow_self(c1);
    let c3 = sqrt(zero - one).unwrap();
    let c4 = Ed25519FieldElement::from_byte_seq_be(&P_5_8.to_be_bytes());
    
    let tv1 = u * u;
    let tv1 = two * tv1;
    let xd = tv1 + one;
    let x1n = zero - j;
    let tv2 = xd * xd;
    let gxd = tv2 * xd;
    let gx1 = j * tv1;
    let gx1 = gx1 * x1n;
    let gx1 = gx1 + tv2;
    let gx1 = gx1 * x1n;
    let tv3 = gxd * gxd;
    let tv2 = tv3 * tv3;
    let tv3 = tv3 * gxd;
    let tv3 = tv3 * gx1;
    let tv2 = tv2 * tv3;
    let y11 = tv2.pow_self(c4);
    let y11 = y11 * tv3;
    let y12 = y11 * c3;
    let tv2 = y11 * y11;
    let tv2 = tv2 * gxd;
    let e1 = tv2 == gx1;
    let y1 = cmov(y12, y11, e1);
    let x2n = x1n * tv1;
    let y21 = y11 * u;
    let y21 = y21 * c2;
    let y22 = y21 * c3;
    let gx2 = gx1 * tv1;
    let tv2 = y21 * y21;
    let tv2 = tv2 * gxd;
    let e2 = tv2 == gx2;
    let y2 = cmov(y22, y21, e2);
    let tv2 = y1 * y1;
    let tv2 = tv2 * gxd;
    let e3 = tv2 == gx1;
    let xn = cmov(x2n, x1n, e3);
    let y = cmov(y2, y1, e3);
    let e4 = sgn0_m_eq_1(y);
    let y = cmov(y, zero - y, xor(e3, e4));

    (xn, xd, y, one)
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#name-edwards25519
fn map_to_curve_elligator2_edwards25519(u: Ed25519FieldElement) -> EdPoint {
    let j = Ed25519FieldElement::from_literal(J);
    let zero = Ed25519FieldElement::ZERO();
    let one = Ed25519FieldElement::ONE();
    let two = Ed25519FieldElement::TWO();
    
    let c1 = sqrt(zero - (j + two)).unwrap();
    let (xmn, xmd, ymn, ymd) = map_to_curve_elligator2_curve25519(u);
    let xn = xmn * ymd;
    let xn = xn * c1;
    let xd = xmd * ymn;
    let yn = xmn - xmd;
    let yd = xmn + xmd;
    let tv1 = xd * yd;
    let e = tv1 == zero;
    let xn = cmov(xn, zero, e);
    let xd = cmov(xd, one, e);
    let yn = cmov(yn, one, e);
    let yd = cmov(yd, one, e);

    (xn, xd, yn, yd)
}

//  https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-3
pub fn ed_encode_to_curve(msg: &ByteSeq, dst: &ByteSeq) -> EdPoint {
    let u = ed_hash_to_field(msg, dst, 1);
    let q = map_to_curve_elligator2_edwards25519(u[0]);
    let p = ed_clear_cofactor(q);
    p
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

// QUICKCHECK ==================================================================
    #[derive(Clone, Debug)]
    struct Wrapper(ByteSeq);

    impl Arbitrary for Wrapper {
        fn arbitrary(g: &mut Gen) -> Wrapper {
            const NUM_BYTES: u32 = 64;
            let mut a: [u8; NUM_BYTES as usize] = [0; NUM_BYTES as usize];
            for i in 0..NUM_BYTES as usize {
                a[i] = u8::arbitrary(g);
            }
            Wrapper(Seq::<U8>::from_public_slice(&a))
        }
    }

// Hash to curve tests =========================================================
    #[quickcheck]
    #[ignore]
    fn point_on_curve(msg: Wrapper) -> bool {
        let dst = ByteSeq::from_public_slice(
            b"ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_");
        let dst = dst.concat(&ByteSeq::from_hex("04"));
        let (x, y, z, _) = ed_encode_to_curve(&msg.0, &dst);
        let z_inv = z.inv();
        let x = x * z_inv;
        let y = y * z_inv;
        let d = Ed25519FieldElement::from_hex(
            "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3");
        let lh = (y * y) - (x * x);
        let rh = Ed25519FieldElement::ONE() + (d * x * x * y * y);
        lh == rh
    }

    #[test]
    // #[ignore]
    fn abc_test() {
        let msg = ByteSeq::from_public_slice(b"abc");
        let dst = ByteSeq::from_public_slice(
            b"QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_NU_");
        let u = ed_hash_to_field(&msg, &dst, 1);
        assert_eq!(u[0usize].to_byte_seq_be().to_hex(), 
            "09cfa30ad79bd59456594a0f5d3a76f6b71c6787b04de98be5cd201a556e253b");
        assert_eq!(u[0usize], Ed25519FieldElement::from_hex( 
            "09cfa30ad79bd59456594a0f5d3a76f6b71c6787b04de98be5cd201a556e253b"));
        
        let q = map_to_curve_elligator2_edwards25519(u[0usize]);
        let (qx, qy, qz, _) = q;
        let qz_inv = qz.inv();
        let qx = qx * qz_inv;
        let qy = qy * qz_inv;
        assert_eq!(qx.to_byte_seq_be().to_hex(), "333e41b61c6dd43af220c1ac34a3663e1cf537f996bab50ab66e33c4bd8e4e19");
        assert_eq!(qy.to_byte_seq_be().to_hex(), "51b6f178eb08c4a782c820e306b82c6e273ab22e258d972cd0c511787b2a3443");

        // let (x, y, z, _) = ed_clear_cofactor(q);
        // let z_inv = z.inv();
        // let x = x * z_inv;
        // let y = y * z_inv;
        // let d = Ed25519FieldElement::from_hex(
        //     "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3");
        // let lh = (y * y) - (x * x);
        // let rh = Ed25519FieldElement::ONE() + (d * x * x * y * y);
        // assert_eq!(lh, rh)
    }

    #[test]
    #[ignore]
    fn empty_test() {
        let msg = ByteSeq::from_public_slice(b"");
        let dst = ByteSeq::from_public_slice(
            b"QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_NU_");
        let u = ed_hash_to_field(&msg, &dst, 1);
        assert_eq!(u[0usize].to_byte_seq_be().to_hex(), 
            "7f3e7fb9428103ad7f52db32f9df32505d7b427d894c5093f7a0f0374a30641d");
    }

    #[test]
    #[ignore]
    fn test_g1() {
        let u = Ed25519FieldElement::from_hex("30f037b9745a57a9a2b8a68da81f397c39d46dee9d047f86c427c53f8b29a55c");
        // let ou = ed_hash_to_field(&ByteSeq::from_public_slice(b""), &ByteSeq::from_public_slice(b""), 1);
        // assert_eq!(u, ou[0]);
        let q = map_to_curve_elligator2_edwards(u);
    }
    
}
