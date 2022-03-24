use hacspec_lib::*;
use hacspec_ed25519::*;
use hacspec_sha512::*;
use hacspec_curve25519::*;

const B_IN_BYTES: usize = 64;
const S_IN_BYTES: usize = 128;
const L: usize = 64usize;
const J: u128 = 486662u128;
const K: u128 = 1u128;
const Z: u128 = 2u128;

array!(ArrEd25519FieldElement, 4, U64);

// TODO should these be in little endian?
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

// taken from bls12-381-hash.rs
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5.4.1
pub fn expand_message_xmd(msg: &ByteSeq, dst: &ByteSeq, len_in_bytes: usize) -> ByteSeq {
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
    let mut b_i = ByteSeq::from_seq(&hash(&b_0.push(&U8(1u8)).concat(&dst_prime))); // H(b_0 || 1 || dst_prime)
    let mut uniform_bytes = ByteSeq::from_seq(&b_i);
    for i in 2..(ell + 1) {
        let t = ByteSeq::from_seq(&b_0);
        b_i = ByteSeq::from_seq(&hash(&(t ^ b_i).push(&U8_from_usize(i)).concat(&dst_prime))); //H((b_0 ^ b_(i-1)) || 1 || dst_prime)
        uniform_bytes = uniform_bytes.concat(&b_i);
    }
    uniform_bytes.truncate(len_in_bytes)
}

// adapted from bls12-381-hash.rs
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-5.3
pub fn ed_hash_to_field(msg: &ByteSeq, dst: &ByteSeq, count: usize) -> Seq<Ed25519FieldElement> {
    let len_in_bytes = count * L; // count * m * L
    let uniform_bytes = expand_message_xmd(msg, dst, len_in_bytes);
    let mut output = Seq::<Ed25519FieldElement>::new(count);
    for i in 0..count {
        // m = 1, so no loop
        let elm_offset = L * i; // L * (j + i * m)
        let tv = uniform_bytes.slice(elm_offset, L); //substr(uniform_bytes, elm_offset, L)
        let u_i =
            // TODO why does the bls hash, use a bigger canvas?
            Ed25519FieldElement::from_byte_seq_be(&tv); // OS2IP(tv) mod p
            // Ed25519FieldElement::from_byte_seq_be(&FpHash::from_byte_seq_be(&tv).to_byte_seq_be().slice(16, 48)); // OS2IP(tv) mod p
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

// Returns true if x is odd and false otherwise?
// TODO what the fuck
fn ed_sgn0(x: Ed25519FieldElement) -> bool {
    x % Ed25519FieldElement::TWO() == Ed25519FieldElement::ONE()
}

// adapted from bls12-381-hash.rs
fn ed_clear_cofactor(x: EdPoint) -> EdPoint {
    point_mul_by_cofactor(x)
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-6.7.1
// TODO check exceptional case defined in 6.7.1 probably not needed as q=5(mod 8)
// TODO k is equal to one
fn map_to_curve_elligator2(u: Ed25519FieldElement) -> Point {
    let j = Ed25519FieldElement::from_literal(J);
    let k = Ed25519FieldElement::from_literal(K);
    let z = Ed25519FieldElement::from_literal(Z);
    let one = Ed25519FieldElement::ONE();
    let zero = Ed25519FieldElement::ZERO();

    // TODO is this inv okay?
    let mut x1 = zero - (j / k) * (one + z * u * u).inv();
    if x1 == zero {
        x1 = zero - (j / k);
    }
    let gx1 = (x1 * x1 * x1) + (j / k) * (x1 * x1) + (x1 / (k * k));
    let x2 = zero - (x1 - (j / k));
    let gx2 = (x2 * x2 * x2) + (j / k) * (x2 * x2) + (x2 / (k * k));
    let mut x = zero;
    let mut y = zero;
    if ed_is_square(gx1) {
        x = x1;
        // TODO what about the sgn0 function? what does it all mean, the numbers
        // TODO what to do with unwrap?
        y = sqrt(gx1).unwrap();
    } else {
        // sgn0 weirdness still
        x = x2;
        y = sqrt(gx2).unwrap();
    }
    let s = x * k;
    let t = y * k;

    // TODO this is stupid
    (X25519FieldElement::from_byte_seq_le(s.to_byte_seq_le()),
    X25519FieldElement::from_byte_seq_le(t.to_byte_seq_le()))
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#name-mappings-for-montgomery-cur
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
    
    (Ed25519FieldElement::from_byte_seq_le(v.to_byte_seq_le()),
    Ed25519FieldElement::from_byte_seq_le(w.to_byte_seq_le()),
    Ed25519FieldElement::from_byte_seq_le(one.to_byte_seq_le()),
    Ed25519FieldElement::from_byte_seq_le((v * w).to_byte_seq_le()))
}

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-6.8.2
fn map_to_curve_elligator2_edwards(u: Ed25519FieldElement) -> EdPoint {
    let st = map_to_curve_elligator2(u);
    // monty_to_edw gives the extended homogeneous coordinates
    monty_to_edw(st)
}

//  https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-3
pub fn ed_hash_to_curve(msg: &ByteSeq, dst: &ByteSeq) -> EdPoint {
    let u = ed_hash_to_field(msg, dst, 2);
    let q0 = map_to_curve_elligator2_edwards(u[0]);
    let q1 = map_to_curve_elligator2_edwards(u[1]);
    let r = point_add(q0, q1);
    let p = ed_clear_cofactor(r);
    p
}