use hacspec_lib::*;

pub fn i2osp(x: usize, x_len: usize) -> ByteSeq {
    unimplemented!();
}

pub fn os2ip(x: &ByteSeq) -> usize {
    unimplemented!();
}

pub fn mgf1(mgf_seed: &ByteSeq, mask_len: &ByteSeq) -> ByteSeq {
    unimplemented!();
}

pub fn rsaep(n: usize, e: usize, m: usize) -> usize {
    unimplemented!();
}

pub fn rsadp(n: usize, d: usize, c: usize) -> usize {
    unimplemented!();
}

pub fn rsasp1(n: usize, d: usize, m: usize) -> usize {
    unimplemented!()
}

pub fn rsavp1(n: usize, e: usize, s: usize) -> usize {
    unimplemented!()
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

    #[test]
    fn i2os2i() {
        unimplemented!()
    }

    #[test]
    fn os2i2os() {
        unimplemented!()
    }

    #[test]
    fn rsaeprsadp() {
        unimplemented!()
    }

    // perhaps check properties on the numbers of rsa keys
}
