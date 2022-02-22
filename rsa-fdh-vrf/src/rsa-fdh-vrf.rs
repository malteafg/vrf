use hacspec_lib::*;
use rsa::*;

// TODO check if we should include mgf_salt
pub fn prove(n: usize, e: usize, alpha: &ByteSeq) -> ByteSeq {
    unimplemented!()
}

pub fn proof_to_hash(pi: &ByteSeq) -> ByteSeq {
    unimplemented!()
}

// TODO check if we should include mgf_salt
pub fn verify(n: usize, d: usize, alpha: &ByteSeq, pi: &ByteSeq) -> bool {
    unimplemented!()
}

// TODO check what we should do for the ciphersuites (different hash functions)

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
