use hacspec_lib::*;
use rsa::*;
use hacspec_sha256::*;

pub type BoolResult = Result<bool, Error>;

// TODO check if we should include mgf_salt
pub fn prove(sk: SK, alpha: &ByteSeq) -> ByteSeqResult {
    let mgf_domain_separator = ByteSeq::from_hex("01");
    // Add suite string when suite stuff is done, MGF salt stuff
    // let mgf_salt = ByteSeq::from_hex("01")
    // Do proper k value
    let em = mgf1(&mgf_domain_separator.concat(alpha), 128 - 1)?;
    let m = os2ip(&em);
    let s = rsasp1(sk, m)?;
    i2osp(s, 128)
}

pub fn proof_to_hash(pi_string: &ByteSeq) -> ByteSeq {
    let proof_to_hash_domain_separator = ByteSeq::from_hex("02");
    let sha_digest = sha256(&proof_to_hash_domain_separator.concat(pi_string));
    // TODO this is stupid
    let empty = ByteSeq::new(0);
    empty.concat(&sha_digest)
}

// TODO check if we should include mgf_salt
pub fn verify(pk: PK, alpha: &ByteSeq, pi_string: &ByteSeq) -> BoolResult {
    let s = os2ip(pi_string);
    // Check if signature representative is out of range
    let m = rsavp1(pk, s)?;
    let mgf_domain_separator = ByteSeq::from_hex("01");
    // TODO add all the correct string things
    let em = mgf1(&mgf_domain_separator.concat(alpha), 128 - 1)?;
    let new_m = os2ip(&em);
    // TODO do proper return type as in spec
    BoolResult::Ok(m == new_m)
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
