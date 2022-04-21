#[cfg(not(feature = "hacspec"))]
extern crate hacspec_lib;

#[cfg(feature = "hacspec")]
use hacspec_attributes::*;

#[cfg(not(feature = "hacspec"))]
extern crate creusot_contracts;
#[cfg(not(feature = "hacspec"))]
pub use creusot_contracts::*;

pub use hacspec_lib::*;

#[trusted]
fn trusted_super_oracle() -> u32 {
    return 42u32
}

#[ensures(result == 42u32)]
fn the_answer() -> u32 {
    trusted_super_oracle()
}