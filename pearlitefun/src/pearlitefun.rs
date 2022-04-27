#[cfg(not(feature = "hacspec"))]
extern crate hacspec_lib;

#[cfg(feature = "hacspec")]
use hacspec_attributes::*;

#[cfg(not(feature = "hacspec"))]
extern crate creusot_contracts;
#[cfg(not(feature = "hacspec"))]
pub use creusot_contracts::*;

pub use hacspec_lib::*;

public_nat_mod!(
    type_name: Ed25519FieldElement,
    type_of_canvas: FieldCanvas,
    bit_size_of_field: 256,
    modulo_value: "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
);

#[ensures(result == 42u32)]
fn the_answer() -> u32 {
    return 42u32
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