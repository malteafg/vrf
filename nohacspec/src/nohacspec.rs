extern crate creusot_contracts;
pub use creusot_contracts::*;
pub use creusot_contracts::ensures;


#[ensures(result == 42u32)]
fn the_answer() -> u32 {
    return 42u32
}

#[ensures(if c {result == b} else {result == a})]
#[ensures(a == a)]
fn cmov(
    a: u32, b: u32, c: bool
) -> u32 {
    if c {
        b
    } else {
        a
    }
}
