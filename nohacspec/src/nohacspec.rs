extern crate creusot_contracts;
pub use creusot_contracts::*;
pub use creusot_contracts::ensures;


#[ensures(result == 42u32)]
fn the_answer() -> u32 {
    return 42u32
}

#[predicate]
fn sum_one(a: u32, b: u32) -> bool {
    a + b > b
}

#[ensures(if c {result == b} else {result == a})]
#[ensures(a == a)]
#[ensures(sum_one(a,b))]
fn cmov(
    a: u32, b: u32, c: bool
) -> u32 {
    if c {
        b
    } else {
        a
    }
}
