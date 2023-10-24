use num_bigint::BigUint;
use std::{ops::Add, str::FromStr};

lazy_static! {
    // This number is the base field of JubJub(elliptic cruve) and refers to the finite field over which the curve is defined
    //
    //
    pub static ref SNARK_SCALAR_FIELD: BigUint = BigUint::from_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"
    )
    .unwrap();
    pub static ref FR_ORDER: BigUint = BigUint::from_str(
        "21888242871839275222246405745257275088614511777268538073601725287587578984328"
    )
    .unwrap();
}

pub struct Field {
    x: BigUint,
    y: BigUint,
}

impl Add for Field {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        todo!()
    }
}
