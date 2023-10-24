use num_bigint::BigInt;
use num_traits::{self, Euclid, One};
use std::{
    ops::{Add, Div, Mul, Sub},
    str::FromStr,
};

lazy_static! {
    // This number is the base field of JubJub (elliptic cruve) and refers to the finite field over which the curve is defined.
    // The operation on the point of the elliptic curve are carried out within this field.
    // This is a large prime that specifies the order of the base field F_Q.
    // The coordinates of points on the Jubjub Elliptic curve are done mudolo this prime number
    pub static ref SNARK_SCALAR_FIELD: BigInt = BigInt::from_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"
    )
    .unwrap();

    // When dealing with cryptographic operations, like point multiplication, you are dealing with scalars.
    // The constant FR_ORDER is the order of the scalar field, a prime number slightly different from SNARK_SCALAR_FIELD
    // It indicates how many different scalars there are in the set that you can use for these cryptographic operations
    pub static ref FR_ORDER: BigInt = BigInt::from_str(
        "21888242871839275222246405745257275088614511777268538073601725287587578984328"
    )
    .unwrap();
}

// Implementation of the base field F_Q.
// It has the form: n mod m.
// m is the field modulus.
pub struct FQ {
    n: BigInt,
    m: BigInt,
}

impl FQ {
    pub fn new(n: BigInt, m: Option<BigInt>) -> Self {
        let modulus = m.unwrap_or_else(|| SNARK_SCALAR_FIELD.clone());

        FQ {
            n: n % &modulus,
            m: modulus,
        }
    }
}

impl Add for FQ {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let new_n = (self.n + rhs.n) % self.m;
        FQ { n: new_n, m: rhs.m }
    }
}

impl Sub for FQ {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let new_n = (self.n - rhs.n).rem_euclid(&self.m); //Solution will always be positive
        FQ { n: new_n, m: rhs.m }
    }
}

impl Mul for FQ {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let new_n = (self.n * rhs.n) % self.m;
        FQ { n: new_n, m: rhs.m }
    }
}

// The division in a finite field acts differently than the usual division operation.
// This can be done through Fermat's Little Thereom, through multiplication of inverse modulo p.
// Fermat little thereom: n(^p-1) = 1 mod p -> n * n^(p-2) = 1 mod p
// So our final calculation looks like this: n1 * n2^(p-2) mod m.
// Where n1 is the number of the first Point and n2 is the number of the second Point.

impl Div for FQ {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let fermat_exponent = &rhs.m - (BigInt::one() + BigInt::one());
        let multiplicative_inverse = rhs.n.modpow(&fermat_exponent, &rhs.m);
        let result = self.n * multiplicative_inverse;
        FQ {
            n: result,
            m: rhs.m,
        }
    }
}
