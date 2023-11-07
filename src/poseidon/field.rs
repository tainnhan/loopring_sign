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
    pub fn n(&self) -> &BigInt {
        &self.n
    }
    pub fn m(&self) -> &BigInt {
        &self.m
    }

    pub fn new(n: BigInt) -> Self {
        Self::with_modulus(n, SNARK_SCALAR_FIELD.clone())
    }

    pub fn with_modulus(n: BigInt, m: BigInt) -> Self {
        FQ { n: n % &m, m: m }
    }

    pub fn one() -> Self {
        FQ {
            n: BigInt::from(1),
            m: SNARK_SCALAR_FIELD.clone(),
        }
    }

    pub fn zero() -> Self {
        FQ {
            n: BigInt::from(0),
            m: SNARK_SCALAR_FIELD.clone(),
        }
    }
    fn addition(n1: &BigInt, n2: &BigInt, modulus: &BigInt) -> Self {
        let new_n = (n1 + n2) % modulus;
        FQ {
            n: new_n,
            m: modulus.clone(),
        }
    }

    fn subtract(n1: &BigInt, n2: &BigInt, m: &BigInt) -> Self {
        let new_n = (n1 - n2).rem_euclid(m);
        FQ {
            n: new_n,
            m: m.clone(),
        }
    }

    fn multiply(n1: &BigInt, n2: &BigInt, modulus: &BigInt) -> Self {
        let new_n = (n1 * n2) % modulus;
        FQ {
            n: new_n,
            m: modulus.clone(),
        }
    }

    // The division in a finite field acts differently than the usual division operation.
    // This can be done through Fermat's Little Thereom, through multiplication of inverse modulo p.
    // Fermat little thereom: n(^p-1) = 1 mod p -> n * n^(p-2) = 1 mod p
    // So our final calculation looks like this: n1 * n2^(p-2) mod m.
    // Where n1 is the number of the first Point and n2 is the number of the second Point.

    fn divide(n: &BigInt, m: &BigInt, rhs_n: &BigInt, rhs_m: &BigInt) -> Self {
        let fermat_exponent = rhs_m - (BigInt::one() + BigInt::one());
        let multiplicative_inverse: BigInt = rhs_n.modpow(&fermat_exponent, rhs_m);
        let result = (n * multiplicative_inverse) % m;

        FQ {
            n: result,
            m: m.clone(),
        }
    }
}
impl Add for FQ {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        FQ::addition(&self.n, &rhs.n, &self.m)
    }
}
impl<'a, 'b> Add<&'b FQ> for &'a FQ {
    type Output = FQ;

    fn add(self, rhs: &'b FQ) -> FQ {
        FQ::addition(&self.n, &rhs.n, &self.m)
    }
}
impl<'a> Add<&'a FQ> for FQ {
    type Output = FQ;

    fn add(self, rhs: &'a FQ) -> Self::Output {
        FQ::addition(&self.n, &rhs.n, &self.m)
    }
}

impl<'a> Add<FQ> for &'a FQ {
    type Output = FQ;

    fn add(self, rhs: FQ) -> Self::Output {
        FQ::addition(&self.n, &rhs.n, &self.m)
    }
}

impl Sub for FQ {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        FQ::subtract(&self.n, &rhs.n, &self.m)
    }
}

impl<'a, 'b> Sub<&'b FQ> for &'a FQ {
    type Output = FQ;

    fn sub(self, rhs: &'b FQ) -> Self::Output {
        FQ::subtract(&self.n, &rhs.n, &self.m)
    }
}

impl<'a> Sub<&'a FQ> for FQ {
    type Output = FQ;
    fn sub(self, rhs: &'a FQ) -> Self::Output {
        FQ::subtract(&self.n, &rhs.n, &self.m)
    }
}
impl<'a> Sub<FQ> for &'a FQ {
    type Output = FQ;
    fn sub(self, rhs: FQ) -> Self::Output {
        FQ::subtract(&self.n, &rhs.n, &self.m)
    }
}

impl Mul for FQ {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        FQ::multiply(&self.n, &rhs.n, &self.m)
    }
}
impl<'a, 'b> Mul<&'b FQ> for &'a FQ {
    type Output = FQ;

    fn mul(self, rhs: &'b FQ) -> Self::Output {
        FQ::multiply(&self.n, &rhs.n, &self.m)
    }
}

impl<'a> Mul<&'a FQ> for FQ {
    type Output = FQ;

    fn mul(self, rhs: &'a FQ) -> Self::Output {
        FQ::multiply(&self.n, &rhs.n, &self.m)
    }
}

impl<'a> Mul<FQ> for &'a FQ {
    type Output = FQ;
    fn mul(self, rhs: FQ) -> Self::Output {
        FQ::multiply(&self.n, &rhs.n, &self.m)
    }
}

impl Div for FQ {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        FQ::divide(&self.n, &self.m, &rhs.n, &rhs.m)
    }
}

impl<'a, 'b> Div<&'b FQ> for &'a FQ {
    type Output = FQ;

    fn div(self, rhs: &'b FQ) -> Self::Output {
        FQ::divide(&self.n, &self.m, &rhs.n, &rhs.m)
    }
}

impl<'a> Div<&'a FQ> for FQ {
    type Output = FQ;
    fn div(self, rhs: &'a FQ) -> Self::Output {
        FQ::divide(&self.n, &self.m, &rhs.n, &rhs.m)
    }
}

impl<'a> Div<FQ> for &'a FQ {
    type Output = FQ;
    fn div(self, rhs: FQ) -> Self::Output {
        FQ::divide(&self.n, &self.m, &rhs.n, &rhs.m)
    }
}

impl Clone for FQ {
    fn clone(&self) -> Self {
        Self {
            n: self.n.clone(),
            m: self.m.clone(),
        }
    }

    fn clone_from(&mut self, source: &Self) {
        *self = source.clone()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn field_addition() {
        let n1 = BigInt::from_str(
            "16975020951829843291561856284829257584634286376639034318405002894754175986822",
        )
        .unwrap();
        let n2 = BigInt::from_str(
            "64019726205844806607227168444173457603185468776494125031546307012808629654",
        )
        .unwrap();

        let field_1 = FQ::new(n1);
        let field_2 = FQ::new(n2);
        let result = field_1.add(field_2);
        let real_result = BigInt::from_str(
            "17039040678035688098169083453273431042237471845415528443436549201766984616476",
        )
        .unwrap();
        assert_eq!(result.n, real_result);
    }
    #[test]
    fn field_subraction() {
        let n1 = BigInt::from_str(
            "16975020951829843291561856284829257584634286376639034318405002894754175986822",
        )
        .unwrap();
        let n2 = BigInt::from_str(
            "64019726205844806607227168444173457603185468776494125031546307012808629654",
        )
        .unwrap();

        let field_1 = FQ::new(n1);
        let field_2 = FQ::new(n2);

        let result_1 = field_1.clone().sub(field_2.clone());
        let result_2 = field_2.clone().sub(field_1.clone());

        assert_eq!(
            result_1.n,
            BigInt::from_str(
                "16911001225623998484954629116385084127031100907862540193373456587741367357168",
            )
            .unwrap()
        );

        assert_eq!(
            result_2.n,
            BigInt::from_str(
                "4977241646215276737291776628872190961517263492553494150324747598834441138449",
            )
            .unwrap()
        )
    }

    #[test]
    fn field_multiplication() {
        let n1 = BigInt::from_str(
            "16975020951829843291561856284829257584634286376639034318405002894754175986822",
        )
        .unwrap();
        let n2 = BigInt::from_str(
            "64019726205844806607227168444173457603185468776494125031546307012808629654",
        )
        .unwrap();
        let n3 = BigInt::from_str(
            "8023312754331632317345164874475855606161388395970421403351236980717209379200",
        )
        .unwrap();

        let field_1 = FQ::new(n1);
        let field_2 = FQ::new(n2);
        let field_3 = FQ::new(n3);

        let result_1 = field_1.clone().mul(field_2.clone()).mul(field_3.clone());
        let result_2 = field_1.clone().mul(field_3.clone());

        assert_eq!(
            result_1.n,
            BigInt::from_str(
                "18182554182870232023808950424673874478127155834326600840622566402557800401919"
            )
            .unwrap()
        );

        assert_eq!(
            result_2.n,
            BigInt::from_str(
                "7078307911818432186422689430568175567157289995259698798344014234848622444761"
            )
            .unwrap()
        );
    }

    #[test]
    fn field_division() {
        let n1 = BigInt::from_str(
            "16975020951829843291561856284829257584634286376639034318405002894754175986822",
        )
        .unwrap();
        let n2 = BigInt::from_str(
            "64019726205844806607227168444173457603185468776494125031546307012808629654",
        )
        .unwrap();
        let n3 = BigInt::from_str(
            "8023312754331632317345164874475855606161388395970421403351236980717209379200",
        )
        .unwrap();

        let field_1 = FQ::new(n1);
        let field_2 = FQ::new(n2);
        let field_3 = FQ::new(n3);

        let result1 = field_1.clone().div(field_2.clone());
        let result2 = field_2.clone().div(field_1.clone());
        let result3 = field_3.clone().div(field_2.clone()).div(field_1.clone());

        assert_eq!(
            result1.n,
            BigInt::from_str(
                "9916021784047275937858878444139751840705039734455470105457699170412095765019"
            )
            .unwrap()
        );

        assert_eq!(
            result2.n,
            BigInt::from_str(
                "4046019741176394233170180050870245201959085245483667903544123842500354019676"
            )
            .unwrap()
        );

        assert_eq!(result3.n, BigInt::from_str("1").unwrap());
    }
}
