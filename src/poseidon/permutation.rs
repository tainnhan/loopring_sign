use std::ops::Range;

/*
Implements the Poseidon permutation:

Starkad and Poseidon: New Hash Functions for Zero Knowledge Proof Systems
 - Lorenzo Grassi, Daniel Kales, Dmitry Khovratovich, Arnab Roy, Christian Rechberger, and Markus Schofnegger
 - https://eprint.iacr.org/2019/458.pdf

 The reference implementation in Python from Loopring can be found here:
 - https://github.com/Loopring/hello_loopring/blob/loopring-v3/sdk/ethsnarks/poseidon/permutation.py
 */
use crate::util::errors::PoseidonError;
use blake2b_simd::Params;
use num_bigint::BigInt;
use num_traits::{Euclid, One, Zero};

trait AsBytes {
    fn as_bytes(&self) -> Vec<u8>;
}

impl AsBytes for BigInt {
    fn as_bytes(&self) -> Vec<u8> {
        self.to_bytes_le().1
    }
}

impl AsBytes for &str {
    fn as_bytes(&self) -> Vec<u8> {
        str::as_bytes(self).to_vec()
    }
}

//
// describe the general paramters of poseidon
//
pub struct Poseidon {
    p: BigInt,
    t: usize,
    n_rounds_f: usize,
    n_rounds_p: usize,
    seed: String,
    e: BigInt,
    constants_c: Option<Vec<BigInt>>,
    constants_m: Option<Vec<Vec<BigInt>>>,
    securiy_target: usize,
}

// The 'state' is the internal state that goes thorugh each
// permutation in a sponge function

impl Poseidon {
    pub fn new(
        p: BigInt,
        t: usize,
        n_rounds_f: usize,
        n_rounds_p: usize,
        seed: String,
        e: BigInt,
        mut constants_c: Option<Vec<BigInt>>,
        mut constants_m: Option<Vec<Vec<BigInt>>>,
        securiy_target: usize,
    ) -> Self {
        constants_c.get_or_insert_with(|| {
            Poseidon::poseidon_constants(
                &p,
                &format!("{}_constants", seed),
                &n_rounds_f + &n_rounds_p,
            )
        });
        constants_m
            .get_or_insert_with(|| Self::poseidon_matrix(&p, &format!("{}_matrix_0000", seed), &t));
        Poseidon {
            p,
            t,
            n_rounds_f,
            n_rounds_p,
            seed,
            e,
            constants_c,
            constants_m,
            securiy_target,
        }
    }
    // poseidon
    /*
      Main instansiation of the Poseidon permutation

      The state is `t` elements wide, there are `F` full-rounds
      followed by `P` partial rounds, then `F` full rounds again.

          [    ARK    ]    --,
            | | | | | |       |
          [    SBOX   ]       -  Full Round
            | | | | | |       |
          [    MIX    ]    --`


          [    ARK    ]    --,
            | | | | | |       |
          [    SBOX   ]       -  Partial Round
                      |       |   Only 1 element is substituted in partial round
          [    MIX    ]    --`

      There are F+P rounds for the full permutation.

      You can provide `r = N - 2s` bits of input per round, where `s` is the desired
      security level, in most cases this means you can provide `t-1` inputs with
      appropriately chosen parameters. The permutation can be 'chained' together
      to form a sponge construct.
    */

    pub fn calculate_poseidon(
        &self,
        inputs: Vec<BigInt>,
        chained: bool,
        trace: bool,
    ) -> Result<BigInt, PoseidonError> {
        if inputs.is_empty() {
            return Err(PoseidonError::EmptyInputError);
        }
        // Don't allow inputs to exceed the rate, unless in chained mode
        if !chained && inputs.len() >= self.t {
            return Err(PoseidonError::InputsExceedRate);
        }

        // The state can be thought of as an array or a matrix of numbers.
        // The "width" of the state refers to how many individual elements are in this set.
        // Each element is a piece of data, often fixed-size, and typically these elements are
        // interpreted as integers or binary strings.
        // A wider state (a larger "t") means more data is being processed during each round
        // of the permutation, which might influence the algorithm's overall efficiency and throughput.

        let mut state: Vec<BigInt> = vec![BigInt::zero(); self.t];

        // into_iter consumes the value of the vector and
        // therefore the inputs iter cannot be used anymore

        for (i, input_value) in inputs.into_iter().enumerate() {
            state[i] = input_value;
        }
        // We need to calculate Constant_c and Constants_m now
        if let Some(ref constants) = self.constants_c {
            for (i, constant_c) in constants.into_iter().enumerate() {
                for state_item in &mut state {
                    *state_item += constant_c;
                }
                state = self.poseidon_sbox(state, i);
            }
        }

        Ok(BigInt::one())
    }

    pub fn poseidon_constants(p: &BigInt, seed: &str, n: usize) -> Vec<BigInt> {
        let mut result: Vec<BigInt> = Vec::with_capacity(n);
        let mut current_seed: BigInt = Self::calculate_blake2b::<&str>(&seed);
        result.push(current_seed.clone() % p);

        for _ in 1..n {
            current_seed = Self::calculate_blake2b::<BigInt>(&current_seed);
            result.push(current_seed.clone() % p);
        }
        result
    }

    /*  This matrix will be used for linear transformation (Mixlayer) that applies a systematic, consistent
        transformation to the input input data to produce transformed data.
        This can be visualized as follow:

        [output state] = [matrix] * [input state]

        Poseidon uses the MDS Matrix which can found here:
        iacr.org/2019/458 § 2.3 About the MDS Matrix (pg 8)
        Also:
         - https://en.wikipedia.org/wiki/Cauchy_matrix
    */

    pub fn poseidon_matrix(p: &BigInt, seed: &str, t: &usize) -> Vec<Vec<BigInt>> {
        let c: Vec<BigInt> = Self::poseidon_constants(&p, &seed, t * 2);
        let mut matrix: Vec<Vec<BigInt>> = Vec::new();

        // each element is the modular inverse since cuachy matri is (1/xi-xj)
        // t = 9 -> Means we are creating a 9x9 matrix
        //  return [[pow((c[i] - c[t+j]) % p, p - 2, p) for j in range(t)]
        //         for i in range(t)]
        // c[0] - c[1]
        for i in 0..*t {
            let mut row: Vec<BigInt> = Vec::new();
            for j in 0..*t {
                let base = (&c[i] - &c[t + j]).rem_euclid(p);
                let exponent = p - 2;
                let modular_inverse = base.modpow(&exponent, p);
                row.push(modular_inverse);
            }
            matrix.push(row);
        }
        matrix
    }

    /*
    iacr.org/2019/458 § 2.2 The Hades Strategy (pg 6)

    In more details, assume R_F = 2 · R_f is an even number. Then
    - the first R_f rounds have a full S-Box layer,
    - the middle R_P rounds have a partial S-Box layer (i.e., 1 S-Box layer),
    - the last R_f rounds have a full S-Box layer
    */

    fn poseidon_sbox(&self, mut state: Vec<BigInt>, i: usize) -> Vec<BigInt> {
        let half_f = self.n_rounds_f / 2;

        if i < half_f || i >= half_f + self.n_rounds_p {
            for state_item in &mut state {
                let new_state = state_item.modpow(&self.e, &self.p);
                *state_item = new_state;
            }
        } else {
            state[0] = state[0].modpow(&self.e, &self.p);
        }
        state
    }

    fn poseidon_mix(&self, mut state: Vec<BigInt>) -> Vec<BigInt> {
        Vec::new()
    }

    fn calculate_blake2b<T: AsBytes>(seed: &T) -> BigInt {
        let hash = Params::new()
            .hash_length(32)
            .key(b"")
            .personal(b"")
            .to_state()
            .update(&seed.as_bytes())
            .finalize();
        let result = BigInt::from_bytes_le(num_bigint::Sign::Plus, hash.as_bytes());
        result
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::poseidon::field::SNARK_SCALAR_FIELD;

    use super::*;

    #[test]
    fn test_blake2bhash() {
        let n = BigInt::from_str(
            "14132513739920849383792069751007754351800355055139761101807090020635929082500",
        )
        .unwrap();

        let hash = Poseidon::calculate_blake2b(&n);
        assert_eq!(
            hash,
            BigInt::from_str(
                "2944673226682481007627110343206629017840128596422012786319796010373889882365"
            )
            .unwrap()
        );
    }
    #[test]
    fn test_blake2bhash_str() {
        let hash = Poseidon::calculate_blake2b(&"poseidon_matrix_0000");
        assert_eq!(
            hash,
            BigInt::from_str(
                "14132513739920849383792069751007754351800355055139761101807090020635929082500"
            )
            .unwrap()
        );
    }
    #[test]
    fn test_poseidon_constants() {
        let p = SNARK_SCALAR_FIELD.clone();
        let seed = String::from("poseidon_constants");
        let n = 65;
        let constants_c = Poseidon::poseidon_constants(&p, &seed, 65);

        assert_eq!(
            constants_c[0],
            BigInt::from_str(
                "14397397413755236225575615486459253198602422701513067526754101844196324375522"
            )
            .unwrap()
        );
        assert_eq!(
            constants_c[1],
            BigInt::from_str(
                "10405129301473404666785234951972711717481302463898292859783056520670200613128"
            )
            .unwrap()
        );
        assert_eq!(
            constants_c[2],
            BigInt::from_str(
                "5179144822360023508491245509308555580251733042407187134628755730783052214509"
            )
            .unwrap()
        );
        assert_eq!(
            constants_c[63],
            BigInt::from_str(
                "14423660424692802524250720264041003098290275890428483723270346403986712981505"
            )
            .unwrap()
        );
        assert_eq!(
            constants_c[64],
            BigInt::from_str(
                "10635360132728137321700090133109897687122647659471659996419791842933639708516"
            )
            .unwrap()
        );
    }
    #[test]
    fn test_poseidon_matrix() {
        let seed = "poseidon_matrix_0000";
        let p = SNARK_SCALAR_FIELD.clone();
        let t = 9;
        let constant_m = Poseidon::poseidon_matrix(&p, seed, &t);
        assert_eq!(
            constant_m[0][0],
            BigInt::from_str(
                "16378664841697311562845443097199265623838619398287411428110917414833007677155"
            )
            .unwrap()
        );
        assert_eq!(
            constant_m[0][1],
            BigInt::from_str(
                "12968540216479938138647596899147650021419273189336843725176422194136033835172"
            )
            .unwrap()
        );
        assert_eq!(
            constant_m[0][2],
            BigInt::from_str(
                "3636162562566338420490575570584278737093584021456168183289112789616069756675"
            )
            .unwrap()
        );
        assert_eq!(
            constant_m[1][3],
            BigInt::from_str(
                "8642889650254799419576843603477253661899356105675006557919250564400804756641"
            )
            .unwrap()
        );
        assert_eq!(
            constant_m[8][8],
            BigInt::from_str(
                "11398590172899810645820530606484864595574598270604175688862890426075002823331"
            )
            .unwrap()
        );
    }
}
// #[cfg(test)]
// mod tests {

//     use super::*;

//     #[test]
