/*
Implements the Poseidon permutation:

Starkad and Poseidon: New Hash Functions for Zero Knowledge Proof Systems
 - Lorenzo Grassi, Daniel Kales, Dmitry Khovratovich, Arnab Roy, Christian Rechberger, and Markus Schofnegger
 - https://eprint.iacr.org/2019/458.pdf

 The reference implementation in Python from Loopring can be found here:
 - https://github.com/Loopring/hello_loopring/blob/loopring-v3/sdk/ethsnarks/poseidon/permutation.py
 */
use crate::util::errors::PoseidonError;
use blake2b_simd::{Hash, Params};
use num_bigint::BigInt;
use num_traits::{FromPrimitive, One};

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
    constants_m: Option<Vec<BigInt>>,
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
        mut constants_m: Option<Vec<BigInt>>,
        securiy_target: usize,
    ) -> Self {
        constants_c.get_or_insert_with(|| Poseidon::poseidon_constants());
        constants_m.get_or_insert_with(|| Poseidon::poseidon_matrix());
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

    pub fn calculate_blake2b(seed: String) -> Hash {
        let hash = Params::new()
            .hash_length(32)
            .key(b"")
            .personal(b"")
            .to_state()
            .update(seed.as_bytes())
            .finalize();
        hash
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

        //let state: Vec<BigInt>

        Ok(BigInt::one())
    }

    pub fn poseidon_constants() -> Vec<BigInt> {
        Vec::new()
    }

    pub fn poseidon_matrix() -> Vec<BigInt> {
        Vec::new()
    }
}
