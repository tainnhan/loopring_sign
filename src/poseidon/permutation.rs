/*
Implements the Poseidon permutation:

Starkad and Poseidon: New Hash Functions for Zero Knowledge Proof Systems
 - Lorenzo Grassi, Daniel Kales, Dmitry Khovratovich, Arnab Roy, Christian Rechberger, and Markus Schofnegger
 - https://eprint.iacr.org/2019/458.pdf

 The reference implementation in Python from Loopring can be found here:
 - https://github.com/Loopring/hello_loopring/blob/loopring-v3/sdk/ethsnarks/poseidon/permutation.py
 */
use blake2b_simd::{Hash, Params};
use num_bigint::BigUint;

//
// describe the general paramters of poseidon
//
pub struct Poseidon {
    pub p: BigUint,
    pub t: u32,
    pub n_rounds_f: u32,
    pub n_rounds_p: u32,
    pub seed: String,
    pub e: BigUint,
    pub constants_c: Vec<BigUint>,
    pub constants_m: Vec<BigUint>,
    pub securiy_target: u32,
}

// The 'state' is the internal state that goes thorugh each
// permutation in a sponge function
pub struct Permutation;

impl Permutation {
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
}
