/*
Implements Pure-EdDSA and Hash-EdDSA

The signer has two secret values:

    * k = Secret key
    * r = Per-(message,key) nonce

The signer provides a signature consiting of two values:

    * R = Point, image of `r*B`
    * s = Image of `r + (k*t)`

The signer provides the verifier with their public key:

    * A = k*B

Both the verifier and the signer calculate the common reference string:

    * t = H(R, A, M)

The nonce `r` is secret, and protects the value `s` from revealing the
signers secret key.

For Hash-EdDSA, the message `M` is compressed before H(R,A,M)

For further information see: https://ed2519.cr.yp.to/eddsa-20150704.pdf
*/

use super::{
    field::{FQ, SNARK_SCALAR_FIELD},
    jubjub::{Point, JUBJUB_L},
};
use crate::util::helpers::{generate_signature_base_string, sha256_snark, to_bytes_32};
use num_bigint::{BigInt, Sign};
use num_traits::{Num, Zero};
use sha2::{Digest, Sha512};
pub struct Signature {
    R: Point,
    s: FQ,
}

impl Signature {
    pub fn new(R: Point, s: FQ) -> Self {
        Signature { R, s }
    }

    pub fn to_string(self) -> String {
        format!("{} {} {}", &self.R.x().n(), &self.R.y().n(), &self.s.n())
    }
}

pub struct SignatureScheme;

impl SignatureScheme {
    // The variable B
    pub fn base_point() -> Point {
        Point::generate()
    }

    pub fn sign(private_key: BigInt, hash: BigInt) {
        let base_point = Self::base_point();

        let a = base_point * private_key.clone();
        let m = hash;
        let r = Self::hash_secret(FQ::new(private_key), m);
    }

    /*
    Hash the key and message to create `r`, the blinding factor for this signature.

    If the same `r` value is used more than once, the key for the signature is revealed.

    From: https://eprint.iacr.org/2015/677.pdf (EdDSA for more curves)

    Page 3:

        (Implementation detail: To save time in the computation of `rB`, the signer
        can replace `r` with `r mod L` before computing `rB`.)
    */

    fn hash_secret(k: FQ, arg: BigInt) -> BigInt {
        let mut key_bytes = to_bytes_32(k.n());
        let hash_bytes = to_bytes_32(&arg);
        key_bytes.extend(hash_bytes);

        let mut hasher = Sha512::new();
        hasher.update(key_bytes);
        let hash = BigInt::from_bytes_le(Sign::Plus, &hasher.finalize()[..]);

        hash % JUBJUB_L.clone()
    }
}

pub fn generate_eddsa_signature(
    request_type: &str,
    url: &str,
    data: &[(&str, &str)],
    hex_private_key: &str,
) {
    let signature_base = generate_signature_base_string(request_type, url, data);
    let hash = sha256_snark(&signature_base);

    let private_key_big_int =
        match BigInt::from_str_radix(hex_private_key.trim_start_matches("0x"), 16) {
            Ok(value) => value,
            Err(_) => BigInt::zero(),
        };

    SignatureScheme::sign(private_key_big_int, hash)
}

#[cfg(test)]
mod tests {
    use num_traits::One;
    use std::str::FromStr;

    use super::*;
    #[test]
    fn hash_secret_test() {
        let k = FQ::new(BigInt::one());
        let arg = BigInt::from_str(
            "20693456676802104653139582814194312788878632719314804297029697306071204881418",
        )
        .unwrap();

        let result = SignatureScheme::hash_secret(k, arg);
        assert_eq!(
            result,
            BigInt::from_str(
                "456425617452149303537516185998917840598824274191970480768523181450944242406"
            )
            .unwrap()
        );
    }
}
