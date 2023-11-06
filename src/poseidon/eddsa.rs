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

use std::fmt::format;

use super::{
    field::{FQ, SNARK_SCALAR_FIELD},
    jubjub::{Point, JUBJUB_E, JUBJUB_L},
    permutation::{self, Poseidon},
};
use crate::util::helpers::{generate_signature_base_string, sha256_snark, to_bytes_32};
use num_bigint::{BigInt, Sign};
use num_traits::{sign, Num, Zero};
use sha2::{Digest, Sha512};

pub struct Signature {
    R: Point,
    s: FQ,
}

impl Signature {
    pub fn new(R: Point, s: FQ) -> Self {
        Signature { R, s }
    }

    pub fn to_string(&self) -> String {
        format!("{} {} {}", &self.R.x().n(), &self.R.y().n(), &self.s.n())
    }
}

pub struct SignedMessage {
    A: Point,
    sig: Signature,
    msg: BigInt,
}

impl SignedMessage {
    pub fn new(A: Point, sig: Signature, msg: BigInt) -> Self {
        SignedMessage { A, sig, msg }
    }

    pub fn to_string(&self) -> String {
        format!(
            "{} {} {} {}",
            self.A.x().n(),
            self.A.y().n(),
            self.sig.to_string(),
            self.msg
        )
    }
}
pub struct SignatureScheme;

impl SignatureScheme {
    // The variable B
    pub fn base_point() -> Point {
        Point::generate()
    }

    pub fn sign(private_key: BigInt, hash: BigInt) -> SignedMessage {
        let base_point = Self::base_point();

        let A = &base_point * &private_key; // A = k * P -> Public key

        let M = hash.clone(); // prehash message
        let r = Self::hash_secret(FQ::new(private_key.clone()), &M);

        let R = &base_point * &r;

        let t = Self::hash_public(&R, &A, M);
        let S = (r + (private_key * t)) % JUBJUB_E.clone();

        let signature_result = Signature::new(R, FQ::new(S));

        let signed_message = SignedMessage::new(A, signature_result, hash);

        //let signature_result = Sig
        signed_message
    }

    /*
    Hash the key and message to create `r`, the blinding factor for this signature.

    If the same `r` value is used more than once, the key for the signature is revealed.

    From: https://eprint.iacr.org/2015/677.pdf (EdDSA for more curves)

    Page 3:

        (Implementation detail: To save time in the computation of `rB`, the signer
        can replace `r` with `r mod L` before computing `rB`.)
    */

    fn hash_secret(k: FQ, arg: &BigInt) -> BigInt {
        let mut key_bytes = to_bytes_32(k.n());
        let hash_bytes = to_bytes_32(&arg);
        key_bytes.extend(hash_bytes);

        let mut hasher = Sha512::new();
        hasher.update(key_bytes);
        let hash = BigInt::from_bytes_le(Sign::Plus, &hasher.finalize()[..]);

        hash % JUBJUB_L.clone()
    }

    fn hash_public(R: &Point, A: &Point, M: BigInt) -> BigInt {
        let mut input: Vec<BigInt> = Vec::new();
        input.extend(R.as_scalar());
        input.extend(A.as_scalar());
        input.extend(vec![M]);

        let poseidon = Poseidon::new(
            SNARK_SCALAR_FIELD.clone(),
            6,
            6,
            52,
            format!("poseidon"),
            BigInt::from(5),
            None,
            None,
            128,
        );

        poseidon.calculate_poseidon(input).unwrap()
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

    SignatureScheme::sign(private_key_big_int, hash);
    ()
}

#[cfg(test)]
mod tests {
    use num_traits::One;
    use std::{str::FromStr, time::Instant};

    use super::*;
    #[test]
    fn hash_secret_test() {
        let k = FQ::new(BigInt::one());
        let arg = BigInt::from_str(
            "20693456676802104653139582814194312788878632719314804297029697306071204881418",
        )
        .unwrap();

        let result = SignatureScheme::hash_secret(k, &arg);
        assert_eq!(
            result,
            BigInt::from_str(
                "456425617452149303537516185998917840598824274191970480768523181450944242406"
            )
            .unwrap()
        );
    }

    #[test]
    fn hash_public_test() {
        let R = Point::new(
            FQ::new(
                BigInt::from_str(
                    "4991609103248925747358645194965349262579784734809679007552644294476920671344",
                )
                .unwrap(),
            ),
            FQ::new(
                BigInt::from_str(
                    "423391641476660815714427268720766993055332927752794962916609674122318189741",
                )
                .unwrap(),
            ),
        );

        let A = Point::new(
            FQ::new(
                BigInt::from_str(
                    "16540640123574156134436876038791482806971768689494387082833631921987005038935",
                )
                .unwrap(),
            ),
            FQ::new(
                BigInt::from_str(
                    "20819045374670962167435360035096875258406992893633759881276124905556507972311",
                )
                .unwrap(),
            ),
        );

        let M = BigInt::from_str(
            "20693456676802104653139582814194312788878632719314804297029697306071204881418",
        )
        .unwrap();

        let result = SignatureScheme::hash_public(&R, &A, M);

        assert_eq!(
            result,
            BigInt::from_str(
                "4221734722145693593102605227029250076638572186265556559955657451417362287555"
            )
            .unwrap()
        );
    }

    #[test]
    fn sign_test() {
        let msg_hash = BigInt::from_str(
            "20693456676802104653139582814194312788878632719314804297029697306071204881418",
        )
        .unwrap();
        let private_key = BigInt::from(1);
        let start = Instant::now();

        let signed = SignatureScheme::sign(private_key, msg_hash);
        let duration = start.elapsed();
        println!("{}", duration.as_secs());
        assert_eq!(signed.to_string(), "16540640123574156134436876038791482806971768689494387082833631921987005038935 20819045374670962167435360035096875258406992893633759881276124905556507972311 4991609103248925747358645194965349262579784734809679007552644294476920671344 423391641476660815714427268720766993055332927752794962916609674122318189741 4678160339597842896640121413028167917237396460457527040724180632868306529961 20693456676802104653139582814194312788878632719314804297029697306071204881418" )
    }
}
