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
    jubjub::{Point, JUBJUB_E, JUBJUB_L},
    permutation::Poseidon,
};
use crate::util::helpers::{generate_signature_base_string, sha256_snark, to_bytes_32};
use num_bigint::{BigInt, Sign};
use num_traits::{Num, Zero};
use sha2::{Digest, Sha512};

pub struct Signature {
    image_of_r: Point,
    s: FQ,
}

impl Signature {
    pub fn image_of_r(&self) -> &Point {
        &self.image_of_r
    }

    pub fn s(&self) -> &FQ {
        &self.s
    }

    pub fn new(image_of_r: Point, s: FQ) -> Self {
        Signature { image_of_r, s }
    }

    pub fn to_string(&self) -> String {
        format!(
            "{} {} {}",
            &self.image_of_r.x().n(),
            &self.image_of_r.y().n(),
            &self.s.n()
        )
    }
}

pub struct SignedMessage {
    public_key: Point,
    sig: Signature,
    msg: BigInt,
}

impl SignedMessage {
    pub fn public_key(&self) -> &Point {
        &self.public_key
    }
    pub fn sig(&self) -> &Signature {
        &self.sig
    }

    pub fn msg(&self) -> &BigInt {
        &self.msg
    }

    pub fn new(public_key: Point, sig: Signature, msg: BigInt) -> Self {
        SignedMessage {
            public_key,
            sig,
            msg,
        }
    }

    pub fn to_string(&self) -> String {
        format!(
            "{} {} {} {}",
            self.public_key.x().n(),
            self.public_key.y().n(),
            self.sig.to_string(),
            self.msg
        )
    }

    pub fn to_hex(&self) -> String {
        let r_x_hex = format!("{:0>64}", self.sig().image_of_r().x().n().to_str_radix(16));
        let r_y_hex: String = format!("{:0>64}", self.sig().image_of_r().y().n().to_str_radix(16));
        let s_hex: String = format!("{:0>64}", self.sig().s().n().to_str_radix(16));
        format!("0x{}{}{}", r_x_hex, r_y_hex, s_hex)
    }
}
pub struct SignatureScheme;

impl SignatureScheme {
    // The variable B
    pub fn base_point() -> Point {
        Point::generate()
    }

    pub fn sign(private_key_scalar: BigInt, hash: BigInt) -> SignedMessage {
        let base_point = Self::base_point();

        let public_key = &base_point * &private_key_scalar; // A = k * P -> Public key

        let message = hash.clone(); // prehash message
        let r = Self::hash_secret(FQ::new(private_key_scalar.clone()), &message);

        let image_of_r = &base_point * &r;

        let t = Self::hash_public(&image_of_r, &public_key, message);
        let signature = (r + (private_key_scalar * t)) % &*JUBJUB_E;

        let signature_result = Signature::new(image_of_r, FQ::new(signature));

        let signed_message = SignedMessage::new(public_key, signature_result, hash);

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

    fn hash_public(image_of_r: &Point, public_key: &Point, message: BigInt) -> BigInt {
        let mut input: Vec<BigInt> = Vec::new();
        input.extend(image_of_r.as_scalar());
        input.extend(public_key.as_scalar());
        input.extend(vec![message]);

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
) -> String {
    let signature_base = generate_signature_base_string(request_type, url, data);
    let hash = sha256_snark(&signature_base);

    let private_key_big_int =
        match BigInt::from_str_radix(hex_private_key.trim_start_matches("0x"), 16) {
            Ok(value) => value,
            Err(_) => BigInt::zero(),
        };

    let signed_message = SignatureScheme::sign(private_key_big_int, hash);

    signed_message.to_hex()
}

pub fn get_eddsa_sig_with_poseidon(inputs: Vec<BigInt>, private_key: String) -> String {
    let p = SNARK_SCALAR_FIELD.clone();
    let poseidon = Poseidon::new(
        p,
        inputs.len() + 1,
        6,
        53,
        "poseidon".to_string(),
        BigInt::from(5),
        None,
        None,
        128,
    );

    let hash = poseidon.calculate_poseidon(inputs).unwrap();

    let private_key_big_int = match BigInt::from_str_radix(private_key.trim_start_matches("0x"), 16)
    {
        Ok(value) => value,
        Err(_) => BigInt::zero(),
    };

    let result = SignatureScheme::sign(private_key_big_int, hash);
    result.to_hex()
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
        let image_of_r = Point::new(
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

        let public_key = Point::new(
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

        let message = BigInt::from_str(
            "20693456676802104653139582814194312788878632719314804297029697306071204881418",
        )
        .unwrap();

        let result = SignatureScheme::hash_public(&image_of_r, &public_key, message);

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
    #[test]
    fn sign_test_2() {
        let key = BigInt::from_str(
            "1965533437444427599736796973543479035828634172708055838572430750620147597402",
        )
        .unwrap();

        let msg = BigInt::from_str(
            "20823375595941673465102915960468301465677704522962441935281926279865178787657",
        )
        .unwrap();
        let signed = SignatureScheme::sign(key, msg);
        assert_eq!(
            *signed.sig().image_of_r().x().n(),
            BigInt::from_str(
                "2114973053955517366033592592501464590076342821657201629830614924692550700766"
            )
            .unwrap()
        );
        assert_eq!(
            *signed.sig().image_of_r().y().n(),
            BigInt::from_str(
                "6713953096854639492359183468711112854151280690992619923536842965423886430417"
            )
            .unwrap()
        );
        assert_eq!(
            *signed.sig().s().n(),
            BigInt::from_str(
                "21100876117443371431735908718802018647851328087147897184613053393129281831653"
            )
            .unwrap()
        );
    }
    #[test]
    fn generate_eddsa_test() {
        let l2_key = "0x087d254d02a857d215c4c14d72521f8ab6a81ec8f0107eaf16093ebb7c70dc50";
        let data: &[(&str, &str)] = &[("accountId", "12345")];
        let request_type = "POST";
        let url = "https://api3.loopring.io/api/v3/apiKey";

        let result = generate_eddsa_signature(request_type, url, data, l2_key);
        assert_eq!(result.as_str(), "0x15fdcda3ca2965d2ae43739cc6740e50c08d3f756c6161bcedb10fbc05290e000f3bc31e2293ba91ca7ac55cd20a86ae3541d3dfed63896cd474015ec60b8d40274f98b2d0a87ebf8cd0ee16dc9ec953a229cf0d6b2b61867ca80ba6e8ae1ed3");
    }
    #[test]
    fn generate_eddsa_sig_with_poseidon() {
        let l2_key = "0x087d254d02a857d215c4c14d72521f8ab6a81ec8f0107eaf16093ebb7c70dc50";
        let inputs = vec![BigInt::from(2), BigInt::from(5), BigInt::from(7)];
        let result = get_eddsa_sig_with_poseidon(inputs, l2_key.to_string());

        assert_eq!(result, "0x0659e9406f7c3a0e1bd6ec42e69ca4a013e21253ff8abd216d9411b882b263502d99f4229cf3f10991e7999bf45b55f4afa9976e237df94378fd647fdb5a5eec0f944d06f57d08b23f3327334c43198a9c78d477a3f0f3e30f0c2c464f5319be".to_string());
    }
}
