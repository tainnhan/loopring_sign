// 1. The user from l1 has to retrieve a keyseed that can be taken from GET /api/v3/account
// 2. The user has to sign this message with their l1 key, generating a ECDSA Signature
// 3. L2_EDDSA_KEY=eth.sign(keySeed)

use std::ops::{Add, Mul};

use num_bigint::{BigInt, Sign};
use num_traits::{Num, Zero};
use sha2::{Digest, Sha256};

use crate::{
    poseidon::jubjub::{Point, JUBJUB_L},
    util::helpers::to_bytes_32,
};

pub struct Account {
    pub private_key: String,
    pub public_key_x: String,
    pub public_key_y: String,
}

pub fn generate_l2_private_key(signed_message_ecdsa: String) -> Result<String, String> {
    match hex::decode(signed_message_ecdsa.trim_start_matches("0x")) {
        Ok(value) => {
            let mut hasher = Sha256::new();
            hasher.update(value);
            let hash = BigInt::from_bytes_le(Sign::Plus, &hasher.finalize()[..]);
            let hash_byte_array = to_bytes_32(&hash);

            let mut big_int = BigInt::zero();

            for (i, item) in hash_byte_array.iter().enumerate() {
                let item_big_int = BigInt::from(*item);
                let tmp = BigInt::from(256).pow(i.try_into().unwrap());
                big_int = big_int.add(item_big_int.mul(tmp));
            }
            let secret_key = big_int % &*JUBJUB_L;
            let secret_key_hex = format!("{:0>64}", secret_key.to_str_radix(16));

            Ok(format!("0x{}", secret_key_hex))
        }
        Err(_) => Err(String::from("You didn't pass a valid hex-string")),
    }
}

pub fn generate_l2_keys(signed_message_ecdsa: String) -> Result<Account, String> {
    match generate_l2_private_key(signed_message_ecdsa) {
        Ok(secret_key) => {
            let base_point = Point::generate();
            let private_key =
                BigInt::from_str_radix(secret_key.trim_start_matches("0x"), 16).unwrap();

            let public_key = base_point.mul(&private_key);
            let public_key_x = format!("0x{:0>64}", public_key.x().n().to_str_radix(16));
            let public_key_y = format!("0x{:0>64}", public_key.y().n().to_str_radix(16));
            Ok(Account {
                private_key: secret_key,
                public_key_x,
                public_key_y,
            })
        }
        Err(_) => Err(String::from("You didn't pass a valid hex-string")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_private_key_test() {
        let signed_message_ecdsa = String::from("0xf8214f068c55d1bebf1fbefced91eba5f4bbe14315e1ad71f61f21e094f5853a12eba239aeaa77538ae458eebe49ca2b732d211bf0943095b3502a3b0e6a08cd1c");
        let secret_key = generate_l2_private_key(signed_message_ecdsa).unwrap();
        assert_eq!(
            secret_key.as_str(),
            "0x001fa186947c8c644cd11078f67e0bb21656432f55c4df76997b6acab2abda7f"
        );
    }
    #[test]
    fn generate_l2_keys_test() {
        let signed_message_ecdsa = String::from("0xf8214f068c55d1bebf1fbefced91eba5f4bbe14315e1ad71f61f21e094f5853a12eba239aeaa77538ae458eebe49ca2b732d211bf0943095b3502a3b0e6a08cd1c");
        let account = generate_l2_keys(signed_message_ecdsa).unwrap();

        assert_eq!(
            account.private_key.as_str(),
            "0x001fa186947c8c644cd11078f67e0bb21656432f55c4df76997b6acab2abda7f"
        );
        assert_eq!(
            account.public_key_x.as_str(),
            "0x29d178cdd6a40cd900c41565b6057a1d12c00a8c41ad367e2fe0100aab00fbe3"
        );
        assert_eq!(
            account.public_key_y.as_str(),
            "0x29e339a045af33d5729eab3b64c617e6a78dcfd0988f95f215d443d77a864b9c"
        );
    }
}
