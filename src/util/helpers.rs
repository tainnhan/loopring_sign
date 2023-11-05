use indexmap::IndexMap;
use num_bigint::BigInt;
use num_bigint::Sign;
use percent_encoding::{percent_encode, AsciiSet, CONTROLS, NON_ALPHANUMERIC};
use serde_json;
use sha2::{Digest, Sha256};
use url::form_urlencoded;

use crate::poseidon::field::SNARK_SCALAR_FIELD;

pub fn to_bytes_32(n: &BigInt) -> Vec<u8> {
    let (_, array) = n.to_bytes_le();
    let mut data: Vec<u8> = vec![0; 32];
    let bytes_to_copy = array.len().min(32);
    data[..bytes_to_copy].copy_from_slice(&array[..bytes_to_copy]);
    data
}

pub fn sha256_snark(signature_base: &str) -> BigInt {
    let mut hasher = Sha256::new();
    hasher.update(signature_base);
    let hash = BigInt::from_bytes_be(Sign::Plus, &hasher.finalize()[..]);
    hash % SNARK_SCALAR_FIELD.clone()
}

// The algorithm for the API Request Signatures can be taken from:
// https://docs-protocol.loopring.io/resources/request-signing/special-api-request-signatures

pub fn generate_signature_base_string(
    request_type: &str,
    url: &str,
    data: &[(&str, &str)],
) -> String {
    const FRAGMENT: &AsciiSet = &CONTROLS.add(b':').add(b'/');
    let method = request_type.to_uppercase();

    let mut signature_base = format!("{}&{}&", &method, percent_encode(url.as_bytes(), FRAGMENT));

    let params = match method.as_str() {
        "GET" | "DELETE" => encode_get_delete_params(data),
        "POST" | "PUT" => encode_post_put_params(data),
        _ => "".to_string(),
    };
    signature_base += params.as_str();
    signature_base
}

fn encode_get_delete_params(data: &[(&str, &str)]) -> String {
    let mut sorted_data = data.to_vec();
    sorted_data.sort_by(|a, b| a.0.cmp(&b.0));

    let encoded_params = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(&sorted_data)
        .finish();

    percent_encode(encoded_params.as_bytes(), NON_ALPHANUMERIC)
        .to_string()
        .replace("%2C", "%252C")
}

fn encode_post_put_params(data: &[(&str, &str)]) -> String {
    let map: IndexMap<_, _> = data.iter().cloned().collect();
    let json_string = serde_json::to_string(&map).expect("Failed to serialize");
    let encoded_string: String =
        percent_encode(json_string.as_bytes(), NON_ALPHANUMERIC).to_string();
    encoded_string
        .replace("!", "%21")
        .replace("'", "%27")
        .replace("(", "%28")
        .replace(")", "%29")
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use num_traits::One;

    use super::*;

    #[test]
    fn test_base_signature() {
        let params: &[(&str, &str)] = &[("accountId", "11087")];
        let test =
            generate_signature_base_string("get", "https://api3.loopring.io/api/v3/apiKey", params);

        assert_eq!(
            "GET&https%3A%2F%2Fapi3.loopring.io%2Fapi%2Fv3%2FapiKey&accountId%3D11087",
            test.as_str()
        );
    }
    #[test]
    fn test_base_signature_get_order() {
        let params: &[(&str, &str)] = &[("type", "12345"), ("accountId", "11087")];
        let test =
            generate_signature_base_string("get", "https://api3.loopring.io/api/v3/apiKey", params);

        assert_eq!(
            "GET&https%3A%2F%2Fapi3.loopring.io%2Fapi%2Fv3%2FapiKey&accountId%3D11087%26type%3D12345",
            test.as_str()
        );
    }
    #[test]
    fn test_base_signature_get_comma() {
        let params: &[(&str, &str)] = &[("type", "123,45"), ("accountId", "11087")];
        let test =
            generate_signature_base_string("get", "https://api3.loopring.io/api/v3/apiKey", params);

        assert_eq!(
            "GET&https%3A%2F%2Fapi3.loopring.io%2Fapi%2Fv3%2FapiKey&accountId%3D11087%26type%3D123%252C45",
            test.as_str()
        );
    }
    #[test]
    fn test_base_signature_post() {
        let params: &[(&str, &str)] = &[("type", "12345"), ("accountId", "11087")];
        let test = generate_signature_base_string(
            "POST",
            "https://api3.loopring.io/api/v3/apiKey",
            params,
        );
        assert_eq!("POST&https%3A%2F%2Fapi3.loopring.io%2Fapi%2Fv3%2FapiKey&%7B%22type%22%3A%2212345%22%2C%22accountId%22%3A%2211087%22%7D",test.as_str())
    }
    #[test]
    fn sha256_snark_test() {
        let message = "GET&https%3A%2F%2Fapi3.loopring.io%2Fapi%2Fv3%2FapiKey&accountId%3D11087";
        let hash = sha256_snark(message);
        assert_eq!(
            hash,
            BigInt::from_str(
                "5994921150357204702563138282498811875553516325971267534989280218561106882680"
            )
            .unwrap()
        )
    }

    #[test]
    fn to_bytes_test() {
        let k = BigInt::one();
        let arg = BigInt::from_str(
            "20693456676802104653139582814194312788878632719314804297029697306071204881418",
        )
        .unwrap();

        let mut byte_array_0 = to_bytes_32(&k);
        let byte_array_1 = to_bytes_32(&arg);

        byte_array_0.extend(byte_array_1);
        let expected = vec![
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 10, 228, 215, 147, 146, 102, 9, 42, 66, 160, 26, 94, 171, 73, 235, 194, 245,
            106, 249, 114, 50, 52, 155, 182, 188, 18, 133, 216, 215, 20, 192, 45,
        ];
        assert_eq!(byte_array_0, expected);
    }
}
