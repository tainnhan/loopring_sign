use indexmap::IndexMap;
use percent_encoding::{percent_encode, AsciiSet, CONTROLS, NON_ALPHANUMERIC};
use serde_json;
use url::form_urlencoded;
pub struct Helpers;

impl Helpers {
    // The algorithm for the API Request Signatures can be taken from:
    // https://docs-protocol.loopring.io/resources/request-signing/special-api-request-signatures

    pub fn generate_signature_base_string(
        request_type: &str,
        url: &str,
        data: &[(&str, &str)],
    ) -> String {
        const FRAGMENT: &AsciiSet = &CONTROLS.add(b':').add(b'/');
        let method = request_type.to_uppercase();

        let mut signature_base =
            format!("{}&{}&", &method, percent_encode(url.as_bytes(), FRAGMENT));

        let params = match method.as_str() {
            "GET" | "DELETE" => Self::encode_get_delete_params(data),
            "POST" | "PUT" => Self::encode_post_put_params(data),
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
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_base_signature() {
        let params: &[(&str, &str)] = &[("accountId", "11087")];
        let test = Helpers::generate_signature_base_string(
            "get",
            "https://api3.loopring.io/api/v3/apiKey",
            params,
        );

        assert_eq!(
            "GET&https%3A%2F%2Fapi3.loopring.io%2Fapi%2Fv3%2FapiKey&accountId%3D11087",
            test.as_str()
        );
    }
    #[test]
    fn test_base_signature_get_order() {
        let params: &[(&str, &str)] = &[("type", "12345"), ("accountId", "11087")];
        let test = Helpers::generate_signature_base_string(
            "get",
            "https://api3.loopring.io/api/v3/apiKey",
            params,
        );

        assert_eq!(
            "GET&https%3A%2F%2Fapi3.loopring.io%2Fapi%2Fv3%2FapiKey&accountId%3D11087%26type%3D12345",
            test.as_str()
        );
    }
    #[test]
    fn test_base_signature_get_comma() {
        let params: &[(&str, &str)] = &[("type", "123,45"), ("accountId", "11087")];
        let test = Helpers::generate_signature_base_string(
            "get",
            "https://api3.loopring.io/api/v3/apiKey",
            params,
        );

        assert_eq!(
            "GET&https%3A%2F%2Fapi3.loopring.io%2Fapi%2Fv3%2FapiKey&accountId%3D11087%26type%3D123%252C45",
            test.as_str()
        );
    }
    #[test]
    fn test_base_signature_post() {
        let params: &[(&str, &str)] = &[("type", "12345"), ("accountId", "11087")];
        let test = Helpers::generate_signature_base_string(
            "POST",
            "https://api3.loopring.io/api/v3/apiKey",
            params,
        );
        assert_eq!("POST&https%3A%2F%2Fapi3.loopring.io%2Fapi%2Fv3%2FapiKey&%7B%22type%22%3A%2212345%22%2C%22accountId%22%3A%2211087%22%7D",test.as_str())
    }
}
