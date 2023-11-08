# loopring_sign

`loopring_sign` is a Rust-based tool designed to generate EdDSA signatures for interacting with the Loopring API. It complements the official Python reference implementation, which is available in the Loopring repository under the `loopring-v3` branch at [hello_loopring/sdk/ethsnarks](https://github.com/Loopring/hello_loopring/tree/loopring-v3/sdk/ethsnarks).

This tool utilizes the Poseidon hash function and the Baby Jubjub Elliptic Curve (specified in EIP-2494) to produce EdDSA signatures compatible with the Loopring protocol.

## :warning: Development Status & Security Note

:construction: **Under Active Development**: This crate is currently under active development. As such, it may contain bugs or incomplete features. Use it at your own risk.

:lock: **Security Warning**: This crate requires the use of your private key. Ensure you understand the risks involved and never share your private key with untrusted parties.

## Install

Add this to your Cargo.toml

```rust
[dependencies]
loopring_sign = "0.1.2"
```

## Example 1: Generate EdDSA Signature

```rust
use loopring_sign::poseidon::eddsa::generate_eddsa_signature;

fn main() {
    // private key of loopring layer 2
    let l2_key = "0x087d254d02a857d215c4c14d72521f8ab6a81ec8f0107eaf16093ebb7c70dc50";

    // request params
    let data: &[(&str, &str)] = &[("accountId", "12345")];

    // GET, DELETE, POST or PUT
    let request_type = "POST";

    // API-endpoint
    let url: &str = "https://api3.loopring.io/api/v3/apiKey";

    let sig = generate_eddsa_signature(request_type, url, data, l2_key);

    // 0x15fdcda3ca2965d2ae43739cc6740e50c08d3f756c6161bcedb10fbc05290e000f3bc31e2293ba91ca7ac55cd20a86ae3541d3dfed63896cd474015ec60b8d40274f98b2d0a87ebf8cd0ee16dc9ec953a229cf0d6b2b61867ca80ba6e8ae1ed3
    println!("{}", &sig);

    // Do something with the sig
}
```

## Example 2: Calculate L2 Private Key

```rust
use loopring_sign::poseidon::keygen::generate_l2_keys;

fn main() {
    // 1. The user must retrieve a keyseed from the Loopring API endpoint /api/v3/account.
    // 2. The user must sign the keyseed using their L1 (Layer 1) key to generate an ECDSA signature.
    // 3. The user can then derive their L2 (Layer 2) key from the ECDSA signature and therefore interacting with the L2 Protocol
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
```

## License

This project is licensed under

- [MIT license](http://opensource.org/licenses/MIT)

## Acknowledgements

Special thanks to leppaludi and fudgey. Their implementations in Go and C# have provided additional perspectives and have been a source of inspiration for `loopring_sign`. Check out their repositories for Go and C# implementations:

- Go implementation: [go-loopring-sig](https://github.com/loopexchange-labs/go-loopring-sig)
- C# implementation: [PoseidonSharp](https://github.com/fudgebucket27/PoseidonSharp/tree/master)
