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
loopring_sign = "0.1.0"
```

## Usage example

```rust
use loopring_sign::poseidon::eddsa::generate_eddsa_signature;

fn main() {
    // private key of loopring layer 2
    //
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

## License

This project is licensed under

- [MIT license](http://opensource.org/licenses/MIT)

## Acknowledgements

Special thanks to leppaludi and fudgey. Their implementations in Go and C# have provided additional perspectives and have been a source of inspiration for `loopring_sign`. Check out their repositories for Go and C# implementations:

- Go implementation: [go-loopring-sig](https://github.com/loopexchange-labs/go-loopring-sig)
- C# implementation: [PoseidonSharp](https://github.com/fudgebucket27/PoseidonSharp/tree/master)
