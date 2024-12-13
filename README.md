# jose-primitives
 
This library provides support for creating and parsing JWE (JSON Web Encryption) tokens using the `ECDH-1PU` key agreement protocol. The library is specifically designed to facilitate authenticated encryption (authcrypt) and supports generating a common key between participants using secure cryptographic methods.

## Features
- **Key Agreement Protocol:** `ECDH-1PU` to derive a shared common key between participants.
- **Supported Curves:** `P-384` and `X25519` (as specified in the [DIDComm Messaging RFC](https://identity.foundation/didcomm-messaging/spec/)).
- **JWE Token Creation:** Supports `alg` and `enc` combinations such as:
  - `ECDH-1PU+A256KW` for key agreement.
  - `A256CBC-HS512` for content encryption.
- **JWE Token Parsing:** Parses JWE tokens in compressed format with the above `alg` and `enc` combinations.

## Supported Algorithms

### Key Agreement (`alg`)
| Algorithm         | Description                                |
| ----------------- | ------------------------------------------ |
| `ECDH-1PU+A256KW` | Authenticated encryption with key wrapping |

### Content Encryption (`enc`)
| Algorithm       | Description                   |
| --------------- | ----------------------------- |
| `A256CBC-HS512` | AES-256 CBC with HMAC SHA-512 |

## Supported Key Types
| Curve Name   | Description                  |
| ------------ | ---------------------------- |
| `NIST P-384` | High-security elliptic curve |
| `X25519`     | Modern, fast elliptic curve  |

## Limitations
- The library only supports JWE tokens created with:
  - `alg`: `ECDH-1PU+A256KW`
  - `enc`: `A256CBC-HS512`
- Parsing is restricted to JWE tokens in **compressed format**.
- Only `P-384` and `X25519` curves are supported.

## License
This library is licensed under the MIT License.

