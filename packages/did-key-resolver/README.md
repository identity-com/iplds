# DID Key Resolver

Utility library capable of extracting public key identified by a kid from a [DIDDocument](https://github.com/decentralized-identity/did-resolver). 

## Usage considerations

The library assumes the key will be used in key agreement algorithms and is tailored towards this use case.

The library will only search for the key in VerificationMethods registered in **keyAgreement** or **capabilityInvocation** sections.

Supports all key encodings specified in [DID spec](https://www.w3.org/TR/did-spec-registries/#verification-method-properties)

### Key types support

Please note, that while the library supports a few [VerificationMethod types](https://www.w3.org/TR/did-spec-registries/#verification-method-types) 
** Reusing the same keys for signature (e.g. ECDSA) and key agreement (e.g. ECDH) is (in general) a dangerous practice. we highly recommend not to do that! **

That said, the library will extract the key identified by the provided kid if it belongs to a **P-256**, **K-256** or **Curve25519** (we will convert key from **ED25519** to **X25519** if necessary). Formally, the following types will be deemed valid: **JsonWebKey2020**, **EcdsaSecp256k1VerificationKey2019**, **Ed25519VerificationKey2018**, **X25519KeyAgreementKey2019**, but we highly recommend using an explicit **X25519KeyAgreementKey2019** keyAgreement key.