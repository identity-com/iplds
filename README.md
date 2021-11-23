# IPLDS - Secure DAG storage

## Introduction

The main goal of this library set is to provide a way to persist, read and share DAGs securely. Current implementation supports IPFS as storage, but the protocol itself is storage-agnostic, so API provides for a capability of replacing the storage provider.

The library consists of several packages:
- [iplds](/packages/iplds): Main point of entrance. A library capable of (re-)packing a DAG into the structure on storage encrypted for sharing with a given Recipient (provided with the Receiver's public key)
- [did-key-solver](/packages/did-key-resolver): A library capable of extracting a Receiver's public key from a given [DIDDocument](https://github.com/decentralized-identity/did-resolver)
- [did-iplds](/packages/did-iplds): A library enveloping [iplds](/packages/iplds) and [did-key-resolver](/packages/did-key-resolver) to provide DAG manipulation for a Receiver identified by a [DIDDocument](https://github.com/decentralized-identity/did-resolver)
- [jwk](/packages/jwk): An utility library providing conversions between JsonWebKey and Raw elliptic curve key formats

You can learn more about protocol here (TODO: Publish the protocol)