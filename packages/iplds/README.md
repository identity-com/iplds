# IPLDS - Secure DAG storage

## Introduction

The main goal of this library is to provide a mechanism for storing (and reading) DAGs securely on IPFS, while being able to share any piece (subgraph) of that with an arbitrary recipient.

This library relies on two existing specifications namely CBOR and COSE with some additional features designed for sensitive data storage.
While CBOR is designed for a fairly small message size, the COSE object structures are built on the CBOR array type and designed to allow better code
reusability when parsing and processing the different types of [security messages](https://tools.ietf.org/html/rfc8152#section-2).
The COSE specification additionally describes how to represent cryptographic keys using CBOR.

The library adheres to some interfaces from [js-multiformats](https://github.com/multiformats/js-multiformats) for better compatibility.

## Structure

The main entities are:
- [SecureContext](src/secure/secure-context.ts): An enveloping entity initialized with the Sender's key pair, keeping track of the persisted, secured nodes of the DAG within a given session
  - As the data stored is encrypted with symmetrical keys, SecureContext's main structure is a Map between CIDs of a stored node and the CIDMetadata, containing the node's encryption key and links to the node's children
- [SecureIPFS](src/types/secure-ipfs.ts): An entity capable of putting/getting and sharing with a given Receiver the encrypted&encoded DAG
  - To store a node it is first encrypted with a symmetric key
  - To share the node with a given Receiver, the node's symmetric key is wrapped by using ECDH-ES+A256KW
- [IWallet](src/secure/wallet.ts): An entity abstracting cryptography operations required by the protocol
  - Currently used primitives are AES256GCM, AES256KW and ECDH-ES on (NIST) P-256, K-256 (secp256k1) and X25519 curves
  - The [IWallet](src/secure/wallet.ts) interface provides an abstraction, but current implementation works in both Node and browsers, using:
    - [Elliptic](https://github.com/indutny/elliptic) for P-256 and K-256
    - [stable-lib] for X25519 and AES* operations

## Installation

FIXME

## Usage

(taken from [examples.test.ts](test/examples.test.ts))

```typescript
import { generateKeyPair } from '@identity.com/jwk';
import { SecureContext } from '@identity.com/iplds';
import { create } from 'ipfs-http-client';

const keyPair = generateKeyPair('P-256');

// create secure context providing data owner keypair
const context = await SecureContext.create(Wallet.from(keyPair));

// create standard IPFS client
const ipfs = create({ url: 'http://localhost:5001/api/v0' });

// wrap it using secure context to enable encryption functionality 
const store = context.secure(ipfs);

```

### Writing & Reading

Once you secured IPFS client, you can use it to read and write data.

#### Text
```typescript
const data = new TextEncoder().encode('secret text')
const cid = await store.put(data);
const { value } = await store.get(cid);
new TextDecoder().decode(value) // secret text
```
#### Files
```typescript
import * as fs from 'fs';

const data = new Uint8Array(fs.readFileSync('./test/samples/sample.jpg'));
const cid = await store.put(data);
const { value: image } = await store.get(cid);
```
#### Objects
You can store nested data and utilize path resolution to retrieve nested values:
```typescript
const data = {
  a: {
    b: {
      c: {
        d: [5],
      },
    },
  },
};
const cid = await store.put(data);
const { value } = await store.get(cid, { path: 'a/b/c/d/0' }); // 5
```

#### Linked data
It is possible to store documents which includes links to encrypted documents stored on IPFS.
```typescript
const doc1 = await store.put({
  name: 'Alice',
});
const doc2 = await store.put({
  name: 'Bob',
});
const cid = await store.put({
  name: 'User List',
  users: [doc1, doc2],
});

const { value } = await store.get(cid);
/**
{
  name: 'User List',
  users: [
    CID(bafyreicbhxiiaadww7f2teanepw75bkmjxmziqe5vdque6vqndsam7jnji),
    CID(bafyreifet6anpdhfulvbgbrtcpdafpcsy7opvf3qme6crld5icmlpyl2nu)
  ]
}
**/

```
This becomes especially useful when combined with path resolution functionality.
The library will traverse the metadata graph and retrieve the requested document.
```typescript
const doc1 = await store.put({
  name: 'Alice',
});
const cid = await store.put({
  name: 'User List',
  users: [doc1],
});

const { value } = await store.get(cid, { path: 'users/0' }); // { name: 'Alice' }
```
Path resolution mechanism offers unified syntax to address data inside the encrypred file and linked files.
```typescript
const user = {
  a: {
    b: {
      c: { name: 'Alice' },
    },
  },
};

const parent = {
  users: [
    await store.put(user),
  ],
};

const cid = await store.put(parent);
const { value } = await store.get(cid, { path: 'users/0/a/b/c/name' }); // 'Alice'
```
Note that path resolution algorithm tries to defer content reading for as long as possible.
It will first try to locate the target file by traversing the metadata graph. Then the file will be downloaded and decrypted to continue path resolution inside it.

### Sharing
The secure sharing is another powerful feature of this library. It comes into play when an encrypted content stored on the IPFS needs to be asynchronously shared with another party.
The content is considered shared with someone when they know the CID of the Metadata pointing to the content and can use their private key to decrypt it.

Use SecureIPFS.share(...) method to (re-)create a Metadata structure for the DAG you are going to be pinning yourself (usually, if you want to share it with some other device of yours).

Example:

```typescript
import { create } from 'ipfs-http-client';
import { generateKeyPair } from '@identity.com/jwk';
import { SecureContext, Wallet } from '@identity.com/iplds';

const ipfs = create({ url: 'http://localhost:5001/api/v0' });

const alice = generateKeyPair('P-256');
const aliceContext = SecureContext.create(Wallet.from(alice));
const aliceStore = aliceContext.secure(ipfs);
const content = { content: 'secret information' };
const cid = await aliceStore.put(content);

// Here is Alice-mobile, some other keypair belonging to Alice.
const aliceMobileWallet = Wallet.from(generateKeyPair('P-256'));

// Now Alice, can use her mobile public key to share her DAG with another device
const shareable = await aliceStore.share(cid, aliceMobileWallet.publicKey);

// Later Alice can use her mobile private key and the above generated SCID to retrieve the content on another device
const aliceMobileContext = SecureContext.create(aliceMobileWallet);
const aliceMobileStore = aliceMobileContext.secure(ipfs);
const { value } = await aliceMobileStore.get(shareable);

//  { content: 'secret information' }
```

Use SecureIPFS.copyFor(...) method to deep copy some content, (re-)encrypting it for someone else (and creating a separate Metadata structure for it). You will not have access to the copy once the operation is complete, so the recipient is supposed to be the one pinning it.

Example:

```typescript
import { create } from 'ipfs-http-client';
import { generateKeyPair } from '@identity.com/jwk';
import { SecureContext, Wallet } from '@identity.com/iplds';

const alice = generateKeyPair('P-256');
const aliceContext = SecureContext.create(Wallet.from(alice));
const aliceStore = aliceContext.secure(ipfs);

const doc1 = await aliceStore.put({
  name: 'Alice',
});
const doc2 = await aliceStore.put({
  name: 'Bob',
});
const cid = await aliceStore.put({
  name: 'User List',
  users: [doc1, doc2],
});

// Here is Bob, who made his public key known to Alice.
const bob = generateKeyPair('P-256');

// Now Alice, can use Bob's public key to copy&re-encrypt her DAG for Bob, and create a shareable CID (SCID) for him
const shareable = await aliceStore.copyFor(cid, bob);

// Later Bob can use his private key
// and the SCID received from Alice to retrieve the content.
const bobContext = SecureContext.create(Wallet.from(bob));
const bobStore = bobContext.secure(ipfs);
const { value } = await bobStore.get(shareable, { path: 'users/0' });

// { name: 'Alice'}
```

**NB:** A shareable CID alone does not give access to the encrypted content.
However, it allows to access the encrypted content metadata which includes content encryption key identifier (`kid`).
By default, the library uses opaque `kid`, derived from recipient public key, but it can be overridden.
Since a `kid` value might contain personal identifying information, it should not be exposed to anyone other than content owner and recipient, as it might leak some sensitive information.
