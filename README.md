# IPLDS - Secure DAG storage

The main goal of this library is to provide a mechanism for storing DAGs securely on IPFS, while being able to share any piece (subgraph) of that with an arbitrary recipient.

This library relies on two existing specifications namely CBOR and COSE with some additional features designed for sensitive data storage applicability.
While CBOR is designed for a fairly small message size, the COSE object structures are built on the CBOR array type and designed to allow better code
reusability when parsing and processing the different types of [security messages](https://tools.ietf.org/html/rfc8152#section-2).
The COSE specification additionally describes how to represent cryptographic keys using CBOR.

The library adheres some interfaces from [js-multiformats](https://github.com/multiformats/js-multiformats) for better compatibility.

## Installation

```bash
yarn install iplds
```

## Usage

```typescript
import { create } from 'ipfs-http-client';
import { Crypto } from '@peculiar/webcrypto';
import { SecureContext } from 'iplds';

const crypto = new Crypto();
const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
  'deriveBits',
]);

// create secure context providing data owner keypair
const context = await SecureContext.create(keyPair);

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

const data = new Uint8Array(fs.readFileSync('scan.jpg'));
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
Note that path resolution algorithm tries to deffer content reading as long as possible.
It will first try to locate the target file by traversing the metadata graph. Then the file will be downloaded and decrypted to continue path resolution inside it.

### Sharing
The secure sharing is another powerful feature of this library. It comes into play when an encrypted content stored on the IPFS needs to be asynchronously shared with another party.
The content is considered shared with someone when they know the CID and can use their private key to decrypt the content.
This also implies that any content written with this library is automatically shared with the owner of the private key provided during secure context initialization.

Here is an example of secure content sharing.

```typescript
import { create } from 'ipfs-http-client';
import { Crypto } from '@peculiar/webcrypto';
import { SecureContext, SCID } from 'iplds';

const ipfs = create({ url: 'http://localhost:5001/api/v0' });
const crypto = new Crypto();

// Here is Alice, who has some secret content stored on IPFS.
const alice = await crypto.subtle.generateKey(
  { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
);
const aliceContext = await SecureContext.create(alice);
const aliceStore = aliceContext.secure(ipfs);
const cid = await aliceStore.put({ content: 'secret information'});

// Here is Bob, who made his public key known to Alice.
const bob = await crypto.subtle.generateKey(
  { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
);

// Now Alice, can share use Bob's public key to create a shareable CID.
const shareable = await aliceStore.share(cid, bob.publicKey!);
const sCID = await shareable.asString();

// Later Bob can use his private key
// and the CID received from Alice to retrieve the content.
const bobContext = await SecureContext.create(bob);
const bobStore = bobContext.secure(ipfs);
const { value } = await bobStore.get(await SCID.from(sCID));
//  { content: 'secret information' }
```
**NB:** A shareable CID alone does not give access to the encrypted content.
However, it allows to access the encrypted content metadata which includes content encryption key identifier (`kid`).
By default, the library uses opaque `kid`, derived from recipient public key, but it can be overridden.
Since a `kid` value might contain personal identifying information, it should not be exposed to anyone other than content owner and recipient, as it might leak some sensitive information.
