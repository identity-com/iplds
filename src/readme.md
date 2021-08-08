# IPLDS - Secure DAG storage

## General description

This library is in public review stage. While API looks good to us, we are open to suggestions and some changes might still occur.

The main goal of this library is to provide a mechanism for storing DAGs securely on IPFS, while being able to share any piece (subgraph) of that with a receiver.

## Installation

Build with yarn

## Development

We're using ipfs-desktop with a configured private node for development.

## Usage

1. Init the Context (pass the address of an IPFS API endpoint if you need):

        const ctx = new IPSecureContext();

2. Init the IPFSS with the Context:

        const ipfss = new IPFSS(ctx);

3. Have the Object you want to persist prepared:

        const x = {descr: "some string"};
        const s = {descr: "some other thing"};

        const p = {
            descr: "mid level object",
            x: x,
            s: s
        };

4. Use the Context to split your Object into parts you want to be stored (and later reused/linked separately)

        ctx.add(p);
        ctx.add(p, '/x');
        ctx.add(p, '/s');

5. And, finally, share the Object with a Receiver of your choice

        return await ipfss.storeObjectWithContext(p, publicKey);

The result you get is a SecureMetadata object. You are supposed to deliver this object to the Receiver. The Receiver is responsible for storing this piece securely and safely. If the Receiver loses this data they won't be able to access the stored Object's DAG later. **This one is partly sensitive - it would leak the Receiver's public key (i.e. identity) to an attacker.** 

The metadata contains the CID of the root of your Object (p), the symmetric key used to encrypt it and the CIDs of the children SecureMetadata objects stored on IPFS. More on the protocol and cryptography used **here** **TODO: Link the protocol docs**

The call actually produces a DAG of objects and their related SecureMetadata counterparts stored on IPFS, each of which is encrypted and doesn't leak any data on its own. So there would be 5 object stored on IPFS (p, x, s, secureMetadataX, secureMetadataS) and one more left in your hands (secureMetedataP) 

## Additional info

See [index.ts](./index.ts) for more usage examples.