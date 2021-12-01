import { generateKeyPair, JWK } from '@identity.com/jwk';
import { CID, create, IPFSHTTPClient } from 'ipfs-http-client';
import { Wallet, SecureIPFS, SecureContext } from '@identity.com/iplds';

import * as fs from 'fs';

describe('Secure Context', () => {
  let keyPair: JWK;
  let context: SecureContext;
  let ipfs: IPFSHTTPClient;
  let store: SecureIPFS;

  beforeAll(() => {
    keyPair = generateKeyPair('P-256');

    // create secure context providing data owner keypair
    context = SecureContext.create(Wallet.from(keyPair));

    // create standard IPFS client
    ipfs = create({ url: 'http://localhost:5001/api/v0' });

    // wrap it using secure context to enable encryption functionality
    store = context.secure(ipfs);
  });

  it('should put and get', async () => {
    const secretMessage = 'secret text';
    const data = new TextEncoder().encode(secretMessage);
    const cid = await store.put(data);
    const { value } = await store.get(cid);
    const fromStorage = new TextDecoder().decode(value); // secret text

    expect(fromStorage).toStrictEqual(secretMessage);
  });

  it('should put and get binary data', async () => {
    const data = new Uint8Array(fs.readFileSync('./test/samples/sample.jpg'));
    const cid = await store.put(data);
    const { value: image } = await store.get(cid);

    expect(image).toStrictEqual(data);
  });

  it('should get values by path', async () => {
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

    expect(value).toStrictEqual(5);
  });

  it('should resolve links between nodes as CIDs', async () => {
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

    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    expect(value.users).toBeDefined();

    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    expect(value.users.length).toStrictEqual(2);

    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    expect(value.users[0]).toBeInstanceOf(CID);
  });

  it('should resolve child nodes by path', async () => {
    const doc1 = await store.put({
      name: 'Alice',
    });
    const cid = await store.put({
      name: 'User List',
      users: [doc1],
    });

    const { value } = await store.get(cid, { path: 'users/0' });

    expect(value).toStrictEqual({ name: 'Alice' });
  });

  it('should resolve values by path in child nodes', async () => {
    const user = {
      a: {
        b: {
          c: { name: 'Alice' },
        },
      },
    };

    const parent = {
      users: [await store.put(user)],
    };

    const cid = await store.put(parent);
    const { value } = await store.get(cid, { path: 'users/0/a/b/c/name' }); // 'Alice'
    expect(value).toStrictEqual('Alice');
  });

  it('should share the secret', async () => {
    const alice = generateKeyPair('P-256');
    const aliceContext = SecureContext.create(Wallet.from(alice));
    const aliceStore = aliceContext.secure(ipfs);
    const content = { content: 'secret information' };
    const cid = await aliceStore.put(content);

    // Here is Bob, who made his public key known to Alice.
    const bobWallet = Wallet.from(generateKeyPair('P-256'));

    // Now Alice, can share use Bob's public key to create a shareable CID.
    const shareable = await aliceStore.share(cid, bobWallet.publicKey);

    // Later Bob can use his private key
    // and the CID received from Alice to retrieve the content.
    const bobContext = SecureContext.create(bobWallet);
    const bobStore = bobContext.secure(ipfs);
    const { value } = await bobStore.get(shareable);

    expect(value).toStrictEqual(content);
  });

  it('should re-share the secret with different keys', async () => {
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

    const scid = await aliceStore.share(cid, alice);
    // Here is Bob, who made his public key known to Alice.
    const bobContext = SecureContext.create(Wallet.from(generateKeyPair('P-256')));

    // Now Alice, can share use Bob's public key to create a shareable CID.
    const shareable = await aliceStore.fullShare(scid, bobContext);

    // Later Bob can use his private key
    // and the CID received from Alice to retrieve the content.
    const bobStore = bobContext.secure(ipfs);
    const { value } = await bobStore.get(shareable, { path: 'users/0' });

    expect(value).toStrictEqual({ name: 'Alice' });

    await expect(async () => await aliceStore.get(shareable, { path: 'users/0' })).rejects.toThrowError();
  });
});
