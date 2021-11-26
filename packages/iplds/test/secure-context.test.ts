/* eslint-disable sonarjs/no-duplicate-string */
import { ECDHCurve, generateKeyPair } from '@identity.com/jwk';
import { randomBytes } from '@stablelib/random';
import * as fs from 'fs';
import { CID, BlockCodec, create, IPFSHTTPClient } from 'ipfs-http-client';
import { decrypt, translate } from '../src/cose/decrypt';
import { createECKey, decryptAES } from '../src/crypto/crypto';
import { SecureContext } from '../src/secure/secure-context';
import { IWallet, Wallet } from '../src/secure/wallet';
import { Metadata } from '../src/types/metadata';
import { SCID } from '../src/types/scid';
import { SecureIPFS } from '../src/types/secure-ipfs';
import { Cose, ECKey, Key } from '../src/types/types';
import { SAMPLE_JSON } from './fixtures/data-fixture';

describe.each([['P-256'], ['K-256'], ['X25519']])('Secure Context: %s', (curve: string) => {
  let aliceKeyPair: ECKey;
  let alice: IWallet<ECKey, Key>;
  let bob: IWallet<ECKey, Key>;
  let ctx: SecureContext;
  let ipfs: IPFSHTTPClient;
  let secure: SecureIPFS;

  beforeAll(() => {
    ipfs = create({ url: 'http://localhost:5001/api/v0' });
  });

  beforeEach(() => {
    aliceKeyPair = generateKeyPair(curve as ECDHCurve);
    alice = Wallet.from(aliceKeyPair);
    const bobJWK = generateKeyPair(curve as ECDHCurve);
    bob = Wallet.from(bobJWK);
    ctx = SecureContext.create(alice);
    secure = ctx.secure(ipfs);
  });

  it('should encrypt/decrypt Uint8Array', async () => {
    const data = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
    const cid = await secure.put(data);

    const decrypted = await secure.get(cid);
    expect(decrypted.value).toStrictEqual(data);
  });

  it('should encrypt/decrypt binary object', async () => {
    const image = new Uint8Array(fs.readFileSync('./test/samples/sample.jpg'));
    const cid = await secure.put(image);

    const decrypted = await secure.get(cid);
    expect(decrypted.value).toStrictEqual(image);
  });

  // currently IPFS node does not support 'json' codec
  it.skip('should encrypt/decrypt plain JSON', async () => {
    const cid = await secure.put(SAMPLE_JSON, {
      format: 'json',
    });

    const decrypted = await secure.get(cid);
    expect(decrypted.value).toStrictEqual(SAMPLE_JSON);
  });

  it('should encrypt/decrypt tree', async () => {
    const leaf1 = await secure.put({
      name: 'LEAF_1',
    });
    const leaf2 = await secure.put({
      name: 'LEAF_2',
    });
    const leaf3 = await secure.put({
      name: 'LEAF_3',
    });
    const root1 = await secure.put({
      name: 'ROOT_1',
      leafs: [leaf1, leaf2],
    });
    const root2 = await secure.put({
      name: 'ROOT_2',
      leafs: [leaf2, leaf3],
    });

    const rootData1 = await secure.get(root1);
    const rootData2 = await secure.get(root2);
    const leafData1 = await secure.get(leaf1);

    expect(rootData1.value).toEqual({
      name: 'ROOT_1',
      leafs: [leaf1, leaf2],
    });
    expect(rootData2.value).toEqual({
      name: 'ROOT_2',
      leafs: [leaf2, leaf3],
    });
    expect(leafData1.value).toEqual({
      name: 'LEAF_1',
    });
  });

  it('should resolve path on single object', async () => {
    const data = {
      a: {
        b: {
          c: {
            d: [5],
          },
        },
      },
    };
    const cid = await secure.put(data);

    const item = await secure.get(cid, { path: 'a/b/c/d/0' });
    expect(item.value).toBe(5);
  });

  [
    // eslint-disable-next-line sonarjs/no-duplicate-string
    { arg: [5], expected: 5, path: 'root/child/a/b/c/0' },
    { expected: Uint8Array.from([5, 4, 5]), path: 'root/child/a/b/c' },
  ].forEach(({ arg, expected, path }) => {
    it(`should resolve path on multiple objects: ${expected.toString()}, ${path}`, async () => {
      const child = {
        a: {
          b: {
            c: arg ?? expected,
          },
        },
      };
      const parentCid = await secure.put({
        root: {
          child: await secure.put(child),
        },
      });

      const item = await secure.get(parentCid, { path });

      expect(item.value).toStrictEqual(expected);
    });
  });

  it('should create share metadata', async () => {
    const codec = await ipfs.codecs.getCodec('dag-cbor');
    const cid = await secure.put(SAMPLE_JSON);

    const scid = await secure.share(cid, alice.publicKey);
    const cose = await scidToCose(ipfs, scid, codec);

    const { content } = await decrypt(cose, aliceKeyPair);
    const item: Metadata = codec.decode(content);

    expect(item.contentCID.toString()).toStrictEqual(cid.toString());
    expect(item.references).toHaveLength(0);
  });

  it('should create recursive share metadata', async () => {
    const codec = await ipfs.codecs.getCodec('dag-cbor');
    const child = {
      a: {
        b: {
          c: [5],
        },
      },
    };
    const parent = {
      root: {
        child: await secure.put(child),
      },
    };
    const cid = await secure.put(parent);

    const sharable = await secure.share(cid, alice.publicKey);

    const cose = await scidToCose(ipfs, sharable, codec);

    const { content } = await decrypt(cose, aliceKeyPair);
    const item: Metadata = codec.decode(content);
    expect(item.contentCID.toString()).toStrictEqual(cid.toString());
    expect(item.references).toHaveLength(1);
    expect(item.references[0].path).toBe('root/child');
    expect(item.references[0].cid).not.toStrictEqual(parent.root.child);
    const childCose = await secure.get(item.references[0].cid);
    const { content: childContent } = await decrypt(translate(childCose.value), aliceKeyPair);
    const childMetadata: Metadata = codec.decode(childContent);
    expect(childMetadata.contentCID).toEqual(parent.root.child);
    expect(childMetadata.references).toHaveLength(0);
  });

  it('should get content from decrypted Cose', async () => {
    const cid = await secure.put(SAMPLE_JSON);
    const scid = await secure.share(cid, alice.publicKey);

    const json = await secure.get(scid);

    expect(json.value).toStrictEqual(SAMPLE_JSON);
  });

  it('should get content using path', async () => {
    const child = {
      a: {
        b: {
          c: [5],
        },
      },
    };
    const parent = {
      root: {
        child: await secure.put(child),
      },
    };
    const cid = await secure.put(parent);

    const cose = await secure.share(cid, alice.publicKey);

    const item = await secure.get(cose, { path: 'root/child/a/b/c/0' });
    expect(item.value).toBe(5);
  });

  it('should get content with fresh SecureContext', async () => {
    const cid = await secure.put(SAMPLE_JSON);
    const cose = await secure.share(cid, alice.publicKey);
    const ctx = SecureContext.create(alice);
    const ipfss = ctx.secure(ipfs);

    const json = await ipfss.get(cose);

    expect(json.value).toStrictEqual(SAMPLE_JSON);
  });

  it('should get content using path with fresh SecureContext', async () => {
    const child = {
      a: {
        b: {
          c: [5],
        },
      },
    };
    const parent = {
      root: {
        child: await secure.put(child),
      },
    };
    const cid = await secure.put(parent);

    const scid = await secure.share(cid, alice.publicKey);
    const ctx = SecureContext.create(alice);
    const ipfss = ctx.secure(ipfs);

    const json = await ipfss.get(scid, { path: 'root/child/a/b/c/0' });

    expect(json.value).toBe(5);
  });

  it('should get content twice using path with fresh SecureContext', async () => {
    const child = {
      a: {
        b: {
          c: [5],
          d: [6],
        },
      },
    };
    const parent = {
      root: {
        child: await secure.put(child),
      },
    };
    const cid = await secure.put(parent);

    const scid = await secure.share(cid, alice.publicKey);
    const ctx = SecureContext.create(alice);
    const ipfss = ctx.secure(ipfs);

    expect((await ipfss.get(scid, { path: 'root/child/a/b/c/0' })).value).toBe(5);
    expect((await ipfss.get(scid, { path: 'root/child/a/b/d/0' })).value).toBe(6);
  });

  it('should store/load complex object', async () => {
    const obj1 = [
      // prettier-ignore
      await secure.put({"_id":"61443dd1ee90262c4476b642","index":0,"guid":"84629167-e6d3-4a00-a501-8aa65656656e","isActive":true,"balance":"$3,920.40","picture":"http://placehold.it/32x32","age":39,"eyeColor":"blue","name":"Darcy Clayton","gender":"female","company":"ACUSAGE","email":"darcyclayton@acusage.com","phone":"+1 (811) 567-3914","address":"635 Bragg Street, Clarktown, Alaska, 6721","about":"Ipsum exercitation proident quis ex nisi officia id labore Lorem ad aliquip. Quis ut cillum enim aliquip. Minim id dolore minim qui pariatur. Veniam ex cupidatat do aliqua eiusmod.\r\n","registered":"2019-04-06T09:49:47 -03:00","latitude":48.141279,"longitude":123.037637,"tags":["ex","nostrud","culpa","duis","excepteur","do","ea"],"friends":[{"id":0,"name":"Wiggins Kane"},{"id":1,"name":"Winters Mcintyre"},{"id":2,"name":"Agnes Mullins"}],"greeting":"Hello, Darcy Clayton! You have 6 unread messages.","favoriteFruit":"strawberry"}),
      // prettier-ignore
      await secure.put({"_id":"61443dd189c2878c8d4c74c2","index":1,"guid":"869fe797-2df8-4fd0-9f4f-e01055d3c5b5","isActive":true,"balance":"$2,885.41","picture":"http://placehold.it/32x32","age":25,"eyeColor":"blue","name":"Dena Stokes","gender":"female","company":"MANGLO","email":"denastokes@manglo.com","phone":"+1 (879) 430-2297","address":"467 Glenwood Road, Caberfae, New Mexico, 6562","about":"Do Lorem ullamco eu et. Occaecat pariatur sit adipisicing anim id nulla. Laborum duis nulla est laborum aliquip fugiat eiusmod voluptate duis est pariatur non quis culpa. Ad quis ea officia labore dolore. Velit mollit sint in duis esse veniam dolor quis. Aliqua dolore qui ex velit sint non est id occaecat pariatur ipsum culpa eu. Id quis laborum mollit minim id.\r\n","registered":"2016-06-04T12:22:52 -03:00","latitude":59.256198,"longitude":128.483879,"tags":["irure","excepteur","ut","pariatur","aliqua","pariatur","laborum"],"friends":[{"id":0,"name":"Enid Wheeler"},{"id":1,"name":"Walker Pate"},{"id":2,"name":"Benton Foley"}],"greeting":"Hello, Dena Stokes! You have 6 unread messages.","favoriteFruit":"apple"}),
      // prettier-ignore
      await secure.put({"_id":"61443dd122d48154ecf5bf90","index":2,"guid":"e60a90e1-1a8e-4b8c-ada6-57230d0d60b4","isActive":true,"balance":"$3,702.63","picture":"http://placehold.it/32x32","age":39,"eyeColor":"blue","name":"Hinton Key","gender":"male","company":"STOCKPOST","email":"hintonkey@stockpost.com","phone":"+1 (809) 569-3098","address":"654 Duryea Place, Yogaville, Pennsylvania, 7558","about":"Enim nulla in ut fugiat labore culpa aliqua fugiat nisi reprehenderit laborum culpa exercitation anim. Ipsum aute officia ullamco cupidatat voluptate cillum mollit nulla Lorem ad et. Ut aliqua nulla eu ut aliquip laboris mollit enim deserunt. Officia sunt Lorem fugiat officia amet reprehenderit esse non mollit in irure nisi quis aute. Ad cillum esse nulla velit enim magna aute elit veniam. Pariatur minim qui elit occaecat laboris et qui id sint ut.\r\n","registered":"2021-03-11T03:55:02 -02:00","latitude":-86.45749,"longitude":-88.241173,"tags":["fugiat","id","exercitation","consequat","sit","non","adipisicing"],"friends":[{"id":0,"name":"Corine Chan"},{"id":1,"name":"Conway Rowland"},{"id":2,"name":"Sparks Ashley"}],"greeting":"Hello, Hinton Key! You have 1 unread messages.","favoriteFruit":"strawberry"}),
    ];
    const cid1 = await secure.put(obj1);
    const image = new Uint8Array(fs.readFileSync('./test/samples/sample.jpg'));
    const cid2 = await secure.put(image);
    const compoundDocument = await secure.put({
      document: cid1,
      image: cid2,
    });
    const scid = await secure.share(compoundDocument, bob.publicKey);
    const bobCtx = SecureContext.create(bob);
    const bobIpfs = bobCtx.secure(ipfs);

    expect((await bobIpfs.get(scid, { path: 'document/0/guid' })).value).toStrictEqual(
      '84629167-e6d3-4a00-a501-8aa65656656e',
    );
    expect((await bobIpfs.get(scid, { path: 'document/2/guid' })).value).toStrictEqual(
      'e60a90e1-1a8e-4b8c-ada6-57230d0d60b4',
    );
    expect((await bobIpfs.get(scid, 'image')).value).toStrictEqual(image);
  });

  it('should traverse deep nested object', async () => {
    const cid = await secure.put({
      a: await secure.put({
        b: await secure.put({
          c: await secure.put({
            d: await secure.put([
              {
                e: await secure.put({
                  f: 5,
                }),
              },
            ]),
          }),
        }),
      }),
    });

    const scid = await secure.share(cid, bob.publicKey);
    const bobCtx = SecureContext.create(bob);
    const bobIpfs = bobCtx.secure(ipfs);

    expect((await bobIpfs.get(scid, 'a/b/c/d/0/e/f')).value).toBe(5);
  });

  it('should be possible to share document part with other user', async () => {
    const inner = await secure.put({
      d: await secure.put([
        {
          e: await secure.put({
            f: 5,
          }),
        },
      ]),
    });
    await secure.put({
      a: await secure.put({
        b: await secure.put({
          c: inner,
        }),
      }),
    });

    const scid = await secure.share(inner, bob.publicKey);
    const bobCtx = SecureContext.create(bob);
    const bobIpfs = bobCtx.secure(ipfs);

    expect((await bobIpfs.get(scid, 'd/0/e/f')).value).toBe(5);
  });

  it('should be possible to share single document on uninitialized context', async () => {
    const obj = { a: 10 };
    const cid = await secure.put(obj);
    const root = await secure.share(cid, alice.publicKey);

    const aliceCtx = SecureContext.create(alice);
    const aliceIpfs = aliceCtx.secure(ipfs);

    const scid = await aliceIpfs.share(root, bob.publicKey);

    const bobCtx = SecureContext.create(bob);
    const bobIpfs = bobCtx.secure(ipfs);

    expect((await bobIpfs.get(scid)).value).toStrictEqual(obj);
  });

  it('should be possible to share single document with path on uninitialized context', async () => {
    const obj = { a: 10 };
    const cid = await secure.put(obj);
    const root = await secure.share(cid, alice.publicKey);

    const aliceCtx = SecureContext.create(alice);
    const aliceIpfs = aliceCtx.secure(ipfs);

    const scid = await aliceIpfs.share(root, bob.publicKey);

    const bobCtx = SecureContext.create(bob);
    const bobIpfs = bobCtx.secure(ipfs);

    expect((await bobIpfs.get(scid, 'a')).value).toBe(10);
  });

  it('should be possible to share nested document on uninitialized context', async () => {
    const cid = await secure.put({
      a: await secure.put({
        b: 7,
      }),
    });

    const root = await secure.share(cid, alice.publicKey);

    const aliceCtx = SecureContext.create(alice);
    const aliceIpfs = aliceCtx.secure(ipfs);

    const scid = await aliceIpfs.share(root, bob.publicKey);

    const bobCtx = SecureContext.create(bob);
    const bobIpfs = bobCtx.secure(ipfs);

    expect((await bobIpfs.get(scid, 'a/b')).value).toBe(7);
  });

  it('should be possible to share deep nested document on uninitialized context', async () => {
    const cid = await secure.put({
      a: await secure.put({
        b: await secure.put({
          c: await secure.put({
            d: await secure.put([
              {
                e: await secure.put({
                  f: 5,
                }),
              },
            ]),
          }),
        }),
      }),
    });

    const root = await secure.share(cid, alice.publicKey);

    const aliceCtx = SecureContext.create(alice);
    const aliceIpfs = aliceCtx.secure(ipfs);

    const scid = await aliceIpfs.share(root, bob.publicKey);

    const bobCtx = SecureContext.create(bob);
    const bobIpfs = bobCtx.secure(ipfs);

    expect((await bobIpfs.get(scid, 'a/b/c/d/0/e/f')).value).toBe(5);
  });

  describe('Deterministic CID', () => {
    let cid: CID;
    beforeEach(async () => {
      cid = await secure.put(SAMPLE_JSON);
    });

    it('Content CID should be deterministic', async () => {
      const ctx2 = SecureContext.create(alice);
      const secure2 = ctx2.secure(ipfs);

      const cid2 = await secure2.put(SAMPLE_JSON);

      expect(cid).toStrictEqual(cid2);
    });

    it('Content CID should not be deterministic', async () => {
      const ctx2 = SecureContext.create(alice, false);
      const secure2 = ctx2.secure(ipfs);

      const cid2 = await secure2.put(SAMPLE_JSON);

      expect(cid).not.toStrictEqual(cid2);
    });

    it('Content CID should not be deterministic with diffrent secret', async () => {
      const ctx2 = SecureContext.create(alice, { secret: randomBytes(16) });
      const secure2 = ctx2.secure(ipfs);

      const cid2 = await secure2.put(SAMPLE_JSON);

      expect(cid).not.toStrictEqual(cid2);
    });

    it('should fail with too short deduplication secret', () => {
      expect(() => SecureContext.create(alice, { secret: randomBytes(15) })).toThrow(
        'Too short deduplication secret. Deduplication secret must be at least 16 bytes',
      );
    });

    it('same document should have different CID uploaded by different users', async () => {
      const ctx2 = SecureContext.create(bob);
      const secure2 = ctx2.secure(ipfs);

      const cid2 = await secure2.put(SAMPLE_JSON);

      expect(cid).not.toStrictEqual(cid2);
    });
  });

  it.skip('encrypt/decrypt large file', async () => {
    jest.setTimeout(0);
    const large = new Uint8Array(fs.readFileSync('./test/samples/random.bin'));

    const cid = await secure.put(large);

    const file = await secure.get(cid);
    expect(file.value).toStrictEqual(large);
  });

  it('share', async () => {
    const data = { content: 'secret information' };
    // Here is Alice, who has some secret content stored on IPFS.
    const alice = await createECKey();
    const aliceContext = SecureContext.create(Wallet.from(alice));
    const aliceStore = aliceContext.secure(ipfs);
    const cid = await aliceStore.put(data);

    // And here is Bob, who made his public key known to Alice.
    const bob = await createECKey();

    // Now Alice, can share use Bob's public key to create a shareable CID.
    const scid = await aliceStore.share(cid, bob);
    const scidStr = await scid.asString();
    // Later Bob can use his private key
    // and the CID received from Alice to retrieve the content.
    const bobContext = SecureContext.create(Wallet.from(bob));
    const bobStore = bobContext.secure(ipfs);

    const { value } = await bobStore.get(SCID.from(scidStr));

    expect(value).toStrictEqual(data);
  });

  describe('getCIDs', () => {
    it('should collect content CID', async () => {
      const cid = await secure.put({ text: 'secure' });

      expect(await secure.getCIDs(cid)).toStrictEqual([cid]);
    });

    it('should collect linked content CIDs', async () => {
      const cid1 = await secure.put({ text: 'secure' });
      const cid2 = await secure.put({ ref: cid1 });

      const cids = await secure.getCIDs(cid2);

      expect(cids).toHaveLength(2);
      expect(cids).toEqual(expect.arrayContaining([cid1, cid2]));
    });

    it('should collect CID with SCID', async () => {
      const cid = await secure.put({ text: 'secure' });
      const scid = await secure.share(cid, bob.publicKey);

      const bobContext = SecureContext.create(bob);
      const bobStore = bobContext.secure(ipfs);

      const cids = await bobStore.getCIDs(scid);

      expect(cids).toHaveLength(2);
      expect(cids).toEqual(expect.arrayContaining([cid, scid.cid]));
    });

    it('should collect CID with SCID', async () => {
      const cid1 = await secure.put({ text: 'secure' });
      const cid2 = await secure.put({ ref: cid1 });

      const scid = await secure.share(cid2, bob.publicKey);

      const bobContext = SecureContext.create(bob);
      const bobStore = bobContext.secure(ipfs);

      const cids = await bobStore.getCIDs(scid);

      expect(cids).toHaveLength(4);
      expect(cids).toEqual(expect.arrayContaining([cid1, cid2, scid.cid]));
    });

    it('should collect deep nested CIDs with', async () => {
      const cid = await secure.put({
        a: await secure.put({
          b: await secure.put({
            c: await secure.put({
              d: await secure.put([
                {
                  e: await secure.put({
                    f: 5,
                  }),
                },
              ]),
            }),
          }),
        }),
      });
      const scid = await secure.share(cid, bob.publicKey);

      const bobContext = SecureContext.create(bob);
      const bobStore = bobContext.secure(ipfs);

      const cids = await bobStore.getCIDs(scid);

      expect(cids).toHaveLength(12); // 6 content CIDs and 6 metadata
      expect(cids).toEqual(expect.arrayContaining([cid, scid.cid]));
    });
  });
});

const scidToCose = async (ipfs: IPFSHTTPClient, scid: SCID, codec: BlockCodec): Promise<Cose> => {
  const rawBlock = await ipfs.block.get(scid.cid);
  const decryptedBlock = await decryptAES(rawBlock, scid.key, scid.iv);
  return translate(codec.decode(decryptedBlock));
};
