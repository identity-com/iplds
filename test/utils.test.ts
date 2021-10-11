import { CID } from 'ipfs-http-client';
import { sha256 } from 'multiformats/hashes/sha2';
import { createAESGCMKey, decryptAES, encryptAES, generateIV } from '../src/crypto';
import { Link } from '../src/types';
import { buildLinkObject, links } from '../src/utils';
import { SAMPLE_JSON } from './fixtures/data-fixture';

describe('AES', () => {
  it('should encrypt/decrypt', async () => {
    const iv = generateIV();
    const key = await createAESGCMKey();
    const encrypted = await encryptAES(new TextEncoder().encode(JSON.stringify(SAMPLE_JSON)), key, iv);

    const decrypted = await decryptAES(encrypted, key, iv);
    const data: unknown = JSON.parse(new TextDecoder().decode(decrypted));

    expect(data).toEqual(SAMPLE_JSON);
  });
});

describe('links', () => {
  it('should fetch all links', async () => {
    const cid = CID.createV0(await sha256.digest(Uint8Array.from([3, 2, 1])));
    const obj = {
      a: {
        b: [
          {
            c: cid,
          },
        ],
      },
    };

    const extracted = [...links(obj, generateIV)];

    expect(extracted).toHaveLength(1);
    expect(extracted[0].path).toBe('a/b/0/c');
    expect(extracted[0].cid).toBe(cid);
  });
});

describe('Build links', () => {
  it('should build link object', async () => {
    const iv = generateIV();
    const cid1 = CID.createV0(await sha256.digest(Uint8Array.from([1, 2, 3])));
    const cid2 = CID.createV0(await sha256.digest(Uint8Array.from([3, 2, 1])));
    const links: Link[] = [
      { path: 'a/b/c/d/e', cid: cid1, iv },
      { path: 'a/b/x/y/z', cid: cid2, iv },
    ];

    const obj = buildLinkObject(links);

    expect(obj.a.b.c.d.e).toStrictEqual(cid1);
    expect(obj.a.b.x.y.z).toStrictEqual(cid2);
  });
});
