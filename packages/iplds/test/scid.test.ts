import { CID } from 'ipfs-http-client';
import { sha256 } from 'multiformats/hashes/sha2';
import { createAESGCMKey, generateIV } from '../src/crypto/crypto';
import { SCID } from '../src/types/scid';

describe('SCID', () => {
  describe('toCID()', () => {
    it('should return SCID', async () => {
      const scid = await createSCID();

      expect(await scid.asString()).toHaveLength(136);
    });

    it('should restore SCID from sharable CID', async () => {
      const scid = await createSCID();
      const scidStr = await scid.asString();

      const actual = SCID.from(scidStr);

      expect(actual.cid).toEqual(scid.cid);
      expect(actual.key).toStrictEqual(scid.key);
      expect(actual.iv).toStrictEqual(scid.iv);
    });
  });
});

const createSCID = async (): Promise<SCID> => {
  const key = await createAESGCMKey();
  const iv = generateIV();
  const hash = await sha256.digest(Uint8Array.from([1, 2, 3]));

  return new SCID(key, iv, CID.createV1(0, hash));
};
