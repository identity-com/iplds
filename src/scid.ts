import { CID } from 'ipfs-http-client';
import { identity } from 'multiformats/hashes/identity';
import { exportRawKey, importRawAESGCMKey, IV_BYTES } from './crypto';
import { concat } from './utils';

const KEY_BYTES = 32;
const CID_BYTES = 36;

export class SCID {
  constructor(public readonly key: CryptoKey, public readonly iv: Uint8Array, public readonly cid: CID) {}

  static async from(cid: string | CID): Promise<SCID> {
    const sharedCID = CID.asCID(cid) ?? CID.parse(cid as string);

    if (sharedCID.code !== identity.code) {
      throw new Error(`Unexpected CID codec. Expected: ${identity.code}, actual: ${sharedCID.code}`);
    }
    if (sharedCID.byteLength !== 84) {
      throw new Error(`Unexpected CID length. Expected: 84, actual: ${sharedCID.byteLength}`);
    }

    const keyStart = sharedCID.byteLength - KEY_BYTES;
    const ivStart = keyStart - IV_BYTES;
    const cidStart = ivStart - CID_BYTES;

    const contentCID = CID.decode(sharedCID.bytes.subarray(cidStart, cidStart + CID_BYTES));
    const rawIV = sharedCID.bytes.subarray(ivStart, ivStart + IV_BYTES);
    const importedKey = await importRawAESGCMKey(sharedCID.bytes.subarray(keyStart, keyStart + KEY_BYTES));

    return new SCID(importedKey, rawIV, contentCID);
  }

  async asCID(): Promise<CID> {
    const digest = await identity.digest(concat(this.cid.bytes, this.iv, new Uint8Array(await exportRawKey(this.key))));

    return CID.createV1(identity.code, digest);
  }

  async asString(): Promise<string> {
    return (await this.asCID()).toString();
  }
}
