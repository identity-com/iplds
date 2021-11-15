import { CID } from 'ipfs-http-client';
import { identity } from 'multiformats/hashes/identity';
import { concat } from 'uint8arrays/concat';
import { Wallet } from '../secure/wallet';
import { Key } from '../types/types';

const CID_BYTES = 36;

export class SCID {
  constructor(public readonly key: Key, public readonly iv: Uint8Array, public readonly cid: CID) {}

  static from(cid: string | CID): SCID {
    const sharedCID = CID.asCID(cid) ?? CID.parse(cid as string);

    if (sharedCID.code !== identity.code) {
      throw new Error(`Unexpected CID codec. Expected: ${identity.code}, actual: ${sharedCID.code}`);
    }
    if (sharedCID.byteLength !== 84) {
      throw new Error(`Unexpected CID length. Expected: 84, actual: ${sharedCID.byteLength}`);
    }

    const contentCID = CID.decode(sharedCID.bytes.subarray(4, 4 + CID_BYTES));

    const { key, iv } = Wallet.fromRaw(sharedCID.bytes.subarray(4 + CID_BYTES));

    return new SCID(key, iv, contentCID);
  }

  async asCID(): Promise<CID> {
    const digest = await identity.digest(concat([this.cid.bytes, Wallet.toRaw(this.key, this.iv)]));
    return CID.createV1(identity.code, digest);
  }

  async asString(): Promise<string> {
    return (await this.asCID()).toString();
  }
}
