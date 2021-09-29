import { GetOptions, GetResult, PutOptions } from 'ipfs-core-types/src/dag';
import { CID } from 'ipfs-http-client';
import { SCID } from './scid';
export interface SecureIPFS {
  put(
    node:
      | Uint8Array
      | Record<string, unknown>
      | Array<Record<string, unknown>>
      | Array<unknown>,
    options?: PutOptions
  ): Promise<CID>;
  get(cid: CID | SCID, options?: GetOptions | string): Promise<GetResult>;
  share(cid: CID | SCID, publicKey: CryptoKey): Promise<SCID>;
}
