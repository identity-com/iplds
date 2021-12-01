import { SecureContext } from '../secure/secure-context';
import { GetOptions, GetResult, PutOptions } from 'ipfs-core-types/src/dag';
import { CID } from 'ipfs-http-client';
import { SCID } from './scid';
import { ECKey } from './types';

export interface SecureDAG {
  put(
    node: Uint8Array | Record<string, unknown> | Array<Record<string, unknown>> | Array<unknown>,
    options?: PutOptions,
  ): Promise<CID>;
  get(cid: CID | SCID, options?: GetOptions | string): Promise<GetResult>;
  getCIDs(cid: CID | SCID): Promise<CID[]>;
}

export interface PublicKeyShareable {
  share(cid: CID | SCID, publicKey: ECKey, reencryptNodes?: boolean): Promise<SCID>;
  fullShare(cid: CID | SCID, recipient: SecureContext): Promise<SCID>;
}

export interface SecureIPFS extends SecureDAG, PublicKeyShareable {}
