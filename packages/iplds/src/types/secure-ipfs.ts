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
  /**
   * Share a DAG with a given recipient. Creates a new Metadata "shadow dag" pointing to the original DAG.
   * @param cid - root of the DAG | SCID of the Metadata of the root of the DAG
   * @param recipientPublicKey - public key to use for Metadata encryption; if absent will use your own
   * @returns - SCID pointing to the new Metadata of the supplied root of the DAG
   */
  share(cid: CID | SCID, recipient: ECKey): Promise<SCID>;
  /**
   * Deep clone a DAG for a given recipient, re-encrypting each node with a new symmetric key, and creating the Metadata structure for that
   * @param cid - root of the DAG | SCID of the Metadata of the root of the DAG
   * @param recipientPublicKey - public key to use for Metadata encryption; if absent will use your own
   * @returns - SCID pointing to the Metadata of the root of the cloned DAG
   */
  copyFor(cid: CID | SCID, recipient: ECKey): Promise<SCID>;
}

export interface SecureIPFS extends SecureDAG, PublicKeyShareable {}
