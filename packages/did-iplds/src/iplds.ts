import { CID } from 'ipfs-http-client';
import { SCID, SecureDAG } from '@identity.com/iplds';
import { DIDDocument } from 'did-resolver';

export type Reciever = {
  did?: string;
  didDocument?: DIDDocument;
  kid?: string;
};

export interface DIDShareable {
  share(cid: CID | SCID, reciever: Reciever): Promise<SCID>;
}

export interface DIDSecureIPFS extends SecureDAG, DIDShareable {}

export class DID_IPLDS {}
