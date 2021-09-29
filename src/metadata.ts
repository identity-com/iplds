import { CID } from 'ipfs-http-client';
import { Link } from './types';

export class Metadata {
  constructor(
    public readonly contentCID: CID,
    public readonly iv: Uint8Array,
    public readonly references: Link[] = []
  ) {}

  static clone(metadata: Metadata): Metadata {
    return new Metadata(metadata.contentCID, metadata.iv, metadata.references);
  }
}
