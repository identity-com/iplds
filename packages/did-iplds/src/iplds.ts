import { DIDKeyResolver } from '@identity.com/did-key-resolver';
import {
  DeduplicationContext,
  GetOptions,
  GetResult,
  IWallet,
  PutOptions,
  SCID,
  SecureContext,
  SecureDAG,
} from '@identity.com/iplds';
import { JWK } from '@identity.com/jwk';
import { DIDDocument, DIDResolutionOptions, Resolvable } from 'did-resolver';
import { CID, IPFSHTTPClient } from 'ipfs-http-client';

export type Receiver = {
  did?: string;
  didDocument?: DIDDocument;
  kid?: string;
  options?: DIDResolutionOptions;
};

export interface DIDShareable {
  share(cid: CID | SCID, receiver: Receiver): Promise<SCID>;
  copyFor(cid: CID | SCID, receiver: Receiver): Promise<SCID>;
}

export interface DIDSecureIPFS extends SecureDAG, DIDShareable {}

export type ContextParameters = {
  wallet: IWallet<JWK, Uint8Array>;
  deduplication?: DeduplicationContext;
  didResolver?: Resolvable;
};

export class DIDSecureContext {
  private constructor(private readonly context: SecureContext, private readonly didResolver?: Resolvable) {}

  static create(parameters: ContextParameters): DIDSecureContext {
    const context = SecureContext.create(parameters.wallet, parameters.deduplication);

    return new DIDSecureContext(context, parameters.didResolver);
  }

  public secure(ipfs: IPFSHTTPClient): DIDSecureIPFS {
    const secure = this.context.secure(ipfs);

    const resolvePublicKey = async (receiver: Receiver): Promise<JWK> => {
      const didDocument = await getDIDDocument(receiver);

      return new DIDKeyResolver().resolveKey(didDocument, receiver.kid);
    };

    const getDIDDocument = async (receiver: Receiver): Promise<DIDDocument> => {
      if (receiver.did && receiver.didDocument) {
        throw new Error(`Ambiguous DID specification. Please specify either "did", either "didDocument"`);
      }
      if (!receiver.did && !receiver.didDocument) {
        throw new Error(`DID was not specified. Please specify either "did", either "didDocument"`);
      }
      if (receiver.didDocument) {
        return receiver.didDocument;
      }

      if (!this.didResolver) {
        throw new Error(`DID Resolver is not provided. You cannot use "did" without DID Resolver.`);
      }
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const result = await this.didResolver.resolve(receiver.did!, receiver.options);
      if (result.didResolutionMetadata.error) {
        throw new Error(result.didResolutionMetadata.error);
      }

      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      return result.didDocument!;
    };

    return {
      async put(
        node: Uint8Array | Record<string, unknown> | Array<Record<string, unknown>> | Array<unknown>,
        options?: PutOptions,
      ): Promise<CID> {
        return await secure.put(node, options);
      },
      async get(cid: CID | SCID, options?: GetOptions | string): Promise<GetResult> {
        return await secure.get(cid, options);
      },
      async getCIDs(cid: CID | SCID): Promise<CID[]> {
        return await secure.getCIDs(cid);
      },
      async share(cid: CID | SCID, receiver: Receiver): Promise<SCID> {
        const publicKey = await resolvePublicKey(receiver);
        return await secure.share(cid, publicKey);
      },
      async copyFor(cid: CID | SCID, receiver: Receiver): Promise<SCID> {
        const publicKey = await resolvePublicKey(receiver);
        return await secure.copyFor(cid, publicKey);
      },
    };
  }
}
