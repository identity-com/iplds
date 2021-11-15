import { IWallet, Wallet } from '@identity.com/iplds';
import { ECDHCurve, generateKeyPair, JWK } from '@identity.com/jwk';
import { DIDResolutionResult, Resolvable } from 'did-resolver';
import { CID, create, IPFSHTTPClient } from 'ipfs-http-client';
import { DIDSecureContext, DIDSecureIPFS } from '../src';
import { didDocument, toBase58 } from './did.helper';

describe.each([['X25519' as ECDHCurve]])('DID Secure Context: %s', (curve) => {
  let alice: IWallet<JWK, Uint8Array>;
  let bob: IWallet<JWK, Uint8Array>;
  let ctx: DIDSecureContext;
  let ipfs: IPFSHTTPClient;
  let secure: DIDSecureIPFS;

  beforeAll(() => {
    ipfs = create({ url: 'http://localhost:5001/api/v0' });
  });

  beforeEach(() => {
    alice = Wallet.from(generateKeyPair(curve));
    bob = Wallet.from(generateKeyPair(curve));
  });

  describe('with DID Document', () => {
    const data = { a: 1, b: 'ABC', c: true };
    let cid: CID;

    beforeEach(async () => {
      ctx = await DIDSecureContext.create({ wallet: alice });
      secure = ctx.secure(ipfs);
      cid = await secure.put(data);
    });

    it('should create share metadata', async () => {
      const scid = await secure.share(cid, {
        didDocument: didDocument({ publicKeyBase58: toBase58(alice.publicKey) }),
      });

      const { value } = await secure.get(scid);
      expect(value).toStrictEqual(data);
    });

    it('should create share metadata for Bob', async () => {
      const scid = await secure.share(cid, { didDocument: didDocument({ publicKeyBase58: toBase58(bob.publicKey) }) });

      const bobCtx = await DIDSecureContext.create({ wallet: bob });
      const bobSecure = bobCtx.secure(ipfs);
      const { value } = await bobSecure.get(scid);
      expect(value).toStrictEqual(data);
    });
  });

  describe('with DID and DID Resolver', () => {
    let didRegistry: Record<string, DIDResolutionResult>;
    const resolver: Resolvable = {
      resolve: async (did: string) => await Promise.resolve(didRegistry[did]),
    };
    const data = { a: 1, b: 'ABC', c: true };
    let cid: CID;

    beforeEach(async () => {
      didRegistry = {};
      ctx = await DIDSecureContext.create({ wallet: alice, didResolver: resolver });
      secure = ctx.secure(ipfs);
      cid = await secure.put(data);
    });

    it('should create share metadata', async () => {
      const aliceDID = 'did:sol:devnet:2CGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7';
      didRegistry[aliceDID] = {
        didDocument: didDocument({ publicKeyBase58: toBase58(alice.publicKey) }),
        didDocumentMetadata: {},
        didResolutionMetadata: {},
      };

      const scid = await secure.share(cid, { did: aliceDID });

      const { value } = await secure.get(scid);
      expect(value).toStrictEqual(data);
    });

    it('should create share metadata for Bob', async () => {
      const bobDID = 'did:sol:devnet:2BGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7';
      didRegistry[bobDID] = {
        didDocument: didDocument({ publicKeyBase58: toBase58(bob.publicKey) }),
        didDocumentMetadata: {},
        didResolutionMetadata: {},
      };

      const scid = await secure.share(cid, { did: bobDID });

      const bobCtx = await DIDSecureContext.create({ wallet: bob });
      const bobSecure = bobCtx.secure(ipfs);
      const { value } = await bobSecure.get(scid);
      expect(value).toStrictEqual(data);
    });
  });
});
