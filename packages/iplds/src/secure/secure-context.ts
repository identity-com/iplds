import { jwkPublicToRaw } from '@identity.com/jwk';
import { GetOptions, GetResult, PutOptions } from 'ipfs-core-types/src/dag';
import { BlockCodec, CID, IPFSHTTPClient } from 'ipfs-http-client';
import { encodeCOSE } from '../cose/encrypt';
import { sha256Raw } from '../crypto/crypto';
import { Metadata } from '../types/metadata';
import { SCID } from '../types/scid';
import { SecureIPFS } from '../types/secure-ipfs';
import { CIDMetadata, Cose, DeduplicationContext, ECKey, Key, Link, MetadataOrComplexObject } from '../types/types';
import { buildLinkObject, cloneReplacingCIDs, ComplexObject, links } from '../utils/utils';
import { IWallet, Wallet } from './wallet';

export class SecureContext {
  // maps CID to CIDMetadata
  private readonly context: Map<string, CIDMetadata> = new Map();

  private constructor(
    private readonly wallet: IWallet<ECKey, Key>,
    private readonly deduplicationSecret?: Uint8Array,
  ) {}

  static create(wallet: IWallet<ECKey, Key>, deduplication: DeduplicationContext = true): SecureContext {
    return new SecureContext(wallet, SecureContext.getDeduplicationSecret(deduplication, wallet.publicKey));
  }

  private static getDeduplicationSecret(deduplication: DeduplicationContext, publicKey: ECKey): Uint8Array | undefined {
    if (typeof deduplication === 'boolean') {
      if (!deduplication) {
        return undefined;
      }

      return sha256Raw(jwkPublicToRaw(publicKey, false));
    }
    if (deduplication.secret.length < 16) {
      throw new Error('Too short deduplication secret. Deduplication secret must be at least 16 bytes');
    }

    return deduplication.secret;
  }

  public secure(ipfs: IPFSHTTPClient): SecureIPFS {
    const ivResolver = (cid: CID): Uint8Array => {
      const metadata = this.context.get(cid.toString());
      if (!metadata) {
        throw new Error(`Unknown CID: ${cid.toString()}`);
      }
      return metadata.iv;
    };
    const getMetadata = async (metadataCose: Cose): Promise<Metadata> => {
      const { content, key: cek } = await this.wallet.decryptCOSE(metadataCose);
      const codec = await ipfs.codecs.getCodec('dag-cbor');
      const metadata = Metadata.clone(codec.decode(content));
      this.addToContext(metadata.contentCID, cek, metadata.iv, metadata.references);
      for (const link of metadata.references) {
        this.addToContext(link.cid, cek, link.iv);
      }
      return metadata;
    };
    const getItem = async <T extends ComplexObject | Cose>(id: CID, options?: GetOptions): Promise<T> => {
      const cid = CID.asCID(id);
      if (!cid) {
        throw new Error(`"id" parameter is not CID.`);
      }
      const codec = await ipfs.codecs.getCodec(cid.code);
      const block = await this.retrieve(cid, ipfs, options);
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return codec.decode(block);
    };
    const doResolve = async (cid: CID, path: string[], options: GetOptions): Promise<GetResult> => {
      const loaded = await getItem(cid, {
        ...options,
        path: path.join('/'),
      });
      try {
        const metadata = await getMetadata(loaded as Cose);
        return await resolve(metadata, path, options);
      } catch (e) {
        // not a metadata, traverse document
        return await resolve(loaded as ComplexObject, path, options);
      }
    };
    const resolve = async (item: MetadataOrComplexObject, path: string[], options: GetOptions): Promise<GetResult> => {
      if (!item) {
        throw new Error(`No item`);
      }
      if (item instanceof Metadata) {
        try {
          if (path.length === 0) {
            return {
              value: await getItem(item.contentCID, options),
              remainderPath: '',
            };
          }
          const linkObject = buildLinkObject(item.references);
          return await resolve(linkObject, path, options);
        } catch {
          // failed to traverse on metadata, falling back to document traversal
          return await doResolve(item.contentCID, path, options);
        }
      }
      if (path.length === 0) {
        return { value: item, remainderPath: '' };
      }
      const [head, ...tail] = path;
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const value = item[head];
      if (!value) {
        throw new Error('Invalid path');
      }
      if (value instanceof Uint8Array) {
        return {
          value,
          remainderPath: tail.join('/'),
        };
      }

      const cid = CID.asCID(value);
      if (cid) {
        return await doResolve(cid, tail, options);
      }
      return await resolve(value as MetadataOrComplexObject, tail, options);
    };

    const linkToMetadata = async (link: Link, recipientPublicKey: ECKey, codec: BlockCodec): Promise<Cose> =>
      await createMetadata(link.cid, recipientPublicKey, codec);

    const persistMetadata = async (metadata: Cose, key?: Key): Promise<CID> =>
      await this.persist(encodeCOSE(metadata), ipfs, { format: 'dag-cbor' }, key);

    const encryptLinks = async (
      key: Key,
      recipientPublicKey: ECKey,
      codec: BlockCodec,
      links?: Link[],
    ): Promise<Link[]> => {
      if (!links || links.length === 0) {
        return [];
      }
      const promises: Promise<Cose>[] = [];
      for (const link of links) {
        promises.push(linkToMetadata(link, recipientPublicKey, codec));
      }
      const metadatas = await Promise.all(promises);
      const cids = await Promise.all(metadatas.map(async (x) => await persistMetadata(x, key)));
      return buildLinks(links, cids);
    };

    const createMetadata = async (contentCID: CID, recipientPublicKey: ECKey, codec: BlockCodec): Promise<Cose> => {
      const content = this.context.get(contentCID.toString());
      if (!content) {
        throw new Error(`Context does not have info on ${contentCID.toString()}`);
      }

      const encryptedLinks = await encryptLinks(content.key, recipientPublicKey, codec, content.links);
      const metadata = new Metadata(contentCID, content.iv, encryptedLinks);

      return await this.wallet.encryptCOSE(codec.encode(metadata), content.key, recipientPublicKey);
    };

    const repackAll = async (
      { contentCID, references }: Metadata,
      recipient: SecureContext,
      codec: BlockCodec,
    ): Promise<CID> => {
      const nodeMeta = this.context.get(contentCID.toString());
      if (!nodeMeta) {
        throw new Error(`Context does not have info on ${contentCID.toString()}`);
      }

      const node = await getItem<ComplexObject>(contentCID);
      if (!node) {
        throw new Error(`Couldn't retrieve ${contentCID.toString()} from storage`);
      }

      const pCoses: Promise<Cose>[] = [];
      for (const link of references) {
        pCoses.push(getItem(link.cid));
      }

      const coses = await Promise.all(pCoses);
      const childrenMetadatas = await Promise.all(coses.map(getMetadata));

      const childCIDEntries: Promise<[string, CID]>[] = childrenMetadatas.map(
        async (childMetadata): Promise<[string, CID]> => [
          childMetadata.contentCID.toString(),
          await repackAll(childMetadata, recipient, codec),
        ],
      );

      const repackedChildrenCIDs: Map<string, CID> = new Map(await Promise.all(childCIDEntries));

      const shareableNode = cloneReplacingCIDs(node, repackedChildrenCIDs);

      return await recipient.secure(ipfs).put(shareableNode);
    };

    const repackCIDs = async (nodeCID: CID, recipient: SecureContext, codec: BlockCodec): Promise<CID> => {
      const nodeMeta = this.context.get(nodeCID.toString());
      if (!nodeMeta) {
        throw new Error(`Context does not have info on ${nodeCID.toString()}`);
      }

      const node = await getItem<ComplexObject>(nodeCID);
      if (!node) {
        throw new Error(`Couldn't retrieve ${nodeCID.toString()} from storage`);
      }
      nodeMeta.links = [...links(node, ivResolver)];

      const repackedChildrenCIDs: Map<string, CID> = new Map();
      for (const link of nodeMeta.links) {
        repackedChildrenCIDs.set(link.cid.toString(), await repackCIDs(link.cid, recipient, codec));
      }

      const shareableNode = cloneReplacingCIDs(node, repackedChildrenCIDs);

      return await recipient.secure(ipfs).put(shareableNode);
    };

    const repackMetadata = async (
      { contentCID, iv, references }: Metadata,
      recipientPublicKey: ECKey,
      codec: BlockCodec,
    ): Promise<Cose> => {
      const content = this.context.get(contentCID.toString());
      if (!content) {
        throw new Error(`Context does not have info on ${contentCID.toString()}`);
      }

      const items: Promise<Cose>[] = [];
      for (const link of references) {
        items.push(getItem(link.cid));
      }

      const coses = await Promise.all(items);
      const metadatas = await Promise.all(coses.map(getMetadata));

      const repackedMetadatas: Promise<Cose>[] = [];
      for (const meta of metadatas) {
        repackedMetadatas.push(repackMetadata(meta, recipientPublicKey, codec));
      }

      const repacked = await Promise.all(repackedMetadatas);
      const encrypted: Promise<CID>[] = [];
      for (const cose of repacked) {
        encrypted.push(persistMetadata(cose, content.key));
      }

      const cids = await Promise.all(encrypted);
      const links = buildLinks(references, cids);

      const metadata = new Metadata(contentCID, iv, links);

      return await this.wallet.encryptCOSE(codec.encode(metadata), content.key, recipientPublicKey);
    };

    const buildLinks = (links: Link[], cids: CID[]): Link[] =>
      links.map(({ path }, index) => ({
        path,
        iv: ivResolver(cids[index]),
        cid: cids[index],
      }));

    const collectCIDs = async (cid: Metadata | CID): Promise<CID[]> => {
      const result: CID[] = [];
      if (cid instanceof Metadata) {
        result.push(cid.contentCID);
        for (const ref of cid.references) {
          result.push(
            ref.cid,
            // eslint-disable-next-line no-extra-parens
            ...(await collectCIDs(await getMetadata(await getItem(ref.cid)))),
          );
        }
      } else {
        const content = this.context.get(cid.toString());
        if (!content) {
          throw new Error(`Context does not have info on ${cid.toString()}`);
        }
        result.push(cid);
        for (const link of content.links ?? []) {
          // eslint-disable-next-line no-extra-parens
          result.push(...(await collectCIDs(link.cid)));
        }
      }
      return result;
    };

    const createCOSE = async (cid: CID | SCID, publicKey: ECKey): Promise<Cose> => {
      const codec = await ipfs.codecs.getCodec('dag-cbor');

      if (cid instanceof SCID) {
        this.addToContext(cid.cid, cid.key, cid.iv);
        const metadata = await getMetadata(await getItem(cid.cid));
        return await repackMetadata(metadata, publicKey, codec);
      }
      return await createMetadata(cid, publicKey, codec);
    };

    const toSCID = (cid: CID, secureContext = this): SCID => {
      const cidMetadata = secureContext.context.get(cid.toString());
      if (!cidMetadata) {
        throw new Error(`Unknown CID: ${cid.toString()}`);
      }

      return new SCID(cidMetadata.key, cidMetadata.iv, cid);
    };

    /**
     * Share a DAG with a given recipient. Creates a new Metadata "shadow dag" pointing to the original DAG.
     * @param cid - root of the DAG | SCID of the Metadata of the root of the DAG
     * @param recipientPublicKey - public key to use for Metadata encryption; if absent will use your own
     * @returns - SCID pointing to the new Metadata of the supplied root of the DAG
     */
    const share = async (cid: CID | SCID, recipientPublicKey = this.wallet.publicKey): Promise<SCID> => {
      const cose = await createCOSE(cid, recipientPublicKey);
      const metadataCID = await persistMetadata(cose);

      return toSCID(metadataCID);
    };

    /**
     * Deep clone a DAG for a given recipient, re-encrypting each node with a new symmetric key, and creating the Metadata structure for that
     * @param cid - root of the DAG | SCID of the Metadata of the root of the DAG
     * @param recipientPublicKey - public key to use for Metadata encryption; if absent will use your own
     * @returns - SCID pointing to the Metadata of the root of the cloned DAG
     */
    const copyFor = async (cid: CID | SCID, recipientPublicKey?: ECKey): Promise<SCID> => {
      const recipient = recipientPublicKey ? SecureContext.create(Wallet.from(recipientPublicKey)) : this;
      let newRootCID;
      const codec = await ipfs.codecs.getCodec('dag-cbor');
      if (cid instanceof CID) {
        newRootCID = await repackCIDs(cid, recipient, codec);
      } else {
        this.addToContext(cid.cid, cid.key, cid.iv);
        const metadata = await getMetadata(await getItem(cid.cid));

        newRootCID = await repackAll(metadata, recipient, codec);
      }

      return await recipient.secure(ipfs).share(newRootCID, recipient.wallet.publicKey);
    };

    return {
      put: async (node: Uint8Array | Record<string, unknown>, options?: PutOptions): Promise<CID> => {
        const settings = <PutOptions>{
          format: 'dag-cbor',
          hashAlg: 'sha2-256',
          ...options,
        };
        if (node instanceof Uint8Array) {
          return await this.persist(node, ipfs, {
            ...settings,
            format: 'raw',
          });
        }
        if (settings.format && settings.format !== 'dag-cbor') {
          const codec = await ipfs.codecs.getCodec(settings.format);
          const serialized = codec.encode(node);
          return await this.persist(serialized, ipfs, settings);
        }
        const codec = await ipfs.codecs.getCodec('dag-cbor');
        const serialized = codec.encode(node);
        return await this.persist(serialized, ipfs, {
          ...settings,
          links: [...links(node, ivResolver)],
        });
      },
      get: async (id: CID | SCID, options?: GetOptions | string): Promise<GetResult> => {
        if (typeof options === 'string') {
          options = { path: options };
        }

        let item: MetadataOrComplexObject = null;
        if (id instanceof SCID) {
          this.addToContext(id.cid, id.key, id.iv);
          item = await getMetadata(await getItem(id.cid));
        } else {
          item = await getItem<ComplexObject>(id, options);
        }

        if (options?.path && options.path.length > 0) {
          const parts = options.path.split('/');
          return resolve(item, parts, options);
        }

        return {
          value:
            // eslint-disable-next-line multiline-ternary
            item instanceof Metadata
              ? // eslint-disable-next-line multiline-ternary
                await getItem(item.contentCID, options)
              : item,
          remainderPath: '',
        };
      },
      share: async (cid: CID | SCID, recipientPublicKey?: ECKey): Promise<SCID> => {
        return await share(cid, recipientPublicKey);
      },
      copyFor: async (cid: SCID, recipientPublicKey?: ECKey): Promise<SCID> => {
        return await copyFor(cid, recipientPublicKey);
      },
      getCIDs: async (cid: CID | SCID): Promise<CID[]> => {
        let metadata: Metadata | null = null;
        if (cid instanceof SCID) {
          this.addToContext(cid.cid, cid.key, cid.iv);
          metadata = await getMetadata(await getItem(cid.cid));
        }
        return [
          // eslint-disable-next-line no-extra-parens
          ...(await collectCIDs(metadata ?? (cid as CID))),
          // eslint-disable-next-line no-extra-parens
          ...(cid instanceof SCID ? [cid.cid] : []),
        ];
      },
    };
  }

  private async persist(
    bytes: Uint8Array,
    ipfs: IPFSHTTPClient,
    options: PutOptions & { links?: Link[] } = {},
    key?: Key,
    iv?: Uint8Array,
  ): Promise<CID> {
    const {
      encrypted,
      key: encryptionKey,
      iv: encryptionIV,
    } = await this.wallet.encrypt(bytes, key, iv, this.deduplicationSecret);
    const { links, ...restOptions } = options;
    const cid = await ipfs.block.put(encrypted, restOptions);
    this.addToContext(cid, encryptionKey, encryptionIV, links ?? []);
    return cid;
  }

  private addToContext(cid: CID, key: Key, iv: Uint8Array, links?: Link[]): void {
    this.context.set(cid.toV1().toString(), { key, iv, links });
    try {
      this.context.set(cid.toV0().toString(), { key, iv, links });
    } catch {
      // ignore CID conversion error
    }
  }

  private async retrieve(cid: CID, ipfs: IPFSHTTPClient, options?: GetOptions): Promise<Uint8Array> {
    const cidMetadata = this.context.get(cid.toString());
    if (!cidMetadata) {
      throw new Error(`Context does not have info on ${cid.toString()}`);
    }
    const bytes = await ipfs.block.get(cid, options);
    const { key, iv } = cidMetadata;

    return this.wallet.decrypt(bytes, key, iv);
  }
}
