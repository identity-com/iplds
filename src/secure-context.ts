import { GetOptions, GetResult, PutOptions } from 'ipfs-core-types/src/dag';
import { BlockCodec, CID } from 'ipfs-http-client';
import { IPFSHTTPClient } from 'ipfs-http-client/dist/src/types';
import { encodeCOSE } from './cose-encrypt';
import { Metadata } from './metadata';
import { SCID } from './scid';
import { SecureIPFS } from './secure-ipfs';
import { CIDMetadata, Cose, Key, Link, MetadataOrComplexObject, RecipientInfo } from './types';
import { buildLinkObject, ComplexObject, links } from './utils';
import { IWallet } from './wallet';

export class SecureContext {
  // maps CID to CIDMetadata
  private readonly context: Map<string, CIDMetadata> = new Map();

  constructor(private readonly wallet: IWallet<Key>, private readonly deterministicCID = true) {}

  public secure(ipfs: IPFSHTTPClient): SecureIPFS {
    const ivResolver = (cid: CID): Uint8Array => {
      const metadata = this.context.get(cid.toString());
      if (!metadata) {
        throw new Error(`Unknown CID: ${cid.toString()}`);
      }
      return metadata.iv;
    };
    const getMetadata = async (cose: Cose): Promise<Metadata> => {
      const { content, key } = await this.wallet.decryptCOSE(cose);
      const codec = await ipfs.codecs.getCodec('dag-cbor');
      const metadata = Metadata.clone(codec.decode(content));
      this.addToContext(metadata.contentCID, key, metadata.iv, metadata.references);
      for (const link of metadata.references) {
        this.addToContext(link.cid, key, link.iv);
      }
      return metadata;
    };
    const getItem = async <T extends ComplexObject | Cose>(id: CID, options?: GetOptions): Promise<T> => {
      const cid = CID.asCID(id);
      if (!cid) {
        throw new Error(`"id" parameter is not CID.`);
      }
      const codec = await ipfs.codecs.getCodec(cid.code);
      const block = await this.decrypt(cid, ipfs, options);
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

    const linkToMetadata = async (link: Link, recipient: RecipientInfo, codec: BlockCodec): Promise<Cose> =>
      await createMetadata(link.cid, recipient, codec);

    const encryptMetadata = async (metadata: Cose, key?: Key): Promise<CID> =>
      await this.encrypt(encodeCOSE(metadata), ipfs, { format: 'dag-cbor' }, key);

    const encryptLinks = async (
      key: Key,
      recipient: RecipientInfo,
      codec: BlockCodec,
      links?: Link[],
    ): Promise<Link[]> => {
      if (!links || links.length === 0) {
        return [];
      }
      const promises: Promise<Cose>[] = [];
      for (const link of links) {
        promises.push(linkToMetadata(link, recipient, codec));
      }
      const metadatas = await Promise.all(promises);
      const cids = await Promise.all(metadatas.map(async (x) => await encryptMetadata(x, key)));
      return buildLinks(links, cids);
    };

    const createMetadata = async (contentCID: CID, recipient: RecipientInfo, codec: BlockCodec): Promise<Cose> => {
      const content = this.context.get(contentCID.toString());
      if (!content) {
        throw new Error(`Context does not have info on ${contentCID.toString()}`);
      }

      const encryptedLinks = await encryptLinks(content.key, recipient, codec, content.links);
      const metadata = new Metadata(contentCID, content.iv, encryptedLinks);

      return await this.wallet.encryptCOSE(codec.encode(metadata), content.key, recipient);
    };

    const repackMetadata = async (
      { contentCID, iv, references }: Metadata,
      recipient: RecipientInfo,
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
        repackedMetadatas.push(repackMetadata(meta, recipient, codec));
      }

      const repacked = await Promise.all(repackedMetadatas);
      const encrypted: Promise<CID>[] = [];
      for (const cose of repacked) {
        encrypted.push(encryptMetadata(cose, content.key));
      }

      const cids = await Promise.all(encrypted);
      const links = buildLinks(references, cids);

      const metadata = new Metadata(contentCID, iv, links);

      return await this.wallet.encryptCOSE(codec.encode(metadata), content.key, recipient);
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

    const createCOSE = async (cid: CID | SCID, publicKey?: Key, kid?: string): Promise<Cose> => {
      const recipient = await this.getRecipient(publicKey, kid);
      const codec = await ipfs.codecs.getCodec('dag-cbor');

      if (cid instanceof SCID) {
        this.addToContext(cid.cid, cid.key, cid.iv);
        const metadata = await getMetadata(await getItem(cid.cid));
        return await repackMetadata(metadata, recipient, codec);
      }
      return await createMetadata(cid, recipient, codec);
    };

    return {
      put: async (node: Uint8Array | Record<string, unknown>, options?: PutOptions): Promise<CID> => {
        const settings = <PutOptions>{
          format: 'dag-cbor',
          hashAlg: 'sha2-256',
          ...options,
        };
        if (node instanceof Uint8Array) {
          return await this.encrypt(node, ipfs, {
            ...settings,
            format: 'raw',
          });
        }
        if (settings.format && settings.format !== 'dag-cbor') {
          const codec = await ipfs.codecs.getCodec(settings.format);
          const serialized = codec.encode(node);
          return await this.encrypt(serialized, ipfs, settings);
        }
        const codec = await ipfs.codecs.getCodec('dag-cbor');
        const serialized = codec.encode(node);
        return await this.encrypt(serialized, ipfs, {
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
      share: async (cid: CID | SCID, publicKey?: Key, kid?: string): Promise<SCID> => {
        const cose = await createCOSE(cid, publicKey, kid);
        const metadataCID = await encryptMetadata(cose);
        const cidMetadata = this.context.get(metadataCID.toString());
        if (!cidMetadata) {
          throw new Error(`Unknown CID: ${metadataCID.toString()}`);
        }
        return new SCID(cidMetadata.key, cidMetadata.iv, metadataCID);
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

  private async getRecipient(publicKey?: Key, kid?: string): Promise<RecipientInfo> {
    if (!publicKey) {
      publicKey = this.wallet.publicKey;
      kid = kid ?? this.wallet.keyId;
    } else {
      // eslint-disable-next-line no-extra-parens
      kid = kid ?? (await this.wallet.getKeyId(publicKey));
    }

    return {
      publicKey,
      kid,
    };
  }

  private async encrypt(
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
    } = await this.wallet.encrypt(bytes, key, iv, this.deterministicCID);
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

  private async decrypt(cid: CID, ipfs: IPFSHTTPClient, options?: GetOptions): Promise<Uint8Array> {
    const metadata = this.context.get(cid.toString());
    if (!metadata) {
      throw new Error(`Context does not have info on ${cid.toString()}`);
    }
    const bytes = await ipfs.block.get(cid, options);
    const { key, iv } = metadata;

    return await this.wallet.decrypt(bytes, key, iv);
  }
}
