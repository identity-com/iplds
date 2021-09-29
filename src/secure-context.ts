import { GetOptions, GetResult, PutOptions } from 'ipfs-core-types/src/dag';
import { BlockCodec, CID } from 'ipfs-http-client';
import { IPFSHTTPClient } from 'ipfs-http-client/dist/src/types';
import { decrypt, translate } from './cose-decrypt';
import { encodeCOSE, encryptToCOSE } from './cose-encrypt';
import {
  createAESGCMKey,
  decryptAES,
  encryptAES,
  exportRawKey,
  generateIV,
  importRawAESGCMKey,
  IV_BYTES,
  keyAgreement,
  sha256,
  sha256Raw,
} from './crypto';
import { Metadata } from './metadata';
import { SecureIPFS } from './secure-ipfs';
import { SCID } from './scid';
import {
  CIDMetadata,
  Cose,
  Link,
  MetadataOrComplexObject,
  SecureContextConfig,
} from './types';
import { buildLinkObject, ComplexObject, concat, links } from './utils';

export class SecureContext {
  // maps CID to CIDMetadata
  private readonly context: Map<string, CIDMetadata> = new Map();

  private constructor(
    private readonly keyId: string,
    private readonly publicKey: CryptoKey,
    private readonly deterministicCID: boolean,
    private readonly privateKey?: CryptoKey
  ) {}

  static async create({
    publicKey,
    privateKey,
    keyId,
    deterministicCID,
  }: SecureContextConfig): Promise<SecureContext> {
    if (!privateKey) {
      throw new Error('No private key');
    }
    if (!publicKey) {
      throw new Error('No public key');
    }
    // eslint-disable-next-line no-extra-parens
    const finalKeyId = keyId ?? (await sha256(await exportRawKey(publicKey)));
    return new SecureContext(
      finalKeyId,
      publicKey,
      deterministicCID ?? true,
      privateKey
    );
  }

  public secure(ipfs: IPFSHTTPClient): SecureIPFS {
    const ivResolver = (cid: CID): Uint8Array => {
      const metadata = this.context.get(cid.toString());
      if (!metadata) {
        throw new Error(`Unknown CID: ${cid.toString()}`);
      }
      return metadata.iv;
    };
    const getMetadata = async (cose: Cose): Promise<Metadata> => {
      const { content, key, kid } = await decrypt(
        translate(cose),
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        this.privateKey!
      );
      if (kid !== this.keyId) {
        console.warn('Key ID does not match!');
      }
      const codec = await ipfs.codecs.getCodec('dag-cbor');
      const metadata = Metadata.clone(codec.decode(content));
      this.addToContext(
        metadata.contentCID,
        key,
        metadata.iv,
        metadata.references
      );
      for (const link of metadata.references) {
        this.addToContext(link.cid, key, link.iv);
      }
      return metadata;
    };
    const getItem = async <T extends ComplexObject | Cose>(
      id: CID,
      options?: GetOptions
    ): Promise<T> => {
      const cid = CID.asCID(id);
      if (!cid) {
        throw new Error(`"id" parameter is not CID.`);
      }
      const codec = await ipfs.codecs.getCodec(cid.code);
      const block = await this.decrypt(cid, ipfs, options);
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return codec.decode(block);
    };
    const doResolve = async (
      cid: CID,
      path: string[],
      options: GetOptions
    ): Promise<GetResult> => {
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
    const resolve = async (
      item: MetadataOrComplexObject,
      path: string[],
      options: GetOptions
    ): Promise<GetResult> => {
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

    const linkToMetadata = async (
      link: Link,
      publicKey: CryptoKey,
      kid: string,
      codec: BlockCodec
    ): Promise<Cose> => await createMetadata(link.cid, publicKey, kid, codec);

    const encryptMetadata = async (
      metadata: Cose,
      key?: CryptoKey
    ): Promise<CID> =>
      await this.encrypt(
        encodeCOSE(metadata),
        ipfs,
        { format: 'dag-cbor' },
        key
      );

    const encryptLinks = async (
      key: CryptoKey,
      publicKey: CryptoKey,
      kid: string,
      codec: BlockCodec,
      links?: Link[]
    ): Promise<Link[]> => {
      if (!links || links.length === 0) {
        return [];
      }
      const promises: Promise<Cose>[] = [];
      for (const link of links) {
        promises.push(linkToMetadata(link, publicKey, kid, codec));
      }
      const metadatas = await Promise.all(promises);
      const cids = await Promise.all(
        metadatas.map(async (x) => await encryptMetadata(x, key))
      );
      return buildLinks(links, cids);
    };

    const createMetadata = async (
      contentCID: CID,
      publicKey: CryptoKey,
      kid: string,
      codec: BlockCodec
    ): Promise<Cose> => {
      const content = this.context.get(contentCID.toString());
      if (!content) {
        throw new Error(
          `Context does not have info on ${contentCID.toString()}`
        );
      }

      const encryptedLinks = await encryptLinks(
        content.key,
        publicKey,
        kid,
        codec,
        content.links
      );
      const metadata = new Metadata(contentCID, content.iv, encryptedLinks);

      const key = await keyAgreement(publicKey, content.key);
      return await encryptToCOSE(codec.encode(metadata), kid, key);
    };

    const repackMetadata = async (
      { contentCID, iv, references }: Metadata,
      publicKey: CryptoKey,
      kid: string,
      codec: BlockCodec
    ): Promise<Cose> => {
      const content = this.context.get(contentCID.toString());
      if (!content) {
        throw new Error(
          `Context does not have info on ${contentCID.toString()}`
        );
      }

      const items: Promise<Cose>[] = [];
      for (const link of references) {
        items.push(getItem(link.cid));
      }

      const coses = await Promise.all(items);
      const metadatas = await Promise.all(coses.map(getMetadata));

      const repackedMetadatas: Promise<Cose>[] = [];
      for (const meta of metadatas) {
        repackedMetadatas.push(repackMetadata(meta, publicKey, kid, codec));
      }

      const repacked = await Promise.all(repackedMetadatas);
      const encrypted: Promise<CID>[] = [];
      for (const cose of repacked) {
        encrypted.push(encryptMetadata(cose, content.key));
      }

      const cids = await Promise.all(encrypted);
      const links = buildLinks(references, cids);

      const metadata = new Metadata(contentCID, iv, links);

      const key = await keyAgreement(publicKey, content.key);
      return await encryptToCOSE(codec.encode(metadata), kid, key);
    };

    const buildLinks = (links: Link[], cids: CID[]): Link[] =>
      links.map(({ path }, index) => ({
        path,
        iv: ivResolver(cids[index]),
        cid: cids[index],
      }));

    return {
      put: async (
        node: Uint8Array | Record<string, unknown>,
        options?: PutOptions
      ): Promise<CID> => {
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
      get: async (
        id: CID | SCID,
        options?: GetOptions | string
      ): Promise<GetResult> => {
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
      share: async (
        cid: CID | SCID,
        publicKey?: CryptoKey,
        kid?: string
      ): Promise<SCID> => {
        const codec = await ipfs.codecs.getCodec('dag-cbor');

        if (!publicKey) {
          publicKey = this.publicKey;
          kid = kid ?? this.keyId;
        } else {
          // eslint-disable-next-line no-extra-parens
          kid = kid ?? (await sha256(await exportRawKey(publicKey)));
        }

        let cose: Cose | null = null;
        if (cid instanceof SCID) {
          this.addToContext(cid.cid, cid.key, cid.iv);
          const metadata = await getMetadata(await getItem(cid.cid));
          cose = await repackMetadata(metadata, publicKey, kid, codec);
        } else {
          cose = await createMetadata(cid, publicKey, kid, codec);
        }
        const metadataCID = await encryptMetadata(cose);
        const cidMetadata = this.context.get(metadataCID.toString());
        if (!cidMetadata) {
          throw new Error(`Unknown CID: ${metadataCID.toString()}`);
        }
        return new SCID(cidMetadata.key, cidMetadata.iv, metadataCID);
      },
    };
  }

  private async encrypt(
    bytes: Uint8Array,
    ipfs: IPFSHTTPClient,
    options: PutOptions & { links?: Link[] } = {},
    key?: CryptoKey,
    iv?: Uint8Array
  ): Promise<CID> {
    ({ key, iv } = await this.getEncryptionMaterial(bytes, key, iv));
    const encrypted = await encryptAES(bytes, key, iv);
    const { links, ...restOptions } = options;
    const cid = await ipfs.block.put(encrypted, restOptions);
    this.addToContext(cid, key, iv, links ?? []);
    return cid;
  }

  private async getEncryptionMaterial(
    bytes: Uint8Array,
    key?: CryptoKey,
    iv?: Uint8Array
  ): Promise<{ key: CryptoKey; iv: Uint8Array }> {
    if (key && iv) {
      return { key, iv };
    }

    if (!this.deterministicCID) {
      // eslint-disable-next-line no-extra-parens
      return { key: key ?? (await createAESGCMKey()), iv: iv ?? generateIV() };
    }

    const dataHash = await sha256Raw(bytes);
    const publicKey = new Uint8Array(await exportRawKey(this.publicKey));
    const encoder = new TextEncoder();
    if (!key) {
      key = await importRawAESGCMKey(
        await sha256Raw(
          await sha256Raw(
            concat(encoder.encode('ENCRYPTION_KEY'), publicKey, dataHash)
          )
        )
      );
    }
    if (!iv) {
      iv = (
        await sha256Raw(
          await sha256Raw(concat(encoder.encode('IV'), publicKey, dataHash))
        )
      ).subarray(0, IV_BYTES);
    }

    return { key, iv };
  }

  private addToContext(
    cid: CID,
    key: CryptoKey,
    iv: Uint8Array,
    links?: Link[]
  ): void {
    this.context.set(cid.toV1().toString(), { key, iv, links });
    try {
      this.context.set(cid.toV0().toString(), { key, iv, links });
    } catch {
      // ignore CID convertion error
    }
  }

  private async decrypt(
    cid: CID,
    ipfs: IPFSHTTPClient,
    options?: GetOptions
  ): Promise<Uint8Array> {
    const meta = this.context.get(cid.toString());
    if (!meta) {
      throw new Error(`Context does not have info on ${cid.toString()}`);
    }
    const bytes = await ipfs.block.get(cid, options);
    const { key, iv } = meta;

    return decryptAES(bytes, key, iv);
  }
}
