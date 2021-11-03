import { decrypt, translate } from '../cose-decrypt';
import { encryptToCOSE } from '../cose-encrypt';
import {
  createAESGCMKey,
  decryptAES,
  encryptAES,
  exportRawKey,
  generateIV,
  importRawAESGCMKey,
  IV_BYTES,
  KEY_BYTES,
  sha256,
  sha256Raw,
} from '../crypto';
import { Cose, Key, RecipientInfo } from '../types';
import { concat } from '../utils';

export interface IWallet<K> {
  keyId: string;
  publicKey: K;
  encrypt(
    bytes: Uint8Array,
    key?: K,
    iv?: Uint8Array,
    deterministic?: boolean,
  ): Promise<{ encrypted: Uint8Array; key: K; iv: Uint8Array }>;
  decrypt(bytes: Uint8Array, key: K, iv: Uint8Array): Promise<Uint8Array>;

  encryptCOSE(content: Uint8Array, key: K, recipient: RecipientInfo): Promise<Cose>;

  decryptCOSE(cose: Cose): Promise<{ content: Uint8Array; key: K }>;

  getKeyId(publicKey: K): Promise<string>;
}

export class Wallet implements IWallet<Key> {
  private constructor(
    public readonly keyId: string,
    public readonly publicKey: Key,
    private readonly privateKey?: Key,
  ) {}

  static async getKeyId<K extends Key>(publicKey: K): Promise<string> {
    return await sha256(await exportRawKey(publicKey));
  }

  static async from({
    keyId,
    publicKey,
    privateKey,
  }: {
    keyId?: string;
    publicKey?: Key;
    privateKey?: Key;
  }): Promise<Wallet> {
    if (!privateKey) {
      throw new Error('No private key');
    }
    if (!publicKey) {
      throw new Error('No public key');
    }
    // eslint-disable-next-line no-extra-parens
    const finalKeyId = keyId ?? (await Wallet.getKeyId(publicKey));

    return new Wallet(finalKeyId, publicKey, privateKey);
  }

  static async fromRaw(bytes: Uint8Array): Promise<{ key: Key; iv: Uint8Array }> {
    const iv = bytes.subarray(0, IV_BYTES);
    const key = await importRawAESGCMKey(bytes.subarray(IV_BYTES, IV_BYTES + KEY_BYTES));

    return { key, iv };
  }

  static async toRaw(key: Key, iv: Uint8Array): Promise<Uint8Array> {
    return concat(iv, await exportRawKey(key));
  }

  async encryptCOSE(content: Uint8Array, key: Key, recipient: RecipientInfo): Promise<Cose> {
    return await encryptToCOSE(content, key, recipient);
  }

  async decryptCOSE(cose: Cose): Promise<{ content: Uint8Array; key: Key }> {
    const { content, key, kid } = await decrypt(
      translate(cose),
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      this.privateKey!,
    );
    if (kid !== this.keyId) {
      console.warn('Key ID does not match!');
    }

    return { content, key };
  }

  async encrypt(
    bytes: Uint8Array,
    key?: Key,
    iv?: Uint8Array,
    deterministic = true,
  ): Promise<{ encrypted: Uint8Array; key: Key; iv: Uint8Array }> {
    const { key: encryptionKey, iv: encryptionIV } = await this.getEncryptionMaterial(bytes, key, iv, deterministic);
    const encrypted = await encryptAES(bytes, encryptionKey, encryptionIV);

    return {
      encrypted,
      key: encryptionKey,
      iv: encryptionIV,
    };
  }

  async decrypt(bytes: Uint8Array, key: Key, iv: Uint8Array): Promise<Uint8Array> {
    return await decryptAES(bytes, key, iv);
  }

  async getKeyId(publicKey: Key): Promise<string> {
    return await Wallet.getKeyId(publicKey);
  }

  private async getEncryptionMaterial(
    bytes: Uint8Array,
    key?: Key,
    iv?: Uint8Array,
    deterministic = true,
  ): Promise<{ key: Key; iv: Uint8Array }> {
    if (key && iv) {
      return { key, iv };
    }

    if (!deterministic) {
      // eslint-disable-next-line no-extra-parens
      return { key: key ?? (await createAESGCMKey()), iv: iv ?? generateIV() };
    }

    const dataHash = await sha256Raw(bytes);
    const publicKey = new Uint8Array(await exportRawKey(this.publicKey));
    const encoder = new TextEncoder();
    if (!iv) {
      iv = (await sha256Raw(await sha256Raw(concat(encoder.encode('IV'), publicKey, dataHash)))).subarray(0, IV_BYTES);
    }

    if (!key) {
      return {
        key: await importRawAESGCMKey(
          await sha256Raw(await sha256Raw(concat(encoder.encode('ENCRYPTION_KEY'), publicKey, dataHash))),
        ),
        iv,
      };
    }

    return { key, iv };
  }
}
