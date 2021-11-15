import { decrypt, translate } from '../cose-decrypt';
import { encryptToCOSE } from '../cose-encrypt';
import { createAESGCMKey, decryptAES, encryptAES, generateIV, IV_BYTES, KEY_BYTES, sha256Raw } from '../crypto';
import { sanitizePublicKey } from '../../../jwk/src/jwk';
import { Cose, ECKey, Key } from '../types';
import { concat } from '../utils';

export interface IWallet<ECKey = unknown, AESKey = unknown> {
  publicKey: ECKey;
  encrypt(
    bytes: Uint8Array,
    key?: AESKey,
    iv?: Uint8Array,
    deduplicationSecret?: Uint8Array,
  ): Promise<{ encrypted: Uint8Array; key: AESKey; iv: Uint8Array }>;
  decrypt(bytes: Uint8Array, key: AESKey, iv: Uint8Array): Promise<Uint8Array>;

  encryptCOSE(content: Uint8Array, key: AESKey, recipientPublicKey: ECKey): Promise<Cose>;

  decryptCOSE(cose: Cose): Promise<{ content: Uint8Array; key: AESKey }>;
}

export class Wallet implements IWallet<ECKey, Key> {
  public readonly publicKey: ECKey;
  private readonly key: ECKey;
  private constructor(public readonly jwk: ECKey) {
    this.key = jwk;
    this.publicKey = sanitizePublicKey(jwk);
  }

  static from(jwk: ECKey): Wallet {
    return new Wallet(jwk);
  }

  static fromRaw(bytes: Uint8Array): { key: Key; iv: Uint8Array } {
    const iv = bytes.subarray(0, IV_BYTES);
    const key = bytes.subarray(IV_BYTES, IV_BYTES + KEY_BYTES);

    return { key, iv };
  }

  static toRaw(key: Key, iv: Uint8Array): Uint8Array {
    return concat(iv, key);
  }

  async encryptCOSE(content: Uint8Array, key: Key, recipientPublicKey: ECKey): Promise<Cose> {
    return await encryptToCOSE(content, key, recipientPublicKey);
  }

  async decryptCOSE(cose: Cose): Promise<{ content: Uint8Array; key: Key }> {
    const { content, key, kid } = await decrypt(
      translate(cose),
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      this.key,
    );
    if (kid && kid !== this.publicKey.kid) {
      console.warn('Key ID does not match!');
    }

    return { content, key };
  }

  async encrypt(
    bytes: Uint8Array,
    key?: Key,
    iv?: Uint8Array,
    deduplicationSecret?: Uint8Array,
  ): Promise<{ encrypted: Uint8Array; key: Key; iv: Uint8Array }> {
    const { key: encryptionKey, iv: encryptionIV } = await this.getEncryptionMaterial(
      bytes,
      key,
      iv,
      deduplicationSecret,
    );
    const encrypted = await encryptAES(bytes, encryptionKey, encryptionIV);

    return {
      encrypted,
      key: encryptionKey,
      iv: encryptionIV,
    };
  }

  async decrypt(bytes: Uint8Array, key: Key, iv: Uint8Array): Promise<Uint8Array> {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return await decryptAES(bytes, key, iv)!;
  }

  private async getEncryptionMaterial(
    bytes: Uint8Array,
    key?: Key,
    iv?: Uint8Array,
    deduplicationSecret?: Uint8Array,
  ): Promise<{ key: Key; iv: Uint8Array }> {
    if (key && iv) {
      return { key, iv };
    }

    if (!deduplicationSecret) {
      // eslint-disable-next-line no-extra-parens
      return { key: key ?? (await createAESGCMKey()), iv: iv ?? generateIV() };
    }

    const dataHash = await sha256Raw(bytes);
    const encoder = new TextEncoder();
    iv =
      iv ??
      (await sha256Raw(await sha256Raw(concat(encoder.encode('IV'), deduplicationSecret, dataHash)))).subarray(
        0,
        IV_BYTES,
      );

    key =
      key ??
      // eslint-disable-next-line no-extra-parens
      (await sha256Raw(await sha256Raw(concat(encoder.encode('ENCRYPTION_KEY'), deduplicationSecret, dataHash))));

    return { key, iv };
  }
}
