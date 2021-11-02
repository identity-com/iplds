import { AbstractCryptoProvider } from './AbstractCryptoProvider';
import { translateKeyTypeToAlgorithm } from './cose-js/common';
import { decryptKeyManagement } from './ecdh-es-akw';
import { DecryptKeyAgreement } from './types';

export class DefaultCryptoProvider extends AbstractCryptoProvider<CryptoKey, CryptoKey, Uint8Array> {
  private static ALG_ENCRYPTION = 'A256GCM';
  private static ALG_KEY_AGREEMENT = 'ECDH-ES-A256KW'; // -31: https://datatracker.ietf.org/doc/html/rfc8152#section-12.5.1

  private static readonly SUBTLE_ENCRYPTION_ALG = 'AES-GCM';
  private static readonly IV_BITS = 96;
  private static readonly IV_BYTES = IV_BITS / 8;

  public fromECDHKey = async (ecdhKey: CryptoKey): Promise<JsonWebKey> => await crypto.subtle.exportKey('jwk', ecdhKey);

  public toECDHKey = async (jwk: JsonWebKey, usage?: KeyUsage[]): Promise<CryptoKey> =>
    await this.importJWKECKey(jwk, this.getParameters(jwk), usage);

  public async fromRawCEKKey(rawCEKKey: Uint8Array): Promise<JsonWebKey> {
    return await this.importRawAESGCMKey(rawCEKKey);
  }

  public async toRawCEKKey(jwk: JsonWebKey, usage: KeyUsage[] = ['encrypt', 'decrypt']): Promise<Uint8Array> {
    return new Uint8Array(
      await crypto.subtle.exportKey('raw', await crypto.subtle.importKey('jwk', jwk, { name: 'AES-GCM' }, true, usage)),
    );
  }

  public async toCEKKey(jwk: JsonWebKey, usages: KeyUsage[] = ['encrypt', 'decrypt']): Promise<CryptoKey> {
    return await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: DefaultCryptoProvider.SUBTLE_ENCRYPTION_ALG },
      true,
      usages,
    );
  }

  public async fromCEKKey(cekKey: CryptoKey): Promise<JsonWebKey> {
    return await crypto.subtle.exportKey('jwk', cekKey);
  }

  public async fromKWKey(kwKey: Uint8Array, usage: KeyUsage[] = ['encrypt', 'decrypt']): Promise<JsonWebKey> {
    return await crypto.subtle.exportKey('jwk', await crypto.subtle.importKey('raw', kwKey, 'AES-KW', true, usage));
  }

  public sha256 = async (data: Uint8Array): Promise<string> => {
    return Array.from(await this.sha256Raw(data))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(''); // convert bytes to hex string
  };

  public sha256Raw = async (data: Uint8Array): Promise<Uint8Array> =>
    new Uint8Array(await crypto.subtle.digest('SHA-256', data));

  public exportRawECKey = async (key: JsonWebKey, usage?: KeyUsage[]): Promise<Uint8Array> =>
    new Uint8Array(await crypto.subtle.exportKey('raw', await this.toECDHKey(key, usage)));

  public encryptAES = async (data: Uint8Array, key: JsonWebKey, iv: Uint8Array): Promise<Uint8Array> => {
    const params: AesGcmParams = {
      name: DefaultCryptoProvider.SUBTLE_ENCRYPTION_ALG,
      iv,
    };
    return new Uint8Array(await crypto.subtle.encrypt(params, await this.toCEKKey(key), data));
  };

  public decryptAES = async (encrypted: Uint8Array, key: JsonWebKey, iv: Uint8Array): Promise<Uint8Array> => {
    const params: AesGcmParams = {
      name: DefaultCryptoProvider.SUBTLE_ENCRYPTION_ALG,
      iv,
    };
    return new Uint8Array(await crypto.subtle.decrypt(params, await this.toCEKKey(key), encrypted));
  };

  public generateIV = (): Uint8Array => {
    const iv = new Uint8Array(DefaultCryptoProvider.IV_BYTES);

    crypto.getRandomValues(iv);

    return iv;
  };

  public unwrapKey = async (keyAgreement: DecryptKeyAgreement): Promise<Uint8Array> =>
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    await decryptKeyManagement(
      DefaultCryptoProvider.ALG_KEY_AGREEMENT,
      await cryptoProvider.toECDHKey(recipientPrivate),
      await cryptoProvider.providerSpecificKeyAgreement(keyAgreement),
    );

  private readonly getParameters = (jwk: JsonWebKey): EcKeyImportParams => ({
    name: translateKeyTypeToAlgorithm(jwk.kty) as string,
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    namedCurve: jwk.crv!,
  });

  private readonly importJWKECKey = async (
    jwk: JsonWebKey,
    params: EcKeyImportParams,
    usages: KeyUsage[] = ['deriveBits'],
  ): Promise<CryptoKey> => await crypto.subtle.importKey('jwk', jwk, params, true, usages);

  private readonly importRawAESGCMKey = async (
    raw: Uint8Array,
    usage: KeyUsage[] = ['encrypt', 'decrypt'],
  ): Promise<JsonWebKey> =>
    await crypto.subtle.exportKey('jwk', await crypto.subtle.importKey('raw', raw, 'AES-GCM', true, usage));
}
