import { AbstractCryptoProvider } from './AbstractCryptoProvider';
import { translateKeyTypeToAlgorithm } from './cose-js/common';

export class DefaultCryptoProvider extends AbstractCryptoProvider<CryptoKey, CryptoKey, Uint8Array> {
  private readonly SUBTLE_ENCRYPTION_ALG = 'AES-GCM';

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
    return await crypto.subtle.importKey('jwk', jwk, { name: this.SUBTLE_ENCRYPTION_ALG }, true, usages);
  }

  public async fromCEKKey(cekKey: CryptoKey): Promise<JsonWebKey> {
    return await crypto.subtle.exportKey('jwk', cekKey);
  }

  public async fromKWKey(kwKey: Uint8Array, usage: KeyUsage[] = ['encrypt', 'decrypt']): Promise<JsonWebKey> {
    return await crypto.subtle.exportKey('jwk', await crypto.subtle.importKey('raw', kwKey, 'AES-KW', true, usage));
  }

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
