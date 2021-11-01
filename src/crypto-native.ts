import { Crypto } from '@peculiar/webcrypto';
import { CRV_ALG, translateKeyTypeToAlgorithm } from './cose-js/common';
import { decryptKeyManagement, ecdh_es_a256kw } from './ecdh-es-akw';
import { DecryptKeyAgreement, ECDHCurve, KeyAgreement, SecureContextConfig } from './types';

const ALG_ENCRYPTION = 'A256GCM';
const ALG_KEY_AGREEMENT = 'ECDH-ES-A256KW'; // -31: https://datatracker.ietf.org/doc/html/rfc8152#section-12.5.1
const SUBTLE_ENCRYPTION_ALG = 'AES-GCM';
const IV_BITS = 96;
export const IV_BYTES = IV_BITS / 8;

const crypto = new Crypto();

// test only
export const createECKey = async (namedCurve: ECDHCurve = 'P-256'): Promise<SecureContextConfig> => {
  const cryptoKeyPair = await crypto.subtle.generateKey(
    {
      name: CRV_ALG[namedCurve],
      namedCurve,
    },
    true,
    ['deriveBits'],
  );

  return {
    publicKey: await crypto.subtle.exportKey('jwk', cryptoKeyPair.publicKey!),
    privateKey: await crypto.subtle.exportKey('jwk', cryptoKeyPair.privateKey!),
  };
};

// test only
export const createAESGCMKey = async (): Promise<JsonWebKey> =>
  await crypto.subtle.exportKey(
    'jwk',
    await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']),
  );

export const keyAgreement = async (recipientPublic: JsonWebKey, cek: JsonWebKey): Promise<KeyAgreement> =>
  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  fromProviderSpecificKeyAgreement(
    await ecdh_es_a256kw(
      ALG_KEY_AGREEMENT,
      ALG_ENCRYPTION,
      await importJWKECCryptoKey(recipientPublic),
      await importJWKAESGCMKey(cek),
      {},
    ),
  );

export const unwrapKey = async (recipientPrivate: JsonWebKey, keyAgreement: DecryptKeyAgreement): Promise<Uint8Array> =>
  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  await decryptKeyManagement(
    ALG_KEY_AGREEMENT,
    await importJWKECCryptoKey(recipientPrivate),
    await providerSpecificKeyAgreement(keyAgreement),
  );

const importJWKECCryptoKey = async (jwk: JsonWebKey, usage?: KeyUsage[]): Promise<CryptoKey> =>
  await importJWKECKey(jwk, getParameters(jwk), usage);

const getParameters = (jwk: JsonWebKey): EcKeyImportParams => ({
  name: translateKeyTypeToAlgorithm(jwk.kty) as string,
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  namedCurve: jwk.crv!,
});

const fromProviderSpecificKeyAgreement = async (specificAgreement: any): Promise<KeyAgreement> => ({
  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
  cek: specificAgreement.cek instanceof Uint8Array
    ? await importRawAESGCMKey(specificAgreement.cek)
    : await crypto.subtle.exportKey('jwk', specificAgreement.cek),

  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
  encryptedKey: specificAgreement.encryptedKey,

  parameters: {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    epk: await crypto.subtle.exportKey('jwk', specificAgreement.parameters.epk),
  },
});

const providerSpecificKeyAgreement = async (keyAgreement: DecryptKeyAgreement): Promise<any> => {
  return {
    encryptedKey: keyAgreement.encryptedKey,
    parameters: {
      epk: await importJWKECCryptoKey(keyAgreement.parameters.epk),
    },
  };
};

export const sha256 = async (data: Uint8Array): Promise<string> => {
  return Array.from(await sha256Raw(data))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(''); // convert bytes to hex string
};

export const sha256Raw = async (data: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', data));

export const exportRawECKey = async (key: JsonWebKey, usage?: KeyUsage[]): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.exportKey('raw', await importJWKECCryptoKey(key, usage)));

export const exportRawAESGCMKey = async (
  key: JsonWebKey,
  usage: KeyUsage[] = ['encrypt', 'decrypt'],
): Promise<Uint8Array> =>
  new Uint8Array(
    await crypto.subtle.exportKey('raw', await crypto.subtle.importKey('jwk', key, { name: 'AES-GCM' }, true, usage)),
  );

export const importRawAESGCMKey = async (
  raw: Uint8Array,
  usage: KeyUsage[] = ['encrypt', 'decrypt'],
): Promise<JsonWebKey> =>
  await crypto.subtle.exportKey('jwk', await crypto.subtle.importKey('raw', raw, 'AES-GCM', true, usage));

export const importRawAESKWKey = async (
  key: Uint8Array,
  usage: KeyUsage[] = ['encrypt', 'decrypt'],
): Promise<JsonWebKey> =>
  await crypto.subtle.exportKey('jwk', await crypto.subtle.importKey('raw', key, 'AES-KW', true, usage));

// TODO: lib-dependent impl
export const importJWKECKey = async (
  jwk: JsonWebKey,
  params: EcKeyImportParams,
  usages: KeyUsage[] = ['deriveBits'],
): Promise<CryptoKey> => await crypto.subtle.importKey('jwk', jwk, params, true, usages);

export const importJWKAESGCMKey = async (
  jwk: JsonWebKey,
  usages: KeyUsage[] = ['encrypt', 'decrypt'],
): Promise<CryptoKey> => await crypto.subtle.importKey('jwk', jwk, { name: SUBTLE_ENCRYPTION_ALG }, true, usages);

export const encryptAES = async (data: Uint8Array, key: JsonWebKey, iv: Uint8Array): Promise<Uint8Array> => {
  const params: AesGcmParams = {
    name: SUBTLE_ENCRYPTION_ALG,
    iv,
  };
  return new Uint8Array(await crypto.subtle.encrypt(params, await importJWKAESGCMKey(key), data));
};

export const decryptAES = async (encrypted: Uint8Array, key: JsonWebKey, iv: Uint8Array): Promise<Uint8Array> => {
  const params: AesGcmParams = {
    name: SUBTLE_ENCRYPTION_ALG,
    iv,
  };
  return new Uint8Array(await crypto.subtle.decrypt(params, await importJWKAESGCMKey(key), encrypted));
};

export const generateIV = (): Uint8Array => {
  const iv = new Uint8Array(IV_BYTES);

  crypto.getRandomValues(iv);

  return iv;
};
