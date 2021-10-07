import { Crypto } from '@peculiar/webcrypto';
import { ecdh_es_a256kw } from './ecdh-es-akw';
import { ECDHCurve, KeyAgreement } from './types';

const ALG_ENCRYPTION = 'A256GCM';
const ALG_KEY_AGREEMENT = 'ECDH-ES-A256KW'; // -31: https://datatracker.ietf.org/doc/html/rfc8152#section-12.5.1
const SUBTLE_ENCRYPTION_ALG = 'AES-GCM';
const IV_BITS = 96;
export const IV_BYTES = IV_BITS / 8;

const crypto = new Crypto();

export const createECKey = async (
  namedCurve: ECDHCurve = 'P-256'
): Promise<CryptoKeyPair> =>
  await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve,
    },
    true,
    ['deriveBits']
  );

export const createAESGCMKey = async (): Promise<CryptoKey> =>
  await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);

export const keyAgreement = async (
  recipientPublic: CryptoKey,
  cek: CryptoKey
): Promise<KeyAgreement> =>
  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  await ecdh_es_a256kw(
    ALG_KEY_AGREEMENT,
    ALG_ENCRYPTION,
    recipientPublic,
    cek,
    {}
  );

export const sha256 = async (data: Uint8Array): Promise<string> => {
  return Array.from(await sha256Raw(data))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(''); // convert bytes to hex string
};

export const sha256Raw = async (data: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', data));

export const exportRawKey = async (key: CryptoKey): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.exportKey('raw', key));

export const exportJWKKey = async (key: CryptoKey): Promise<JsonWebKey> =>
  await crypto.subtle.exportKey('jwk', key);

export const importRawAESGCMKey = async (
  raw: Uint8Array,
  usage: KeyUsage[] = ['encrypt', 'decrypt']
): Promise<CryptoKey> =>
  await crypto.subtle.importKey('raw', raw, 'AES-GCM', true, usage);

export const importRawAESKWKey = async (
  key: Uint8Array,
  usage: KeyUsage[]
): Promise<CryptoKey> =>
  await crypto.subtle.importKey('raw', key, 'AES-KW', true, usage);

export const importJWKKey = async (
  jwk: JsonWebKey,
  params: EcKeyImportParams,
  usage: KeyUsage[] = ['deriveBits']
): Promise<CryptoKey> =>
  await crypto.subtle.importKey('jwk', jwk, params, true, usage);

export const encryptAES = async (
  data: Uint8Array,
  key: CryptoKey,
  iv: Uint8Array
): Promise<Uint8Array> => {
  const params: AesGcmParams = {
    name: SUBTLE_ENCRYPTION_ALG,
    iv,
  };
  return new Uint8Array(await crypto.subtle.encrypt(params, key, data));
};

export const decryptAES = async (
  encrypted: Uint8Array,
  key: CryptoKey,
  iv: Uint8Array
): Promise<Uint8Array> => {
  const params: AesGcmParams = {
    name: SUBTLE_ENCRYPTION_ALG,
    iv,
  };
  return new Uint8Array(await crypto.subtle.decrypt(params, key, encrypted));
};

export const generateIV = (): Uint8Array => {
  const iv = new Uint8Array(IV_BYTES);

  crypto.getRandomValues(iv);

  return iv;
};
