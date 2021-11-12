import { Crypto } from '@peculiar/webcrypto';
import { URLSafeCoder } from '@stablelib/base64';
import { randomBytes } from '@stablelib/random';
import { generateKeyPair as x25519KeyPair, scalarMultBase, sharedKey } from '@stablelib/x25519';
import { concatKdf, lengthAndInput, uint32be } from './buffer-utils';
import { ECDHCurve, ECKey, JWK, Key, KeyAgreement, Recipient } from './types';
import { concat } from './utils';

const IV_BITS = 96;
export const IV_BYTES = IV_BITS / 8;
export const KEY_BYTES = 32;
const SUBTLE_ENCRYPTION_ALG = 'AES-GCM';
export const ALG_ENCRYPTION = 'A256GCM';
export const ALG_KEY_AGREEMENT = 'ECDH-ES+A256KW'; // -31: https://datatracker.ietf.org/doc/html/rfc8152#section-12.5.1

const crypto = new Crypto();
const base64 = new URLSafeCoder();
const encoder = new TextEncoder();

export const createECKey = async (crv: ECDHCurve = 'X25519'): Promise<ECKey> => {
  return await Promise.resolve(generateKeyPair(crv));
};

export const keyAgreement = async (recipientPublic: ECKey, cek: CryptoKey): Promise<KeyAgreement> =>
  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  await encryptKeyManagement(ALG_KEY_AGREEMENT, recipientPublic, cek, {});

export const sha256 = async (data: Uint8Array): Promise<string> =>
  Array.from(await sha256Raw(data))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(''); // convert bytes to hex string

export const sha256Raw = async (data: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', data));

export const generateIV = (): Uint8Array => randomBytes(IV_BYTES);

export const encryptAES = async (data: Uint8Array, key: Key, iv: Uint8Array): Promise<Uint8Array> => {
  const encryptionKey = await importRawAESGCMKey(key);
  const params: AesGcmParams = {
    name: SUBTLE_ENCRYPTION_ALG,
    iv,
  };
  return new Uint8Array(await crypto.subtle.encrypt(params, encryptionKey, data));
};

export const decryptAES = async (encrypted: Uint8Array, key: Key, iv: Uint8Array): Promise<Uint8Array> => {
  const encryptionKey = await importRawAESGCMKey(key);
  const params: AesGcmParams = {
    name: SUBTLE_ENCRYPTION_ALG,
    iv,
  };
  return new Uint8Array(await crypto.subtle.decrypt(params, encryptionKey, encrypted));
};

export const exportJWKKey = async (key: CryptoKey): Promise<ECKey> => await crypto.subtle.exportKey('jwk', key);

export const exportRawKey = async (key: CryptoKey): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.exportKey('raw', key));

export const importRawAESKWKey = async (key: Uint8Array, usage: KeyUsage[]): Promise<CryptoKey> =>
  await crypto.subtle.importKey('raw', key, 'AES-KW', true, usage);

export const importRawAESGCMKey = async (
  raw: Uint8Array,
  usage: KeyUsage[] = ['encrypt', 'decrypt'],
): Promise<CryptoKey> => await crypto.subtle.importKey('raw', raw, 'AES-GCM', true, usage);

export const importJWKKey = async (
  jwk: ECKey,
  params: EcKeyImportParams,
  usage: KeyUsage[] = ['deriveBits'],
): Promise<CryptoKey> => await crypto.subtle.importKey('jwk', jwk, params, true, usage);

export const createAESGCMKey = async (): Promise<Uint8Array> =>
  exportRawKey(await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']));

export const jwkPublicKeyToRaw = (jwk: ECKey): Uint8Array => {
  if (jwk.kty !== 'EC' && jwk.kty !== 'OKP') {
    throw new Error('Invalid key type');
  }
  if (!jwk.x) {
    throw new Error('Public key data is missing in JWK key');
  }

  return base64.decode(jwk.x);
};

export const jwkPrivateKeyToRaw = (jwk: ECKey): Uint8Array => {
  if (jwk.kty !== 'EC' && jwk.kty !== 'OKP') {
    throw new Error('Invalid key type: ' + (jwk.kty ?? ''));
  }
  if (!jwk.d) {
    throw new Error('Private key information is missing in JWK key!');
  }

  return base64.decode(jwk.d);
};

export const rawToJwkPublicKey = (publicKey: Uint8Array, curve: ECDHCurve): ECKey => {
  return {
    crv: curve,
    kty: curve === 'X25519' ? 'OKP' : 'EC',
    x: base64.encode(publicKey),
  };
};

export const rawToJwkPrivateKey = (privateKey: Uint8Array, curve: ECDHCurve): ECKey => {
  let publicKey = null;
  if (curve === 'X25519') {
    publicKey = scalarMultBase(privateKey);
  }
  return {
    crv: curve,
    kty: curve === 'X25519' ? 'OKP' : 'EC',
    x: publicKey ? base64.encode(publicKey) : undefined,
    d: base64.encode(privateKey),
    use: 'enc',
  };
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars-experimental
const CURVE_MAP: Record<ECDHCurve, string> = {
  'K-256': 'secp256k1',
  'P-256': 'p256',
  X25519: 'curve25519',
};

export const generateKeyPair = (curve: ECDHCurve = 'X25519'): ECKey => {
  const keyPair = x25519KeyPair();
  return rawToJwkPrivateKey(keyPair.secretKey, curve);
  // if (curve === 'X25519') {
  // }
  // const ec = new EC(CURVE_MAP[curve]);
  // const keyPair = ec.genKeyPair();

  // return rawToJwkPrivateKey(keyPair.getPrivate('hex'), curve);
};

export const onlyPublicKey = ({ d, ...jwk }: JWK): JWK => jwk;

export const deriveKey = async (
  publicKey: ECKey,
  privateKey: ECKey,
  algorithm: string,
  keyLength: number,
  apu = new Uint8Array(0),
  apv = new Uint8Array(0),
): Promise<Key> => {
  const value = concat(
    lengthAndInput(encoder.encode(algorithm)),
    lengthAndInput(apu),
    lengthAndInput(apv),
    uint32be(keyLength),
  );

  const sharedSecret = sharedKey(jwkPrivateKeyToRaw(privateKey), jwkPublicKeyToRaw(publicKey));
  return await concatKdf(digest, sharedSecret, keyLength, value);
};

const digest = async (algorithm: string, data: BufferSource): Promise<Uint8Array> => {
  const subtleDigest = `SHA-${algorithm.substr(-3)}`;
  return new Uint8Array(await crypto.subtle.digest(subtleDigest, data));
};

const ecdhAllowed = (crv: string): boolean => ['P-256', 'P-384', 'P-521', 'K-256', 'X25519'].includes(crv);

export const encryptKeyManagement = async (
  alg: string,
  recipientPublic: ECKey,
  cek: CryptoKey,
  providedParameters: { apu?: string; apv?: string; epk?: ECKey } = {},
): Promise<KeyAgreement> => {
  if (!recipientPublic.crv) {
    throw new Error(`Invalid JWK key`);
  }
  if (!ecdhAllowed(recipientPublic.crv)) {
    throw new Error('ECDH-ES with the provided key is not allowed or not supported by your javascript runtime');
  }
  const { epk } = providedParameters;
  const ephemeralKey = epk ?? generateKeyPair(recipientPublic.crv as ECDHCurve);

  const sharedSecret = await deriveKey(recipientPublic, ephemeralKey, alg, parseInt(alg.substr(-5, 3), 10));
  // parameters = { epk: { x, y, crv, kty } };
  //   if (apu) parameters.apu = b64encode(apu);
  //   if (apv) parameters.apv = b64encode(apv);

  const encryptedKey = await wrap(sharedSecret, cek);

  return { cek: await exportRawKey(cek), encryptedKey, parameters: { epk: onlyPublicKey(ephemeralKey) } };
};

export const decryptKeyManagement = async (
  alg: string,
  recipientPrivate: ECKey,
  ecdhRecipient: Recipient,
): Promise<Key> => {
  // Direct Key Agreement
  if (!recipientPrivate.crv) {
    throw new Error(`Invalid JWK key`);
  }
  if (!ecdhAllowed(recipientPrivate.crv)) {
    throw new Error('ECDH-ES with the provided key is not allowed or not supported by your javascript runtime');
  }

  const sharedSecret = await deriveKey(ecdhRecipient[1].epk, recipientPrivate, alg, parseInt(alg.substr(-5, 3), 10));

  // Key Agreement with Key Wrapping
  return unwrap(sharedSecret, ecdhRecipient[2]);
};

const wrap = async (key: Uint8Array | CryptoKey, cek: CryptoKey): Promise<Uint8Array> => {
  const wrappingKey = await getCryptoKey(key, ['wrapKey']);

  return new Uint8Array(await crypto.subtle.wrapKey('raw', cek, wrappingKey, 'AES-KW'));
};

const unwrap = async (key: Uint8Array | CryptoKey, wrappedKey: Uint8Array): Promise<Uint8Array> => {
  const cryptoKey = await getCryptoKey(key, ['unwrapKey']);
  const cryptoKeyCek = await crypto.subtle.unwrapKey(
    'raw',
    wrappedKey,
    cryptoKey,
    'AES-KW',
    { hash: { name: 'SHA-256' }, name: 'HMAC' },
    true,
    ['sign'],
  );

  return new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKeyCek));
};

const getCryptoKey = async (key: Uint8Array | CryptoKey, usage: KeyUsage[]): Promise<CryptoKey> => {
  if (key instanceof Uint8Array) {
    return await crypto.subtle.importKey('raw', key, 'AES-KW', true, usage);
  }
  return key; // is CryptoKey
};
