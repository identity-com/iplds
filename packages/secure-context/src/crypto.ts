import { CURVES, EC256, EC256JWK, ECDHCurve } from '@identity.com/jwk';
import { Crypto } from '@peculiar/webcrypto';
import { AES } from '@stablelib/aes';
import { AESKW } from '@stablelib/aes-kw';
import { URLSafeCoder } from '@stablelib/base64';
import { GCM } from '@stablelib/gcm';
import { decode, encode } from '@stablelib/hex';
import { randomBytes } from '@stablelib/random';
import { sharedKey } from '@stablelib/x25519';
import { ec as EC } from 'elliptic';
import { generateKeyPair, jwkPrivateToRaw, jwkPublicToRaw, sanitizePublicKey } from '../../jwk/src/jwk';
import { concatKdf, lengthAndInput, uint32be } from './buffer-utils';
import { ECKey, Key, KeyAgreement, Recipient } from './types';
import { concat } from './utils';

const IV_BITS = 96;
export const IV_BYTES = IV_BITS / 8;
export const KEY_BYTES = 32;
export const ALG_ENCRYPTION = 'A256GCM';
export const ALG_KEY_AGREEMENT = 'ECDH-ES+A256KW'; // -31: https://datatracker.ietf.org/doc/html/rfc8152#section-12.5.1

const crypto = new Crypto();
const encoder = new TextEncoder();
const base64 = new URLSafeCoder();

export const createECKey = async (crv: ECDHCurve = 'X25519'): Promise<ECKey> => {
  return await Promise.resolve(generateKeyPair(crv));
};

export const keyAgreement = async (recipientPublic: ECKey, cek: Key): Promise<KeyAgreement> =>
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
  return await Promise.resolve(new GCM(new AES(key)).seal(iv, data));
};

export const decryptAES = async (encrypted: Uint8Array, key: Key, iv: Uint8Array): Promise<Uint8Array> => {
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  return await Promise.resolve(new GCM(new AES(key)).open(iv, encrypted)!);
};

export const createAESGCMKey = async (): Promise<Uint8Array> => await Promise.resolve(randomBytes(KEY_BYTES));

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

  const sharedSecret = getSharedSecret(publicKey, privateKey);

  return await concatKdf(digest, sharedSecret, keyLength, value);
};

const ELLIPTIC_CURVE_MAP: Record<EC256, string> = {
  'K-256': 'secp256k1',
  'P-256': 'p256',
};

const getSharedSecret = (publicKey: ECKey, privateKey: ECKey): Uint8Array => {
  if (!CURVES.includes(publicKey.crv)) {
    throw new Error(`Unsupported curve type: ${publicKey.crv}`);
  }
  if (publicKey.crv !== privateKey.crv) {
    throw new Error('Incompatible keys');
  }
  if (publicKey.crv === 'X25519') {
    return sharedKey(jwkPrivateToRaw(privateKey), jwkPublicToRaw(publicKey, false, true));
  }

  return ellipticSharedKey(publicKey, privateKey as EC256JWK);
};

export const encryptKeyManagement = async (
  alg: string,
  recipientPublic: ECKey,
  cek: Key,
  providedParameters: { apu?: string; apv?: string; epk?: ECKey } = {},
): Promise<KeyAgreement> => {
  if (!ecdhAllowed(recipientPublic.crv)) {
    throw new Error('ECDH-ES with the provided key is not allowed or not supported by your javascript runtime');
  }
  const { epk } = providedParameters;
  const ephemeralKey = epk ?? generateKeyPair(recipientPublic.crv);

  const sharedSecret = await deriveKey(recipientPublic, ephemeralKey, alg, parseInt(alg.substr(-5, 3), 10));
  // parameters = { epk: { x, y, crv, kty } };
  //   if (apu) parameters.apu = b64encode(apu);
  //   if (apv) parameters.apv = b64encode(apv);

  const encryptedKey = await wrap(sharedSecret, cek);

  return { cek, encryptedKey, parameters: { epk: sanitizePublicKey(ephemeralKey) } };
};

export const decryptKeyManagement = async (
  alg: string,
  recipientPrivate: ECKey,
  ecdhRecipient: Recipient,
): Promise<Key> => {
  // Direct Key Agreement
  if (!ecdhAllowed(recipientPrivate.crv)) {
    throw new Error('ECDH-ES with the provided key is not allowed or not supported by your javascript runtime');
  }

  const sharedSecret = await deriveKey(ecdhRecipient[1].epk, recipientPrivate, alg, parseInt(alg.substr(-5, 3), 10));

  // Key Agreement with Key Wrapping
  return unwrap(sharedSecret, ecdhRecipient[2]);
};

const digest = async (algorithm: string, data: BufferSource): Promise<Uint8Array> => {
  const subtleDigest = `SHA-${algorithm.substr(-3)}`;
  return new Uint8Array(await crypto.subtle.digest(subtleDigest, data));
};

const ecdhAllowed = (crv: ECDHCurve): boolean => CURVES.includes(crv);

const wrap = async (key: Uint8Array, cek: Key): Promise<Uint8Array> => {
  return await Promise.resolve(new AESKW(key).wrapKey(cek));
};

const unwrap = async (key: Uint8Array, wrappedKey: Uint8Array): Promise<Uint8Array> => {
  return await Promise.resolve(new AESKW(key).unwrapKey(wrappedKey));
};
const ellipticSharedKey = (publicKey: EC256JWK, privateKey: EC256JWK): Uint8Array => {
  const ec = new EC(ELLIPTIC_CURVE_MAP[publicKey.crv]);

  const alice = ec.keyFromPublic({
    x: encode(base64.decode(publicKey.x)),
    y: encode(base64.decode(publicKey.y)),
  });
  const bob = ec.keyFromPrivate(jwkPrivateToRaw(privateKey));
  const shared = bob.derive(alice.getPublic()).toString(16).padStart(64, '0');

  return decode(shared);
};
