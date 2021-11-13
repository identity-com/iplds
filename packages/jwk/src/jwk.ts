import { ec as EC } from 'elliptic';
import { generateKeyPair as generateX25519KeyPair } from '@stablelib/x25519';
import { EC256, JWK, ECDHCurve, EC256JWK, X25519JWK } from './types';
import { encoding } from 'multibase';

const JWK_TO_ELLIPTIC_CURVE_NAMES: Record<ECDHCurve, string> = {
  'K-256': 'secp256k1',
  'P-256': 'p256',
  X25519: 'X25519',
};

const base64 = encoding('base64urlpad');

const ENC_UNCOMPRESSED = 4;

export const toJWK = (publicKey: Uint8Array, crv: ECDHCurve): JWK => {
  if (crv === 'X25519') {
    return toJWK25519(publicKey);
  }

  return toJWKEC(crv, publicKey);
};

const toJWK25519 = (publicKeyBinary: Uint8Array): X25519JWK => ({
  kty: 'OKP',
  crv: 'X25519',
  x: base64.encode(publicKeyBinary),
});

/**
 * Converting P-256 / secp256k1 raw public keys to JWK
 * @param crv - JWK.crv compatible curve name
 * @param publicKeyBinary - Compressed or uncompressed public key
 */
const toJWKEC = (crv: EC256, publicKeyBinary: Uint8Array): EC256JWK => {
  if (!(crv in JWK_TO_ELLIPTIC_CURVE_NAMES)) {
    throw new Error('Unsupported curve!');
  }
  const keySize = 32;
  const uncompressed = getUncompressedPublicKey(crv, publicKeyBinary, keySize);

  return {
    crv,
    kty: 'EC',
    x: base64.encode(uncompressed.slice(1, keySize + 1)), // ignore the first '04' byte for uncompressed encoding
    y: base64.encode(uncompressed.slice(keySize + 1)),
  };
};

const getUncompressedPublicKey = (crv: EC256, publicKeyBinary: Uint8Array, keySize: number): Uint8Array => {
  if (publicKeyBinary.length === 2 * keySize) {
    return addUncompressedEncoding(publicKeyBinary);
  } else if (publicKeyBinary.length < 2 * keySize) {
    const ec = new EC(JWK_TO_ELLIPTIC_CURVE_NAMES[crv]);
    // compressed already
    return Uint8Array.from(ec.keyFromPublic(publicKeyBinary).getPublic().encode('array', false));
  }
  return publicKeyBinary; // already with the prefix
};

export const jwkPublicToRaw = (jwk: JWK, compressed = true, encodeUncompressed = false): Uint8Array => {
  if (!(jwk.crv in JWK_TO_ELLIPTIC_CURVE_NAMES)) {
    throw new Error(`Unsupported curve: ${jwk.crv}`);
  }
  if (jwk.crv === 'X25519') {
    return base64.decode(jwk.x);
  }

  const keySize = keySizeFromName(jwk.crv);
  const yArr = base64.decode(jwk.y);
  const xArr = base64.decode(jwk.x);

  if (!compressed) {
    const offset = encodeUncompressed ? 1 : 0;
    const totalSize = 2 * keySize + offset;
    const uncompressedPublicKey = new Uint8Array(totalSize);
    if (encodeUncompressed) {
      uncompressedPublicKey[0] = ENC_UNCOMPRESSED;
    }
    uncompressedPublicKey.set(xArr, offset);
    uncompressedPublicKey.set(yArr, keySize + offset);

    return uncompressedPublicKey;
  }

  return addCompressedEncoding(xArr, yArr);
};

export const jwkPrivateToRaw = (jwk: JsonWebKey): Uint8Array => {
  if (jwk.kty !== 'EC' && jwk.kty !== 'OKP') {
    throw new Error('Invalid key type: ' + (jwk.kty ?? ''));
  }
  if (!jwk.d) {
    throw new Error('Private key information is missing in JWK key!');
  }

  return base64.decode(jwk.d);
};

export const generateKeyPair = (crv: ECDHCurve): JWK => {
  if (!(crv in JWK_TO_ELLIPTIC_CURVE_NAMES)) {
    throw new Error(`Unsupported curve: ${crv}`);
  }
  if (crv === 'X25519') {
    const keyPair = generateX25519KeyPair();
    return {
      kty: 'OKP',
      crv,
      d: base64.encode(normalizeX25519(keyPair.secretKey)),
      x: base64.encode(keyPair.publicKey),
    } as X25519JWK;
  }
  const ec = new EC(JWK_TO_ELLIPTIC_CURVE_NAMES[crv]);
  const keyPair = ec.genKeyPair();
  const dArr = Uint8Array.from(keyPair.getPrivate().toArray());
  const uncompressed = Uint8Array.from(keyPair.getPublic().encode('array', false));
  const keySize = keySizeFromName(crv);
  return {
    kty: 'EC',
    crv,
    d: base64.encode(dArr),
    x: base64.encode(uncompressed.slice(1, keySize + 1)), // ignore the first '04' byte for uncompressed encoding
    y: base64.encode(uncompressed.slice(keySize + 1)),
  } as EC256JWK;
};

const keySizeFromName = (crv: string): number => {
  const namesToKeySizes = new Map([['256', 32]]);

  const keySize = Array.from(namesToKeySizes).find((entry) => crv.includes(entry[0]))?.[1];

  if (keySize) {
    return keySize;
  }

  throw new Error(`Unsupported curve: ${crv}`);
};

const addUncompressedEncoding = (publicKeyBinary: Uint8Array): Uint8Array => {
  return addCompressionEncoding(publicKeyBinary, ENC_UNCOMPRESSED);
};

const addCompressedEncoding = (x: Uint8Array, y: Uint8Array): Uint8Array => {
  const encodedByte = y[y.length - 1] % 2 === 0 ? 2 : 3;
  return addCompressionEncoding(x, encodedByte);
};

const addCompressionEncoding = (publicKeyBinary: Uint8Array, encodedByte: number): Uint8Array => {
  const result = new Uint8Array(publicKeyBinary.length + 1);
  result[0] = encodedByte;
  result.set(publicKeyBinary, 1);
  return result;
};

const normalizeX25519 = (secretKey: Uint8Array): Uint8Array => {
  const normalized = secretKey.slice();
  normalized[0] &= 248;
  normalized[31] &= 127;
  normalized[31] |= 64;

  return normalized;
};

export const sanitizePublicKey = <T extends JsonWebKey>({ d, ...jwk }: T): T => jwk as T;
