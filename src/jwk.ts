import { ec as EC } from 'elliptic';
import { generateKeyPair as generateX25519KeyPair } from '@stablelib/x25519';
import { URLSafeCoder } from '@stablelib/base64';
import { ECDHCurve } from './types';

const JWK_TO_ELLIPTIC_CURVE_NAMES = {
  'K-256': 'secp256k1',
  'P-256': 'p256',
  X25519: 'X25519',
};

const base64 = new URLSafeCoder();

const X25519 = 'X25519';

const ENC_UNCOMPRESSED = 4;

export const toJWK = (publicKey: Uint8Array, crv: ECDHCurve): JsonWebKey => {
  if (crv === 'X25519') {
    return toJWK25519(publicKey);
  }

  return toJWKEC(crv, publicKey);
};

const toJWK25519 = (publicKeyBinary: Uint8Array): JsonWebKey => ({
  kty: 'OKP',
  crv: X25519,
  x: base64.encode(publicKeyBinary),
});

/**
 * Converting P-256 / P-384 / secp256k1 raw public keys to JWK
 * @param crv - JWK.crv compatible curve name
 * @param publicKeyBinary - Compressed or uncompressed public key
 */
const toJWKEC = (crv: ECDHCurve, publicKeyBinary: Uint8Array): JsonWebKey => {
  const keySize = 256;
  const uncompressed = getUncompressedPublicKey(crv, publicKeyBinary, keySize);

  return {
    crv,
    kty: 'EC',
    x: base64.encode(uncompressed.slice(1, keySize + 1)), // ignore the first '04' byte for uncompressed encoding
    y: base64.encode(uncompressed.slice(keySize + 1)),
  };
};

const getUncompressedPublicKey = (crv: ECDHCurve, publicKeyBinary: Uint8Array, keySize: number): Uint8Array => {
  const ec = new EC(JWK_TO_ELLIPTIC_CURVE_NAMES[crv]);
  if (publicKeyBinary.length <= 2 * keySize) {
    return publicKeyBinary;
  }
  return Uint8Array.from(ec.keyFromPublic(addUncompressedEncoding(publicKeyBinary)).getPublic().encode('array', false));
};

export const jwkPublicToRaw = (jwk: JsonWebKey, compressed = true, encodeUncompressed = false): Uint8Array => {
  if (!jwk.crv) {
    throw new Error('Unsupported key type');
  }
  if (!(jwk.crv in JWK_TO_ELLIPTIC_CURVE_NAMES)) {
    throw new Error(`Unsupported curve: ${jwk.crv}`);
  }
  if (jwk.crv === X25519) {
    return base64.decode(jwk.x!);
  }

  const keySize = keySizeFromName(jwk.crv);
  const yArr = base64.decode(jwk.y!);
  const xArr = base64.decode(jwk.x!);

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

export const generateKeyPair = (crv: ECDHCurve): JsonWebKey => {
  if (crv === X25519) {
    const keyPair = generateX25519KeyPair();
    return {
      kty: 'OKP',
      crv,
      d: base64.encode(normalizeX25519(keyPair.secretKey)),
      x: base64.encode(keyPair.publicKey),
    };
  } else if (crv in JWK_TO_ELLIPTIC_CURVE_NAMES) {
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
    };
  }

  throw new Error(`Unsupported curve: ${crv}`);
};

const keySizeFromName = (crv: string): number => {
  const namesToKeySizes = new Map([
    ['256', 32],
    ['384', 48],
  ]);

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

export const sanitizePublicKey = ({ d, ...jwk }: JsonWebKey): JsonWebKey => jwk;
