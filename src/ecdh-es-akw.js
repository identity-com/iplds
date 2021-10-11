import { encoder, uint32be, lengthAndInput, concatKdf } from './buffer-utils';
import { Crypto } from '@peculiar/webcrypto';
import { concat } from './utils';
import { CRV_ALG } from './cose-js/common';

const crypto = new Crypto();

export const ecdh_es_a256kw = async (
  alg,
  enc,
  recipientPublic,
  providedCek,
  providedParameters = {}
) => {
  let encryptedKey;
  let parameters = {};
  let cek;

  if (!ecdhAllowed(recipientPublic.algorithm.namedCurve)) {
    throw new Error(
      'ECDH-ES with the provided key is not allowed or not supported by your javascript runtime'
    );
  }
  const { apu, apv } = providedParameters;
  let { epk: ephemeralKeyPair } = providedParameters;
  ephemeralKeyPair ||
    (ephemeralKeyPair = await generateEpk(
      recipientPublic.algorithm.namedCurve
    ));
  // const { x, y, crv, kty } = await fromKeyLike(ephemeralKey);
  const sharedSecret = await deriveKey(
    recipientPublic,
    ephemeralKeyPair.privateKey,
    alg,
    parseInt(alg.substr(-5, 3), 10),
    apu,
    apv
  );
  // parameters = { epk: { x, y, crv, kty } };
  //   if (apu) parameters.apu = b64encode(apu);
  //   if (apv) parameters.apv = b64encode(apv);

  cek = providedCek || generateCek(enc);

  encryptedKey = await wrap(sharedSecret, cek);

  parameters.epk = ephemeralKeyPair.publicKey;
  return { cek, encryptedKey, parameters };
};

export const decryptKeyManagement = async (
  alg,
  recipientPrivate,
  ecdhRecipient
) => {
  // Direct Key Agreement
  if (!ecdhAllowed(recipientPrivate.algorithm.namedCurve)) {
    throw 'ECDH-ES with the provided key is not allowed or not supported by your javascript runtime';
  }

  let partyUInfo;
  let partyVInfo;
  if (ecdhRecipient.apu !== undefined) {
    partyUInfo = base64url(ecdhRecipient.apu);
  }
  if (ecdhRecipient.apv !== undefined) {
    partyVInfo = base64url(ecdhRecipient.apv);
  }
  const sharedSecret = await deriveKey(
    ecdhRecipient[1].epk,
    recipientPrivate,
    alg,
    parseInt(alg.substr(-5, 3), 10),
    partyUInfo,
    partyVInfo
  );

  // Key Agreement with Key Wrapping
  return unwrap(sharedSecret, ecdhRecipient[2]);
};

export const deriveKey = async (
  publicKey,
  privateKey,
  algorithm,
  keyLength,
  apu = new Uint8Array(0),
  apv = new Uint8Array(0)
) => {
  const value = concat(
    lengthAndInput(encoder.encode(algorithm)),
    lengthAndInput(apu),
    lengthAndInput(apv),
    uint32be(keyLength)
  );
  if (!privateKey.usages.includes('deriveBits')) {
    throw new TypeError(
      'ECDH-ES private key "usages" must include "deriveBits"'
    );
  }
  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: CRV_ALG[privateKey.algorithm.namedCurve],
        public: publicKey,
      },
      privateKey,
      Math.ceil(parseInt(privateKey.algorithm.namedCurve.substr(-3), 10) / 8) <<
        3
    )
  );
  return concatKdf(digest, sharedSecret, keyLength, value);
};

// TODO: validate curve?
const generateEpk = async (crv) =>
  await crypto.subtle.generateKey({ name: CRV_ALG[crv], namedCurve: crv }, true, [
    'deriveBits',
  ]);

const ecdhAllowed = (crv) => ['P-256', 'P-384', 'P-521', 'K-256', 'X25519'].includes(crv);

const digest = async (algorithm, data) => {
  const subtleDigest = `SHA-${algorithm.substr(-3)}`;
  return new Uint8Array(await crypto.subtle.digest(subtleDigest, data));
};

const bitLengths = new Map([
  ['A128CBC-HS256', 256],
  ['A128GCM', 128],
  ['A192CBC-HS384', 384],
  ['A192GCM', 192],
  ['A256CBC-HS512', 512],
  ['A256GCM', 256],
]);

const factory = (random) => (alg) => {
  const bitLength = bitLengths.get(alg);
  if (!bitLength) {
    throw new Error(`Unsupported JWE Algorithm: ${alg}`);
  }
  return random(new Uint8Array(bitLength >> 3));
};

const generateCek = factory(crypto.getRandomValues.bind(crypto));

const wrap = async (key, cek) => {
  const cryptoKey = await getCryptoKey(key, ['wrapKey']);

  return new Uint8Array(
    await crypto.subtle.wrapKey('raw', cek, cryptoKey, 'AES-KW')
  );
};

const unwrap = async (key, encryptedKey) => {
  const cryptoKey = await getCryptoKey(key, ['unwrapKey']);
  const cryptoKeyCek = await crypto.subtle.unwrapKey(
    'raw',
    encryptedKey,
    cryptoKey,
    'AES-KW',
    { hash: { name: 'SHA-256' }, name: 'HMAC' },
    true,
    ['sign']
  );

  return new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKeyCek));
};

const getCryptoKey = async (key, usage) => {
  if (key instanceof Uint8Array) {
    return await crypto.subtle.importKey('raw', key, 'AES-KW', true, usage);
  }
  return key; // is CryptoKey
};
