import { encoder, concat, uint32be, lengthAndInput, concatKdf } from './buffer_utils.js';
import { fromKeyLike } from 'jose/webcrypto/jwk/from_key_like'
import { encode  as b64encode } from 'jose/util/base64url';
import random from 'jose/util/random';
import { Crypto } from '@peculiar/webcrypto';

const crypto = new Crypto();

export async function ecdh_es_a256kw(alg, enc, recipientPublic, providedCek, providedParameters = {}) {
    let encryptedKey;
    let parameters = {};
    let cek;

    if (!ecdhAllowed(recipientPublic.algorithm.namedCurve)) {
        throw 'ECDH-ES with the provided key is not allowed or not supported by your javascript runtime';
    }
    const { apu, apv } = providedParameters;
    let { epk: ephemeralKeyPair } = providedParameters;
    ephemeralKeyPair || (ephemeralKeyPair = await generateEpk(recipientPublic.algorithm.namedCurve));
    // const { x, y, crv, kty } = await fromKeyLike(ephemeralKey);
    const sharedSecret = await deriveKey(recipientPublic, ephemeralKeyPair.privateKey, alg, parseInt(alg.substr(-5, 3), 10), apu, apv);
    // parameters = { epk: { x, y, crv, kty } };
    if (apu)
        parameters.apu = b64encode(apu);
    if (apv)
        parameters.apv = b64encode(apv);

    cek = providedCek || generateCek(enc);

    const kwAlg = alg.substr(-6);
    encryptedKey = await wrap(kwAlg, sharedSecret, cek);

    parameters.epk = ephemeralKeyPair.publicKey;
    return { cek, encryptedKey, parameters };
}

export async function decryptKeyManagement(alg, recipientPrivate, ecdhRecipient) {
    // Direct Key Agreement
    if (!ecdhAllowed(recipientPrivate.algorithm.namedCurve)) {
        throw 'ECDH-ES with the provided key is not allowed or not supported by your javascript runtime'
    }

    let partyUInfo;
    let partyVInfo;
    if (ecdhRecipient.apu !== undefined) partyUInfo = base64url(ecdhRecipient.apu)
    if (ecdhRecipient.apv !== undefined) partyVInfo = base64url(ecdhRecipient.apv)
    const sharedSecret = await deriveKey(
        ecdhRecipient[1].epk,
        recipientPrivate,
        alg,
        parseInt(alg.substr(-5, 3), 10),
        partyUInfo,
        partyVInfo,
    )

    // Key Agreement with Key Wrapping
    const kwAlg = alg.substr(-6)
    return unwrap(kwAlg, sharedSecret, ecdhRecipient[2]);
}

export const ecdhAllowed = (crv) => {
    return ['P-256', 'P-384', 'P-521'].includes(crv);
};

export const generateEpk = async (crv) => {
    // TODO: validate curve?
    return (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: crv }, true, ['deriveBits']));
};

const digest = async (algorithm, data) => {
    const subtleDigest = `SHA-${algorithm.substr(-3)}`;
    return new Uint8Array(await crypto.subtle.digest(subtleDigest, data));
};

export const deriveKey = async (publicKey, privateKey, algorithm, keyLength, apu = new Uint8Array(0), apv = new Uint8Array(0)) => {
    const value = concat(lengthAndInput(encoder.encode(algorithm)), lengthAndInput(apu), lengthAndInput(apv), uint32be(keyLength));
    if (!privateKey.usages.includes('deriveBits')) {
        throw new TypeError('ECDH-ES private key "usages" must include "deriveBits"');
    }
    const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits({
        name: 'ECDH',
        public: publicKey,
    }, privateKey, Math.ceil(parseInt(privateKey.algorithm.namedCurve.substr(-3), 10) / 8) <<
        3));
    return concatKdf(digest, sharedSecret, keyLength, value);
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
        throw `Unsupported JWE Algorithm: ${alg}`;
    }
    return random(new Uint8Array(bitLength >> 3));
};

const generateCek = factory(random);


function getCryptoKey(key, usage) {
    if (key instanceof Uint8Array) {
        return crypto.subtle.importKey('raw', key, 'AES-KW', true, [usage]);
    } else {
        return key; // is CryptoKey
    }
}

const bogusWebCrypto = [
    { hash: { name: 'SHA-256' }, name: 'HMAC' },
    true,
    ['sign'],
];

export const wrap = async (alg, key, cek) => {
    const cryptoKey = await getCryptoKey(key, 'wrapKey');

    return new Uint8Array(await crypto.subtle.wrapKey('raw', cek, cryptoKey, 'AES-KW'));
};

export const unwrap = async (alg, key, encryptedKey) => {
    const cryptoKey = await getCryptoKey(key, 'unwrapKey');
    const cryptoKeyCek = await crypto.subtle.unwrapKey(
        'raw',
        encryptedKey,
        cryptoKey,
        'AES-KW',
        ...bogusWebCrypto,
      );

      return new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKeyCek))
}

