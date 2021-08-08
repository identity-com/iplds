// import encryptKeyManagement from "../node_modules/jose/src/lib/encrypt_key_management";
import { Crypto } from '@peculiar/webcrypto';
import { encode } from 'cborg';
// const encryptKeyManagement = require('../node_modules/jose/dist/browser/lib/encrypt_key_management.js');
// import { decode as b64decode } from 'jose/util/base64url';
import { Cose, Recipient } from './cose';
import { TranslateHeaders, TranslateKey } from './cose-js/common.js';
import { ecdh_es_a256kw } from './ecdh-es-akw.js';

const crypto = new Crypto();

// import { KeyLike } from '../node_modules/jose/src/jwe/flattened/encrypt';
// import { decode as b64decode } from '../node_modules/jose/src/runtime/browser/base64url'

export const SUBTLE_ENCRYPTION_ALG = 'AES-GCM';
const ALG_ENCRYPTION = 'A256GCM';
const ALG_KEY_AGREEMENT = 'ECDH-ES-A256KW'; // -31: https://datatracker.ietf.org/doc/html/rfc8152#section-12.5.1
// const ALG_KEY_WRAP = 'A256KW';
const IV_BITS = 96;
export const IV_BYTES = IV_BITS/8;

// TODO: Business: Our message to Receiver is unauthenticated because of -ES - he can't know it comes from us.
export async function encrypt(plainObj: Object, receiverPublicKID: string, keyMgmt: any) {

    const randomIV = generateIV();

    const params: AesGcmParams = {
        name: SUBTLE_ENCRYPTION_ALG,
        iv: randomIV
    };

    const res = new Uint8Array(await crypto.subtle.encrypt(params, keyMgmt.cek , encode(plainObj)));
    const cose: Cose = [
        {
            alg: ALG_ENCRYPTION
        },
        {
            iv: randomIV
        },
        res,
        await initAESKWRecipients(keyMgmt.encryptedKey, receiverPublicKID, keyMgmt.parameters.epk)
    ];

    console.log("ENCRYPTED: " + cose[2]);

    try {
        const result = translate(cose);
        console.log('translated: ' + result);
        console.log(`encoded raw: ${encode(result)}`);
        return encode(result);
    } catch (e) {
        console.error(e);
        throw e;
    }

}

export async function keyAgreement(receiverPublic: CryptoKey, cek: CryptoKey) {
    return ecdh_es_a256kw(
        ALG_KEY_AGREEMENT,
        ALG_ENCRYPTION,
        receiverPublic,
        cek,
        {}
    );
}

/**
 * 
 * @param kid - recepient's key id
 * @param epk - ephemeral public key
 * @returns ECDH-AKW Recipient layer of the COSE structure
 */
 async function initAESKWRecipients(encryptedKey: Uint8Array, kid: string, epk: CryptoKey): Promise<Recipient[]> {
    const single: Recipient = [
        {
            'alg': ALG_KEY_AGREEMENT
        },
        {
            'kid': kid,
            'epk': toCOSEKey(await crypto.subtle.exportKey('jwk', epk))
        },
        encryptedKey,
        []
    ]

    return [single];
}

export function generateIV(): Uint8Array {
    var iv = new Uint8Array(IV_BYTES);
    
    crypto.getRandomValues(iv);

    return iv;
}

function translate(cose: Cose): Array<any> {
    return [
        TranslateHeaders(cose[0]),
        TranslateHeaders(cose[1]),
        cose[2],
        cose[3].map(translateRecipient)
    ];
}

function translateRecipient(recipient: Recipient): Array<any> {
    return [
        TranslateHeaders(recipient[0]),
        TranslateHeaders(recipient[1]),
        recipient[2],
        recipient[3].map(translateRecipient)
    ];
}

function toCOSEKey(key: JsonWebKey) {
    delete key.key_ops;
    delete key.ext;

    key.kty = key.kty === 'EC' ? 'EC2' : key.kty;

    return Object.fromEntries(TranslateKey(key));
}