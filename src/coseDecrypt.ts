import { Cose, Recipient } from "./cose";
import { decryptKeyManagement } from './ecdh-es-akw.js';
import { Crypto } from '@peculiar/webcrypto';
import { UntranslateHeaders, UntranslateKey } from "./cose-js/common";
import { decode } from 'cborg';

const crypto = new Crypto();

const ALG_KEY_AGREEMENT = 'ECDH-ES-A256KW'; // -31: https://datatracker.ietf.org/doc/html/rfc8152#section-12.5.1

export async function decrypt(coseCBOR: Uint8Array, recipientPrivate: CryptoKey): Promise<Cose> {
    const cose = toCOSE(coseCBOR);
    console.debug(`converted: ${cose}`);

    if (cose[3][0][1].epk)
        cose[3][0][1].epk = await fromCOSEKey(cose[3][0][1].epk);

    const cekRaw = await decryptKeyManagement(
        ALG_KEY_AGREEMENT, 
        recipientPrivate, 
        cose[3][0]);

    const params: AesGcmParams = {
        name: 'AES-GCM',
        iv: cose[1].iv
    };
    
    const cek = await crypto.subtle.importKey(
        "raw",
        cekRaw,
        "AES-GCM",
        true,
        ["encrypt", "decrypt"]
    );

    cose[2] = new Uint8Array(await crypto.subtle.decrypt(params, cek , cose[2]));
    cose[3][0][2] = cekRaw;

    return cose;
}

function toCOSE(cbor: Uint8Array): Cose {
    const decoded = decode(cbor);

    return translate(decoded);
}

function translate(cose: Array<any>): Cose {
    return [
        Object.fromEntries(UntranslateHeaders(cose[0])),
        {
            iv: UntranslateHeaders(cose[1]).get('iv')
        },
        cose[2],
        cose[3].map(translateRecipient)
    ];
}

function translateRecipient(recipient: Array<any>): Recipient {
    return [
        Object.fromEntries(UntranslateHeaders(recipient[0])),
        Object.fromEntries(UntranslateHeaders(recipient[1])),
        recipient[2],
        
        recipient[3].map(translateRecipient)
    ];
}

async function fromCOSEKey(key: any): Promise<CryptoKey> {
    const jwk: JsonWebKey = Object.fromEntries(UntranslateKey(key).entries());
    return await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
}
