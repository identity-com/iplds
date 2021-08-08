import type { KeyLike } from 'jose/webcrypto/types';

// TODO: translate into types (tuples)
export type CoseAlg = {
    alg : string
} 

export type Cose = [CoseAlg, CoseAesGcmParams, Uint8Array, Array<Recipient>];
export type Recipient = [CoseAlg, RecipientAddress, Uint8Array, Array<Recipient>];

export function getCEK(cose: Cose): Uint8Array {
    return cose[3][0][2];
}

export function getContent(cose: Cose): any {
    return cose[2];
}


// export class Cose {
//     protected: Object = {};
//     unprotected: CoseAesGcmParams = new CoseAesGcmParams;
//     message: Uint8Array = new Uint8Array;
//     recipients: Array<Recipient> = [];
// }

// export class Recipient {
//     protected: Object = {};
//     unprotected: any = {};
//     ciphertext: Object = {};
//     recipients: Recipient[] = [];
// }

export class RecipientAddress {
    kid: string = '';
    epk: KeyLike = new Uint8Array;
}

export class CoseAesGcmParams {
    iv: Uint8Array = new Uint8Array;
}
