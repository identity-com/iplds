import { encode } from 'cborg';
import { translateHeaders, translateKey } from './cose-js/common';
import { encryptAES, exportJWKKey, generateIV } from './crypto';
import { Cose, KeyAgreement, Recipient } from './types';

const ALG_ENCRYPTION = 'A256GCM';
const ALG_KEY_AGREEMENT = 'ECDH-ES-A256KW'; // -31: https://datatracker.ietf.org/doc/html/rfc8152#section-12.5.1

export const encryptRaw = async function (
  encoded: Uint8Array,
  recipientKID: string,
  keyAgreement: KeyAgreement,
): Promise<Uint8Array> {
  const cose = await encryptToCOSE(encoded, recipientKID, keyAgreement);
  return encodeCOSE(cose);
};

export const encryptToCOSE = async function (
  encoded: Uint8Array,
  recipientKID: string,
  keyAgreement: KeyAgreement,
): Promise<Cose> {
  const iv = generateIV();

  const res = await encryptAES(encoded, keyAgreement.cek, iv);

  return [
    {
      alg: ALG_ENCRYPTION,
    },
    {
      iv,
    },
    res,
    await initAESKWRecipients(keyAgreement.encryptedKey, recipientKID, keyAgreement.parameters.epk),
  ];
};

export const encodeCOSE = (cose: Cose): Uint8Array => {
  try {
    return encode(translate(cose));
  } catch (e) {
    console.error(e);
    throw e;
  }
};

export const encrypt = async (
  plainObj: unknown,
  recipientPublicKID: string,
  keyMgmt: KeyAgreement,
): Promise<Uint8Array> => await encryptRaw(encode(plainObj), recipientPublicKID, keyMgmt);

/**
 *
 * @param encryptedKey
 * @param kid - recipient's key id
 * @param epk - ephemeral public key
 * @returns ECDH-AKW Recipient layer of the COSE structure
 */
const initAESKWRecipients = async (encryptedKey: Uint8Array, kid: string, epk: CryptoKey): Promise<Recipient[]> => {
  const single: Recipient = [
    {
      alg: ALG_KEY_AGREEMENT,
    },
    {
      kid: kid,
      epk: toCOSEKey(await exportJWKKey(epk)),
    },
    encryptedKey,
    [],
  ];

  return [single];
};

const translate = (cose: Cose): Array<unknown> => [
  translateHeaders(cose[0]),
  translateHeaders(cose[1]),
  cose[2],
  cose[3].map(translateRecipient),
];

const translateRecipient = (recipient: Recipient): Array<unknown> => [
  translateHeaders(recipient[0]),
  translateHeaders(recipient[1]),
  recipient[2],
  recipient[3].map(translateRecipient),
];

const toCOSEKey = (key: JsonWebKey): CryptoKey => {
  delete key.key_ops;
  delete key.ext;

  key.kty = key.kty === 'EC' ? 'EC2' : key.kty;

  return Object.fromEntries(translateKey(key)) as CryptoKey;
};
