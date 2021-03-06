import { encode } from 'cborg';
import { ALG_ENCRYPTION, ALG_KEY_AGREEMENT, encryptAES, generateIV, keyAgreement } from '../crypto/crypto';
import { Cose, ECKey, Key, Recipient, Recipients } from '../types/types';
import { translateHeaders, translateKey } from './common';

export const encryptToCOSE = async function (bytes: Uint8Array, key: Key, recipient: ECKey): Promise<Cose> {
  const agreement = await keyAgreement(recipient, key);

  const iv = generateIV();
  const encrypted = await encryptAES(bytes, key, iv);
  return [
    {
      alg: ALG_ENCRYPTION,
    },
    {
      iv,
    },
    encrypted,
    initAESKWRecipients(agreement.encryptedKey, recipient.kid ?? '', agreement.parameters.epk),
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

/**
 *
 * @param encryptedKey
 * @param kid - recipient's key id
 * @param epk - ephemeral public key
 * @returns ECDH-AKW Recipient layer of the COSE structure
 */
const initAESKWRecipients = (encryptedKey: Key, kid: string, epk: ECKey): Recipients => {
  const recipient: Recipient = [
    {
      alg: ALG_KEY_AGREEMENT,
    },
    {
      kid: kid,
      epk: toCOSEKey(epk),
    },
    encryptedKey,
    [],
  ];

  return [recipient] as Recipients;
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

const toCOSEKey = (key: ECKey): ECKey => {
  const coseKey = { ...key };

  delete coseKey.key_ops;
  delete coseKey.ext;
  delete coseKey.use;

  return Object.fromEntries(translateKey(coseKey)) as unknown as ECKey;
};
