import { getIV, getRecipientId } from './cose';
import { untranslateHeaders, untranslateKey } from './cose-js/common';
import { decryptAES, decryptKeyManagement } from './crypto';
import { Cose, Dictionary, ECKey, Key, Recipient } from './types';
import { cloneRecipient } from './utils';

export const decrypt = async function (
  cose: Cose,
  recipientPrivate: ECKey,
): Promise<{ content: Uint8Array; key: Key; kid: string }> {
  const recipient = cloneRecipient(cose[3][0]);

  recipient[1].epk = fromCOSEKey(cose[3][0][1].epk);

  const cek = await decryptKeyManagement(recipient[0].alg, recipientPrivate, recipient);

  const iv = getIV(cose);

  return {
    content: await decryptAES(cose[2], cek, iv),
    key: cek,
    kid: getRecipientId(cose),
  };
};

export const translate = (cose: Cose): Cose =>
  [
    Object.fromEntries(untranslateHeaders(cose[0])),
    {
      iv: untranslateHeaders(cose[1]).get('iv') as unknown as Uint8Array,
    },
    cose[2],
    cose[3].map(translateRecipient),
  ] as Cose;

const translateRecipient = (recipient: Recipient): Recipient =>
  [
    Object.fromEntries(untranslateHeaders(recipient[0])),
    Object.fromEntries(untranslateHeaders(recipient[1])),
    recipient[2],
    recipient[3].map(translateRecipient),
  ] as unknown as Recipient;

const fromCOSEKey = (key: ECKey): ECKey =>
  Object.fromEntries(untranslateKey(key as unknown as Dictionary<unknown>).entries()) as unknown as ECKey;
