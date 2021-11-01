import { getIV, getRecipientId } from './cose';
import { untranslateHeaders, untranslateKey } from './cose-js/common';
import { decryptAES, unwrapKey } from './crypto';
import { DefaultCryptoProvider } from './DefaultCryptoProvider';
import { ICryptoProvider } from './ICryptoProvider';
import { Cose, Recipient } from './types';

const cryptoProvider: ICryptoProvider<CryptoKey, CryptoKey, Uint8Array> = new DefaultCryptoProvider();

export const decrypt = async function (
  cose: Cose,
  recipientPrivate: JsonWebKey,
): Promise<{ content: Uint8Array; key: JsonWebKey; kid: string }> {
  const recipient = cose[3][0];

  const cekRaw = await unwrapKey(recipientPrivate, {
    encryptedKey: recipient[2],
    parameters: {
      epk: fromCOSEKey(cose[3][0][1].epk),
    },
  });

  const cek = await cryptoProvider.fromRawCEKKey(cekRaw);
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
      iv: untranslateHeaders(cose[1]).get('iv') as Uint8Array,
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
  ] as Recipient;

const fromCOSEKey = (key: CryptoKey): JsonWebKey => Object.fromEntries(untranslateKey(key).entries()) as JsonWebKey;
