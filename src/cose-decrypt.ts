import { getIV, getRecipientId } from './cose';
import { untranslateHeaders, untranslateKey } from './cose-js/common';
import { ICryptoProvider } from './ICryptoProvider';
import { Cose, Recipient } from './types';

export const decrypt = async function <ECDHKey, CEKKey, KWKey>(
  cose: Cose,
  cryptoProvider: ICryptoProvider<ECDHKey, CEKKey, KWKey>,
): Promise<{ content: Uint8Array; key: JsonWebKey; kid: string }> {
  const recipient = cose[3][0];

  const cekRaw = await cryptoProvider.unwrapKey({
    encryptedKey: recipient[2],
    parameters: {
      epk: fromCOSEKey(cose[3][0][1].epk),
    },
  });

  // TODO: What to do with these..? Move inside? 
  const cek = await cryptoProvider.fromRawCEKKey(cekRaw);
  const iv = getIV(cose);

  return {
    content: await cryptoProvider.decryptAES(cose[2], cek, iv),
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
