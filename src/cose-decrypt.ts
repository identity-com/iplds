import { getIV, getRecipientId } from './cose';
import {
  translateKeyTypeToAlgorithm,
  untranslateHeaders,
  untranslateKey,
} from './cose-js/common';
import { decryptAES, importJWKKey, importRawAESGCMKey } from './crypto';
import { decryptKeyManagement } from './ecdh-es-akw';
import { Cose, Recipient } from './types';
import { cloneRecipient } from './utils';

const ALG_KEY_AGREEMENT = 'ECDH-ES-A256KW'; // -31: https://datatracker.ietf.org/doc/html/rfc8152#section-12.5.1

export const decrypt = async function (
  cose: Cose,
  recipientPrivate: CryptoKey
): Promise<{ content: Uint8Array; key: CryptoKey; kid: string }> {
  const recipient = cloneRecipient(cose[3][0]);

  if (cose[3][0][1].epk) {
    recipient[1].epk = await fromCOSEKey(cose[3][0][1].epk);
  }

  const cekRaw = await decryptKeyManagement(
    ALG_KEY_AGREEMENT,
    recipientPrivate,
    recipient
  );

  const cek = await importRawAESGCMKey(cekRaw);
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

const fromCOSEKey = async (key: CryptoKey): Promise<CryptoKey> => {
  const jwk = Object.fromEntries(untranslateKey(key).entries()) as JsonWebKey;
  return await importJWKKey(jwk, getParameters(jwk));
};

const getParameters = (jwk: JsonWebKey): EcKeyImportParams => ({
  name: translateKeyTypeToAlgorithm(jwk.kty) as string,
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  namedCurve: jwk.crv!,
});
