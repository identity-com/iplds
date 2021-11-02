import { Crypto } from '@peculiar/webcrypto';
import { CRV_ALG } from './cose-js/common';
import { DefaultCryptoProvider } from './DefaultCryptoProvider';
import { decryptKeyManagement, ecdh_es_a256kw } from './ecdh-es-akw';
import { ICryptoProvider } from './ICryptoProvider';
import { ECDHCurve, KeyAgreement, SecureContextConfig } from './types';

const ALG_ENCRYPTION = 'A256GCM';
const ALG_KEY_AGREEMENT = 'ECDH-ES-A256KW'; // -31: https://datatracker.ietf.org/doc/html/rfc8152#section-12.5.1
const IV_BITS = 96;
export const IV_BYTES = IV_BITS / 8;

const crypto = new Crypto();
const cryptoProvider: ICryptoProvider<CryptoKey, CryptoKey, Uint8Array> = new DefaultCryptoProvider();

// test only
export const createECKey = async (namedCurve: ECDHCurve = 'P-256'): Promise<SecureContextConfig> => {
  const cryptoKeyPair = await crypto.subtle.generateKey(
    {
      name: CRV_ALG[namedCurve],
      namedCurve,
    },
    true,
    ['deriveBits'],
  );

  return {
    publicKey: await crypto.subtle.exportKey('jwk', cryptoKeyPair.publicKey!),
    privateKey: await crypto.subtle.exportKey('jwk', cryptoKeyPair.privateKey!),
  };
};

// test only
export const createAESGCMKey = async (): Promise<JsonWebKey> =>
  await crypto.subtle.exportKey(
    'jwk',
    await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']),
  );

export const keyAgreement = async (recipientPublic: JsonWebKey, cek: JsonWebKey): Promise<KeyAgreement> =>
  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  cryptoProvider.fromProviderSpecificKeyAgreement(
    await ecdh_es_a256kw(
      ALG_KEY_AGREEMENT,
      ALG_ENCRYPTION,
      await cryptoProvider.toECDHKey(recipientPublic),
      await cryptoProvider.toCEKKey(cek),
      {},
    ),
  );

