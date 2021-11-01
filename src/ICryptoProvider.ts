import { DecryptKeyAgreement, KeyAgreement } from './types';

export interface CryptoKeyAgreement<ECDHKey, CEKKey> extends CryptoDecryptKeyAgreement<ECDHKey> {
  cek: Uint8Array | CEKKey;
}

export interface CryptoDecryptKeyAgreement<ECDHKey> {
  encryptedKey: Uint8Array;
  parameters: {
    epk: ECDHKey;
  };
}

export interface ICryptoProvider<ECDHKey, CEKKey, KWKey> {
  // (recipientPublic: JsonWebKey, cek: JsonWebKey): Promise<CryptoKeyAgreement<ECDHKey>>;
  // (recipientPrivate: JsonWebKey, keyAgreement: CryptoDecryptKeyAgreement<ECDHKey, CEKKey>): Promise<KWKey>;

  fromProviderSpecificKeyAgreement(specificAgreement: CryptoKeyAgreement<ECDHKey, CEKKey>): Promise<KeyAgreement>;
  providerSpecificKeyAgreement(keyAgreement: DecryptKeyAgreement): Promise<CryptoDecryptKeyAgreement<ECDHKey>>;

  toECDHKey(jwk: JsonWebKey, usage?: KeyUsage[]): Promise<ECDHKey>;
  fromECDHKey(ecdhKey: ECDHKey): Promise<JsonWebKey>;

  fromRawCEKKey(rawCEKKey: Uint8Array): Promise<JsonWebKey>;
  toRawCEKKey(jwk: JsonWebKey): Promise<Uint8Array>;

  fromCEKKey(cekKey: CEKKey): Promise<JsonWebKey>;
  toCEKKey(jwk: JsonWebKey): Promise<CEKKey>;

  fromKWKey(kwKey: KWKey): Promise<JsonWebKey>;
}
