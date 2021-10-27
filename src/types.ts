import { CID } from 'ipfs-http-client';
import { Metadata } from './metadata';
import { ComplexObject } from './utils';
import { KEY_CRV } from './cose-js/common';

export type Link = {
  path: string;
  cid: CID;
  iv: Uint8Array; // IV used to encrypt the CID
};

export type SecureContextConfig = {
  publicKey?: JsonWebKey;
  privateKey?: JsonWebKey;
  keyId?: string;
  deterministicCID?: boolean;
};

export type ECDHCurve = keyof typeof KEY_CRV;

export interface CIDMetadata {
  key: JsonWebKey;
  iv: Uint8Array;
  links?: Link[];
}

export type CoseAlg = {
  alg: string;
};

export type Cose = [CoseAlg, CoseAesGcmParams, Uint8Array, Array<Recipient>];

export type Recipient = [CoseAlg, RecipientAddress, Uint8Array, Array<Recipient>];

export type RecipientAddress = {
  kid: string;
  epk: CryptoKey;
};

export type CoseAesGcmParams = {
  iv: Uint8Array;
};

export interface KeyAgreement extends DecryptKeyAgreement {
  cek: JsonWebKey;
}

export interface DecryptKeyAgreement {
  encryptedKey: Uint8Array;
  parameters: {
    epk: JsonWebKey;
  };
}

export type MetadataOrComplexObject = Metadata | ComplexObject;
