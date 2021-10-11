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
  publicKey?: CryptoKey;
  privateKey?: CryptoKey;
  keyId?: string;
  deterministicCID?: boolean;
};

export type ECDHCurve = keyof typeof KEY_CRV;

export interface CIDMetadata {
  key: CryptoKey;
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
  epk?: CryptoKey;
};

export type CoseAesGcmParams = {
  iv: Uint8Array;
};

export type KeyAgreement = {
  cek: CryptoKey;
  encryptedKey: Uint8Array;
  parameters: {
    epk: CryptoKey;
  };
};

export type MetadataOrComplexObject = Metadata | ComplexObject;
