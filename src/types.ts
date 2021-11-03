import { CID } from 'ipfs-http-client';
import { Metadata } from './metadata';
import { ComplexObject } from './utils';
import { KEY_CRV } from './cose-js/common';

export type Key = CryptoKey;

export type Link = {
  path: string;
  cid: CID;
  iv: Uint8Array; // IV used to encrypt the CID
};

export type ECDHCurve = keyof typeof KEY_CRV;

export interface CIDMetadata {
  key: Key;
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
  epk?: Key;
};

export type CoseAesGcmParams = {
  iv: Uint8Array;
};

export type KeyAgreement = {
  cek: Key;
  encryptedKey: Uint8Array;
  parameters: {
    epk: Key;
  };
};

export type MetadataOrComplexObject = Metadata | ComplexObject;

export type RecipientInfo = {
  publicKey: Key;
  kid: string;
};

export type AESEncryption = {
  key: Key;
  iv: Uint8Array;
};
