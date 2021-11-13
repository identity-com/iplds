import { CID } from 'ipfs-http-client';
import { KEY_CRV } from './cose-js/common';
import { Metadata } from './metadata';
import { ComplexObject } from './utils';

export type Key = Uint8Array;
export type ECKey = JWK;

export interface JWK extends JsonWebKey {
  kid?: string;
}

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

export type CoseProtected = {
  alg: string;
};

export type CipherText = Uint8Array;
export type Recipients = Array<Recipient>;

export type Cose = [CoseProtected, CoseUnprotected, CipherText, Recipients];

export type Recipient = [CoseProtected, RecipientAddress, CipherText, Recipients];

export type RecipientAddress = {
  kid: string;
  epk: ECKey;
};

export type CoseUnprotected = {
  iv: Uint8Array;
};

export type KeyAgreement = {
  cek: Key;
  encryptedKey: Key;
  parameters: {
    epk: ECKey;
  };
};

export type MetadataOrComplexObject = Metadata | ComplexObject;

export type AESEncryption = {
  key: Key;
  iv: Uint8Array;
};
