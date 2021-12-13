import { DIDDocument } from 'did-resolver';

export const keyBase58 = 'Eh1CPnKc9m6eHfYjvqKPGgY8TYedJCRLE9Pari3GU5s6';
export const did = `did:sol:${keyBase58}`;
export const kid = `${did}$default`;

const didContext = ['https://w3id.org/did/v1.0', 'https://w3id.org/sol/v1'];
export const capabilityInvocationOnly: DIDDocument = {
  '@context': didContext,
  id: did,
  controller: [],
  verificationMethod: [
    {
      id: kid,
      type: 'X25519KeyAgreementKey2019',
      controller: did,
      publicKeyBase58: keyBase58,
    },
  ],
  authentication: [],
  assertionMethod: [],
  keyAgreement: [],
  capabilityInvocation: [kid],
  capabilityDelegation: [],
  service: [],
  publicKey: [
    {
      id: kid,
      type: 'X25519KeyAgreementKey2019',
      controller: did,
      publicKeyBase58: keyBase58,
    },
  ],
};

export const keyAgreementOnly: DIDDocument = {
  '@context': didContext,
  id: did,
  controller: [],
  verificationMethod: [
    {
      id: kid,
      type: 'X25519KeyAgreementKey2019',
      controller: did,
      publicKeyBase58: keyBase58,
    },
  ],
  authentication: [],
  assertionMethod: [],
  keyAgreement: [kid],
  capabilityInvocation: [],
  capabilityDelegation: [],
  service: [],
  publicKey: [
    {
      id: kid,
      type: 'X25519KeyAgreementKey2019',
      controller: did,
      publicKeyBase58: keyBase58,
    },
  ],
};

export const noIndexSections: DIDDocument = {
  '@context': didContext,
  id: did,
  controller: [],
  verificationMethod: [
    {
      id: kid,
      type: 'X25519KeyAgreementKey2019',
      controller: did,
      publicKeyBase58: keyBase58,
    },
  ],
  authentication: [],
  assertionMethod: [],
  keyAgreement: [],
  capabilityInvocation: [],
  capabilityDelegation: [],
  service: [],
  publicKey: [
    {
      id: kid,
      type: 'X25519KeyAgreementKey2019',
      controller: did,
      publicKeyBase58: keyBase58,
    },
  ],
};

export const messedUpIndex: DIDDocument = {
  '@context': didContext,
  id: did,
  controller: [],
  verificationMethod: [
    {
      id: kid,
      type: 'X25519KeyAgreementKey2019',
      controller: did,
      publicKeyBase58: keyBase58,
    },
  ],
  authentication: [],
  assertionMethod: [],
  keyAgreement: ['WRONG-KEY-NAME'],
  capabilityInvocation: [],
  capabilityDelegation: [],
  service: [],
};

export const base64Key: DIDDocument = {
  '@context': didContext,
  id: did,
  controller: [],
  verificationMethod: [
    {
      id: kid,
      type: 'X25519KeyAgreementKey2019',
      controller: did,
      publicKeyBase64: 'y2dibwauhvi99eyyPWbYI0WcdpV1NDJNOf7nleYTyRE',
    },
  ],
  authentication: [],
  assertionMethod: [],
  keyAgreement: [kid],
  capabilityInvocation: [],
  capabilityDelegation: [],
  service: [],
};

export const baseMultibaseKey: DIDDocument = {
  '@context': didContext,
  id: did,
  controller: [],
  verificationMethod: [
    {
      id: kid,
      type: 'X25519KeyAgreementKey2019',
      controller: did,
      publicKeyMultibase: `z${keyBase58}`,
    },
  ],
  authentication: [],
  assertionMethod: [],
  keyAgreement: [kid],
  capabilityInvocation: [],
  capabilityDelegation: [],
  service: [],
};

export const hexKey: DIDDocument = {
  '@context': didContext,
  id: did,
  controller: [],
  verificationMethod: [
    {
      id: kid,
      type: 'X25519KeyAgreementKey2019',
      controller: did,
      publicKeyHex: '0xcb67626f06ae86f8bdf5ecb23d66d823459c76957534324d39fee795e613c911',
    },
  ],
  authentication: [],
  assertionMethod: [],
  keyAgreement: [kid],
  capabilityInvocation: [],
  capabilityDelegation: [],
  service: [],
};

export const hexKeyNoPrefix: DIDDocument = {
  '@context': didContext,
  id: did,
  controller: [],
  verificationMethod: [
    {
      id: kid,
      type: 'X25519KeyAgreementKey2019',
      controller: did,
      publicKeyHex: 'cb67626f06ae86f8bdf5ecb23d66d823459c76957534324d39fee795e613c911',
    },
  ],
  authentication: [],
  assertionMethod: [],
  keyAgreement: [kid],
  capabilityInvocation: [],
  capabilityDelegation: [],
  service: [],
};

export const blsTypeKey: DIDDocument = {
  '@context': didContext,
  id: did,
  controller: [],
  verificationMethod: [
    {
      id: kid,
      type: 'Bls12381G2Key2020',
      controller: did,
      publicKeyBase58:
        '25ETdUZDVnME6yYuAMjFRCnCPcDmYQcoZDcZuXAfeMhXPvjZg35QmZ7uctBcovA69YDM3Jf7s5BHo4u1y89nY6mHiji8yphZ4AMm4iNCRh35edSg76Dkasu3MY2VS9LnuaVQ',
    },
  ],
  authentication: [],
  assertionMethod: [],
  keyAgreement: [kid],
  capabilityInvocation: [],
  capabilityDelegation: [],
  service: [],
};

export const jsonTypeKey: DIDDocument = {
  '@context': didContext,
  id: did,
  controller: [],
  verificationMethod: [
    {
      id: kid,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwk: {
        crv: 'P-256',
        x: '38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8',
        y: 'nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4',
        kty: 'EC',
        kid,
      },
    },
  ],
  authentication: [],
  assertionMethod: [],
  keyAgreement: [kid],
  capabilityInvocation: [],
  capabilityDelegation: [],
  service: [],
};

export const secpTypeKey: DIDDocument = {
  '@context': didContext,
  id: did,
  controller: [],
  verificationMethod: [
    {
      id: kid,
      type: 'EcdsaSecp256k1VerificationKey2019',
      controller: did,
      publicKeyJwk: {
        crv: 'secp256k1',
        x: 'NtngWpJUr-rlNNbs0u-Aa8e16OwSJu6UiFf0Rdo1oJ4',
        y: 'qN1jKupJlFsPFc1UkWinqljv4YE0mq_Ickwnjgasvmo',
        kty: 'EC',
        kid: kid,
      },
    },
  ],
  authentication: [],
  assertionMethod: [],
  keyAgreement: [kid],
  capabilityInvocation: [],
  capabilityDelegation: [],
  service: [],
};
