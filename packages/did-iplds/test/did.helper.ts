/* eslint-disable sonarjs/no-duplicate-string */
import { JWK, jwkPublicToRaw } from '@identity.com/jwk';
import { DIDDocument } from 'did-resolver';
import { encoding } from 'multibase';

export const didDocument = ({
  kid,
  publicKeyBase58 = '2CGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7',
  verificationType = 'X25519KeyAgreementKey2019',
}: {
  kid?: string;
  publicKeyBase58?: string;
  verificationType?: string;
}): DIDDocument => ({
  '@context': ['https://w3id.org/did/v1.0', 'https://w3id.org/sol/v1'],
  id: `did:sol:devnet:${publicKeyBase58}`,
  controller: [],
  verificationMethod: [
    {
      id: kid ?? `did:sol:devnet:${publicKeyBase58}#default`,
      type: verificationType,
      controller: `did:sol:devnet:${publicKeyBase58}`,
      publicKeyBase58: publicKeyBase58,
    },
  ],
  authentication: [],
  assertionMethod: [],
  keyAgreement: [],
  capabilityInvocation: [`did:sol:devnet:${publicKeyBase58}#default`],
  capabilityDelegation: [],
  service: [],
  publicKey: [
    {
      id: kid ?? `did:sol:devnet:${publicKeyBase58}#default`,
      type: verificationType,
      controller: `did:sol:devnet:${publicKeyBase58}`,
      publicKeyBase58: publicKeyBase58,
    },
  ],
});

export const toBase58 = (publicKey: JWK): string => encoding('base58btc').encode(jwkPublicToRaw(publicKey));
