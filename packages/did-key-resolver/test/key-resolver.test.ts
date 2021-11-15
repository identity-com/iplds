import { resolve } from '@identity.com/sol-did-client';
import { encoding } from 'multibase';
import { DIDKeyResolver } from '../src/key-resolver';

describe('Solana key resolver', () => {
  it('should resolve key from a sample DID', async () => {
    const base58 = encoding('base58btc');

    const controllerPublicBase58 = '2CGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7';
    // const keyPair = nacl.sign.keyPair(); airdropped to
    // const publicKey = base58.decode(controllerPublicBase58);
    // const controller = base58.decode(
    //   '4VEYzWVLBxQhR2YPMEooLLQeZSPkon5W5hrshwca1uSJSyuXHcPrvv2QJ1TJ8w8rXh5Pzpoj2FW6VnDcVb4TLRUZ',
    // );

    // const didId = await register({
    //   payer: controller,
    //   cluster: ClusterType.devnet(),
    // });

    // const keyAgreementPair = nacl.box.keyPair();
    const publicKeyBase58 = 'CDbBA74pK4QH7wXc7JhW8zpkfzgApEugoSGa1Zz7FNPR';
    const keyAgreementPublicKey = base58.decode(publicKeyBase58);

    const didId = `did:sol:devnet:${controllerPublicBase58}`;

    // update a DID
    // const request = {
    //   payer: keyPair.secretKey,
    //   identifier: didId,
    //   document: {
    //     service: [{
    //       description: 'Messaging Service',
    //       id: `${didId}#service1`,
    //       serviceEndpoint: `https://dummmy.dummy/${didId}`,
    //       type: 'Messaging',
    //     }],
    //   },
    // };
    // await update(request);

    // const controllerId = `did:sol:${controllerBase58}`;
    // const keyAgreementId = `${controllerId}#delegate1`;
    // const request = {
    //   payer: controller,
    //   identifier: didId,
    //   document: {
    //     verificationMethod: [
    //       {
    //         id: keyAgreementId,
    //         type: 'X25519KeyAgreementKey2019',
    //         controller: controllerId,
    //         publicKeyBase58: publicKeyBase58,
    //       },
    //     ],
    //     keyAgreement: [keyAgreementId],
    //   },
    // };
    // await update(request);

    const did = await resolve(didId);
    const jwk = new DIDKeyResolver().resolveKey(did, `${didId}#delegate1`);
    expect(jwk.x).toStrictEqual(encoding('base64url').encode(keyAgreementPublicKey));
  });
});

/*
    {
      '@context': [ 'https://w3id.org/did/v1.0', 'https://w3id.org/sol/v1' ],
      id: 'did:sol:devnet:2CGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7',
      controller: [],
      verificationMethod: [
        {
          id: 'did:sol:devnet:2CGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7#default',
          type: 'Ed25519VerificationKey2018',
          controller: 'did:sol:devnet:2CGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7',
          publicKeyBase58: '2CGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7'
        }
      ],
      authentication: [],
      assertionMethod: [],
      keyAgreement: [],
      capabilityInvocation: [
        'did:sol:devnet:2CGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7#default'
      ],
      capabilityDelegation: [],
      service: [],
      publicKey: [
        {
          id: 'did:sol:devnet:2CGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7#default',
          type: 'Ed25519VerificationKey2018',
          controller: 'did:sol:devnet:2CGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7',
          publicKeyBase58: '2CGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7'
        }
      ]
    }
*/
