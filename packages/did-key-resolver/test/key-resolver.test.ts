import { resolve } from '@identity.com/sol-did-client';
import { encoding } from 'multibase';
import { DIDKeyResolver } from '../src/key-resolver';
import { Resolver } from 'did-resolver';
import ethr from 'ethr-did-resolver';

const base58 = encoding('base58btc');
const hex = encoding('base16');
const base64 = encoding('base64url');

describe('Solana key resolver', () => {
  it('should resolve key from a sample DID', async () => {
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

    const did = `did:sol:devnet:${controllerPublicBase58}`;

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

    const didDocument = await resolve(did);
    const jwk = new DIDKeyResolver().resolveKey(didDocument, `${did}#delegate1`);
    expect(jwk.x).toStrictEqual(base64.encode(keyAgreementPublicKey));
  });

  it('should find key in capabilityInvocation[] section', async () => {
    const publicKeyBase58 = '2CGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7';
    const did = `did:sol:${publicKeyBase58}`;
    const doc = await resolve(did);
    const jwk = new DIDKeyResolver().resolveKey(doc, `${did}#default`);
    const resolvedPublicKey = base64.decode(jwk.x);
    expect(resolvedPublicKey).toHaveLength(32);
  });

  it('should convert the key from Ed25519 to X25519', async () => {
    const publicKeyBase58 = '2CGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7';
    const keyAgreementPublicKey = base58.decode(publicKeyBase58);
    const did = `did:sol:${publicKeyBase58}`;
    const doc = await resolve(did);
    const jwk = new DIDKeyResolver().resolveKey(doc, `${did}#default`);

    expect(jwk.crv).toStrictEqual('X25519');

    const resolvedPublicKey = base64.decode(jwk.x);
    expect(resolvedPublicKey).not.toStrictEqual(keyAgreementPublicKey);
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

describe('ETHR key resolver', () => {
  it('should resolve key on a testnet', async () => {
    const providerConfig = {
      name: '0x4',
      rpcUrl: 'https://rinkeby.infura.io/v3/38bae4dd55b942c98e1df206a33f53a5',
    };
    const ethrDidResolver = ethr.getResolver(providerConfig);
    const didResolver = new Resolver(ethrDidResolver);

    const address = '0x420A68929B22bf8A17897f2ca7e3807Bd1D53508';

    // const provider = new ethers.providers.JsonRpcProvider('https://rinkeby.infura.io/v3/38bae4dd55b942c98e1df206a33f53a5');
    // const keyPair = EthrDID.createKeyPair();
    // console.log(`ethr[addr]: ${keyPair.privateKey}`);
    // console.log(`ethr[pub]: ${keyPair.publicKey}`);
    // console.log(`ethr[addr]: ${keyPair.address}`);
    // console.log(`ethr[identifier]: ${keyPair.identifier}`);
    // const publicKey = '0x0383529b3665c5dd455f9354929c345c8e3ebafe1d5ee79fb45f5f4a1367aa34e5'; // identifier too
    // const privateKey = '0xe285785b07bfa96d9cb14e58c90522a5c32ccc5575b2fd1b7555b854e9399bd6';
    // const wallet = new ethers.Wallet(privateKey, provider);
    // const ethrDid = new EthrDID({
    //   identifier: publicKey,
    //   provider,
    //   txSigner: wallet,
    // });

    // const keyAgreementPair = nacl.box.keyPair();
    // const base58 = base58;
    // const kxPriv = 'cf732e388858d5d437cda035b466829b4dec2700491112c02bddade8c3edc899';
    // console.log(`kx[priv]: ${hex.encode(keyAgreementPair.secretKey)}`);
    // console.log(`kx[pub]: ${hex.encode(keyAgreementPair.publicKey)}`);

    // did/pub/(Secp256k1|RSA|Ed25519|X25519)/(veriKey|sigAuth|enc)/(hex|base64|base58)
    /*
    const res = await ethrDid.setAttribute(
        `did/pub/X25519/${DelegateTypes.enc}/base58`,
        base58.encode(kxPub),
      );
    */

    const kxPub = hex.decode('cb67626f06ae86f8bdf5ecb23d66d823459c76957534324d39fee795e613c911');
    const did = `did:ethr:${providerConfig.name}:${address}`;

    const didDocument = (await didResolver.resolve(did)).didDocument!;
    // console.log(didDocument); // note the #delegate-x keyAgreement key suffix
    const kid = `${did}#delegate-6`;
    const jwk = new DIDKeyResolver().resolveKey(didDocument, kid);

    expect(base64.decode(jwk.x)).toStrictEqual(kxPub);
  }, 20000);
});
