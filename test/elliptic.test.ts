import {

  createECKey, createEllipticECKey,
} from '../src/crypto';
import { deriveKey } from '../src/ecdh-es-akw';

describe('ECDH', () => {
  // it('should generate ECDH-ES 25519 keys', async () => {
  //   const alice = await createEC25519Key();
  // });

  it('should generate same shared secret', async () => {

    const alg = 'ECDH-ES-A256KW';
    const alice = await createECKey('P-256');
    const bob = await createECKey('P-256');
    console.log('alice priv: ', new Uint8Array((await crypto.subtle.exportKey('pkcs8', alice.privateKey!))).reduce((a, b) => a + "," + b, ""));
    console.log('alice pub: ', new Uint8Array((await crypto.subtle.exportKey('raw', alice.publicKey!))).reduce((a, b) => a + "," + b, ""));
    console.log('bob priv: ', new Uint8Array((await crypto.subtle.exportKey('pkcs8', bob.privateKey!))).reduce((a, b) => a + "," + b, ""));
    console.log('bob pub: ', new Uint8Array((await crypto.subtle.exportKey('raw', bob.publicKey!))).reduce((a, b) => a + "," + b, ""));

    const cryptoRes1 =  new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: 'ECDH',
          public: bob.publicKey,
        },
        alice.privateKey!,
        Math.ceil(parseInt('256', 10) / 8) <<
          3
      )
    );

    const cryptoRes2 = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: 'ECDH',
          public: bob.publicKey,
        },
        alice.privateKey!,
        Math.ceil(parseInt('256', 10) / 8) <<
          3
      )
    );

    expect(cryptoRes1).toEqual(cryptoRes2);

    const raw = await crypto.subtle.exportKey('pkcs8', alice.privateKey!);
    const ellipticAlice = await createEllipticECKey(alice);
    const ellipticBob = await createEllipticECKey(bob);

    const ellipticRes1 = new Uint8Array(ellipticAlice.derive(ellipticBob.getPublic()).toBuffer());
    const ellipticRes2 = new Uint8Array(ellipticAlice.derive(ellipticBob.getPublic()).toBuffer());

    expect(ellipticRes1).toEqual(ellipticRes2);
    console.log('cryptoRes1.16: ', Buffer.from(cryptoRes1).toString('hex'));
    console.log('BN.tS(16): ', ellipticAlice.derive(ellipticBob.getPublic()).toString(16));
    
    expect(cryptoRes1.length).toEqual(ellipticRes1.length);
    expect(cryptoRes1).toEqual(ellipticRes1);
  });
});