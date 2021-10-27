import {

  createECKey, createEllipticECKey, cryptoToEllipticPrivate, jwkToEllipticPublic,
} from '../src/crypto';
import { deriveKey } from '../src/ecdh-es-akw';
import { ec as EC } from 'elliptic';

describe('ECDH', () => {
  // it('should generate ECDH-ES 25519 keys', async () => {
  //   const alice = await createEC25519Key();
  // });

  it('should generate same shared secret', async () => {

    const alg = 'ECDH-ES-A256KW';
    const alice = await createECKey('K-256');
    const bob = await createECKey('K-256');
    console.log('alice priv: ', Buffer.from(await cryptoToEllipticPrivate(alice.privateKey!)).toString('hex'));

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
          public: alice.publicKey,
        },
        bob.privateKey!,
        Math.ceil(parseInt('256', 10) / 8) <<
          3
      )
    );

    expect(cryptoRes1).toEqual(cryptoRes2);

    const raw = await crypto.subtle.exportKey('pkcs8', alice.privateKey!);
    const ellipticAlice = await createEllipticECKey(alice);
    const ellipticBob = await createEllipticECKey(bob);
    console.log('ellipticAlice: ', ellipticAlice.getPrivate().toString('hex'));

    const ellipticRes1 = new Uint8Array(ellipticAlice.derive(ellipticBob.getPublic()).toBuffer());
    const ellipticRes2 = new Uint8Array(ellipticAlice.derive(ellipticBob.getPublic()).toBuffer());

    expect(ellipticRes1).toEqual(ellipticRes2);
    console.log('cryptoRes1.16: ', Buffer.from(cryptoRes1).toString('hex'));
    console.log('BN.tS(16): ', ellipticAlice.derive(ellipticBob.getPublic()).toString(16));
    
    expect(cryptoRes1.length).toEqual(ellipticRes1.length);
    expect(cryptoRes1).toEqual(ellipticRes1);
  });

  it('should generate RFC-etalon-based shared secret on x25519', async () => {
    const receiverPublicJWK = {
      kty: 'OKP',
      crv: 'X25519',
      kid: 'Bob',
      x: '3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08',
    };

    const epkSecretHex = cleanSpaces(
      'de 9e db 7d 7b 7d c1 b4 d3 5b 61 c2 ec e4 35 37 3f 83 43 c8 5b 78 67 4d ad fc 7e 14 6f 88 2b 4f'
      // '6A2CB91DA5FB77B12A99C0EB872F4CDF4566B25172C1163C7DA518730A6D0770'
    );
   // ' 7 07 6d 0a 73 18 a5 7d 3c 16 c1 72 51 b2 66 45   4d 33 5a 71 76 fb 4f 4e 48 f7 45 ec 93 00 60 af'
    const ecdhEtalonResult = cleanSpaces(
      '4a 5d 9d 5b a4 ce 2d e1 72 8e 3b f4 80 35 0f 25 e0 7e 21 c9 47 d1 9e 33 76 f0 9b 3c 1e 16 17 42');

    const receiverPublicRaw = jwkToEllipticPublic(receiverPublicJWK);
    // const epkSecretRaw = Uint8Array.from(Buffer.from(epkSecretHex, 'hex'));

    const ec = new EC('curve25519');
    let epkSecretRaw = Buffer.from(epkSecretHex, 'hex');
    epkSecretRaw[0] &= 248;
    epkSecretRaw[31] &= 127;
    epkSecretRaw[31] |= 64;
    epkSecretRaw.reverse();

    const ellipticAlice = ec.keyFromPrivate(epkSecretRaw);
    console.log('epkSecretHex: ', epkSecretHex);
    console.log('ellipticAlice: ', ellipticAlice.getPrivate('hex'));
    
    const ellipticBob = ec.keyFromPublic(receiverPublicRaw);
    console.log('bobPublic fromBase', Buffer.from(receiverPublicJWK.x, 'base64url').toString('hex'));
    console.log('bobPublic fromRaw', Buffer.from(receiverPublicRaw).toString('hex'));
    console.log('ellipticBob', ellipticBob.getPublic().getX().toString('hex'));

    const derivedShared = Uint8Array.from(ellipticAlice.derive(ellipticBob.getPublic()).toBuffer());
    const ecdhRaw = Uint8Array.from(Buffer.from(cleanSpaces(ecdhEtalonResult), 'hex'));
    
    console.log('derivedShared: ', Buffer.from(derivedShared).toString('hex'));
    console.log('derivedEtalon: ', ecdhEtalonResult);
    
    expect(derivedShared.length).toStrictEqual(ecdhRaw.length);
    expect(derivedShared).toStrictEqual(ecdhRaw);

  });

});

const cleanSpaces = (hexStr: string): string => hexStr.replace(/\s/g, '');