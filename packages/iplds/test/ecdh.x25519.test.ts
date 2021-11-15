import { sharedKey } from '@stablelib/x25519';
import { jwkPublicToRaw } from '@identity.com/jwk';

describe('ECDH with X25519', () => {
  // (https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.6)
  it('should generate a shared secret equal to RFC8037', () => {
    const receiverPublicJWK = {
      kty: 'OKP',
      crv: 'X25519',
      kid: 'Bob',
      x: '3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08',
    };

    const epkSecretHex =
      '77 07 6d 0a 73 18 a5 7d 3c 16 c1 72 51 b2 66 45 df 4c 2f 87 eb c0 99 2a b1 77 fb a5 1d b9 2c 2a';

    const ecdhEtalonResult =
      '4a 5d 9d 5b a4 ce 2d e1 72 8e 3b f4 80 35 0f 25 e0 7e 21 c9 47 d1 9e 33 76 f0 9b 3c 1e 16 17 42';

    const receiverPublicRaw = jwkPublicToRaw(receiverPublicJWK);
    const epkSecretRaw = Uint8Array.from(Buffer.from(cleanSpaces(epkSecretHex), 'hex'));

    const derivedShared = sharedKey(epkSecretRaw, receiverPublicRaw);
    const ecdhRaw = Uint8Array.from(Buffer.from(cleanSpaces(ecdhEtalonResult), 'hex'));

    expect(derivedShared.length).toStrictEqual(ecdhRaw.length);
    expect(derivedShared).toStrictEqual(ecdhRaw);
  });
});

const cleanSpaces = (hexStr: string): string => hexStr.replace(/\s/g, '');
