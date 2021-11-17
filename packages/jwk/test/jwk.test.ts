import { Crypto } from '@peculiar/webcrypto';
import { toJWK as exportJWK, jwkPublicToRaw, JWK_TO_ELLIPTIC_CURVE_NAMES } from '../src/jwk';
import { ECDHCurve, X25519JWK } from '../src/types';
import { encoding } from 'multibase';
import { ec as EC } from 'elliptic';
import { convertPublicKey } from 'ed2curve-esm';

const cleanSpaces = (hexStr: string): string => hexStr.replace(/\s/g, '');

const ECDH = 'ECDH';
const ECDH_ES = 'ECDH-ES';

const CRV_ALG: Record<ECDHCurve, string> = {
  'P-256': ECDH,
  'K-256': ECDH,
  X25519: ECDH_ES,
};

const crypto = new Crypto();

const base64 = encoding('base64url');

const createECKey = async (namedCurve: ECDHCurve): Promise<Uint8Array> => {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: CRV_ALG[namedCurve],
      namedCurve,
    },
    true,
    ['deriveBits'],
  );

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  return new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey!));
};

describe('JWK Utils', () => {
  it('should convert compressed hex key from ETHR DID', () => {
    const publicKeyHex = '0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

    const publicKey = encoding('base16').decode(preformatHex(publicKeyHex));
    const publicKeyWithoutCompressedEncoding = publicKey.slice(1);

    const jwk = exportJWK(publicKey, 'K-256');
    expect(base64.decode(jwk.x)).toStrictEqual(publicKeyWithoutCompressedEncoding);
  });

  const k256PublicKey = Uint8Array.from([
    121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252, 219, 45, 206, 40, 217, 89,
    242, 129, 91, 22, 248, 23, 152, 72, 58, 218, 119, 38, 163, 196, 101, 93, 164, 251, 252, 14, 17, 8, 168, 253, 23,
    180, 72, 166, 133, 84, 25, 156, 71, 208, 143, 251, 16, 212, 184,
  ]);

  it('should convert uncompressed key from ETHR DID', () => {
    const jwk = exportJWK(k256PublicKey, 'K-256');

    expect(base64.decode(jwk.x)).toStrictEqual(k256PublicKey.slice(0, 32));
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    expect(base64.decode(jwk.y!)).toStrictEqual(k256PublicKey.slice(32));
  });

  const x25519PublicRaw = encoding('base16').decode(
    cleanSpaces('85 20 f0 09 89 30 a7 54 74 8b 7d dc b4 3e f7 5a 0d bf 3a 0d 26 38 1a f4 eb a4 a9 8e aa 9b 4e 6a'),
  );
  const x25519PublicJWK: X25519JWK = { kty: 'OKP', crv: 'X25519', x: 'hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo' };

  it('should convert x25519 key to JWK (RFC 8037)', () => {
    expect(exportJWK(x25519PublicRaw, 'X25519')).toStrictEqual(x25519PublicJWK);
  });

  it('should convert x25519 key from JWK (RFC 8037)', () => {
    expect(jwkPublicToRaw(x25519PublicJWK)).toStrictEqual(x25519PublicRaw);
  });

  it.each([['P-256'], ['K-256'], ['X25519']])('should be compatible with webcrypto@%s', async (curveName: string) => {
    const curve = curveName as ECDHCurve;
    const publicKey = await createECKey(curve);
    expect(jwkPublicToRaw(exportJWK(publicKey, curve), false, true)).toStrictEqual(publicKey);
  });

  it.each([['P-256'], ['K-256']])('should compress as elliptic on %s', (curveName: string) => {
    const curve = curveName as ECDHCurve;
    const ec = new EC(JWK_TO_ELLIPTIC_CURVE_NAMES[curve]);
    const uncompressedPublicKey = Uint8Array.from([4, ...k256PublicKey]); // same key, actually, works on both P-256 and K-256
    const compressedEllipticKey = Uint8Array.from(
      ec.keyFromPublic(uncompressedPublicKey).getPublic().encode('array', true),
    );

    expect(jwkPublicToRaw(exportJWK(uncompressedPublicKey, curve), true)).toStrictEqual(compressedEllipticKey);
  });
  it('converts ed2x', () => {
    const publicKey = encoding('base58btc').decode('2CGCTroGewFq5cKAvP7rjAf7CHveHTuvpmjAc3NmH5H7');
    const x25519Public = convertPublicKey(publicKey);

    expect(x25519Public).not.toBeNull();
  });
});

const preformatHex = (hexString: string): string => {
  if (hexString.startsWith('0x') || hexString.startsWith('0X')) {
    return hexString.substr(2);
  }

  return hexString;
};

/*

    {
      "id": "did:ethr:0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798#controllerKey",
      "type": "EcdsaSecp256k1VerificationKey2019",
      "controller": "did:ethr:0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "publicKeyHex": "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    }

*/
