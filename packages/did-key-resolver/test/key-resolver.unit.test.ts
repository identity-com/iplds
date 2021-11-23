import { encoding } from 'multibase';
import { DIDKeyResolver } from '../src/key-resolver';
import * as SAMPLE_DIDS from './fixtures/sample-dids';

const base64 = encoding('base64url');
const base58 = encoding('base58btc');
const keyAgreementPublicKey = base58.decode(SAMPLE_DIDS.keyBase58);

describe('Sample key resolver', () => {
  it('should resolve key from a keyAgreement section', () => {
    const didDocument = SAMPLE_DIDS.keyAgreementOnly;
    const jwk = new DIDKeyResolver().resolveKey(didDocument, SAMPLE_DIDS.kid);

    expect(base64.decode(jwk.x)).toStrictEqual(keyAgreementPublicKey);
  });

  it('should resolve key from capabilityInvocation section', () => {
    const didDocument = SAMPLE_DIDS.capabilityInvocationOnly;
    const jwk = new DIDKeyResolver().resolveKey(didDocument, SAMPLE_DIDS.kid);

    expect(base64.decode(jwk.x)).toStrictEqual(keyAgreementPublicKey);
  });

  it('should fail when key is absent from indexing sections', () => {
    const didDocument = SAMPLE_DIDS.noIndexSections;

    expect(() => new DIDKeyResolver().resolveKey(didDocument, SAMPLE_DIDS.kid)).toThrowError();
  });

  it('should fail when key reference is wrong in a section', () => {
    const didDocument = SAMPLE_DIDS.messedUpIndex;

    expect(() => new DIDKeyResolver().resolveKey(didDocument, SAMPLE_DIDS.kid)).toThrowError();
  });

  it('should fail when key type is unsupported', () => {
    const didDocument = SAMPLE_DIDS.blsTypeKey;

    expect(() => new DIDKeyResolver().resolveKey(didDocument, SAMPLE_DIDS.kid)).toThrowError();
  });

  it('should resolve key from base64 format', () => {
    const didDocument = SAMPLE_DIDS.base64Key;
    const jwk = new DIDKeyResolver().resolveKey(didDocument, SAMPLE_DIDS.kid);

    expect(base64.decode(jwk.x)).toStrictEqual(keyAgreementPublicKey);
  });

  it('should resolve key from multibase format', () => {
    const didDocument = SAMPLE_DIDS.baseMultibaseKey;
    const jwk = new DIDKeyResolver().resolveKey(didDocument, SAMPLE_DIDS.kid);

    expect(base64.decode(jwk.x)).toStrictEqual(keyAgreementPublicKey);
  });

  it('should resolve key from hex format', () => {
    const didDocument = SAMPLE_DIDS.hexKey;
    const jwk = new DIDKeyResolver().resolveKey(didDocument, SAMPLE_DIDS.kid);

    expect(base64.decode(jwk.x)).toStrictEqual(keyAgreementPublicKey);
  });

  it('should resolve key from jwk type', () => {
    const didDocument = SAMPLE_DIDS.jsonTypeKey;
    const jwk = new DIDKeyResolver().resolveKey(didDocument, SAMPLE_DIDS.kid);

    expect(jwk).toEqual(didDocument.verificationMethod?.[0].publicKeyJwk);
  });

  it('should resolve key from k-256 type', () => {
    const didDocument = SAMPLE_DIDS.secpTypeKey;
    const jwk = new DIDKeyResolver().resolveKey(didDocument, SAMPLE_DIDS.kid);

    expect(jwk).toEqual(didDocument.verificationMethod?.[0].publicKeyJwk);
  });
});
