import { DIDDocument, VerificationMethod } from 'did-resolver';
import { BaseName, decode, encoding } from 'multibase';
import { convertPublicKey as ed2x25519 } from 'ed2curve-esm';
import { toJWK as exportJWK } from '@identity.com/jwk';

export class DIDKeyResolver {
  public resolveKey = (did: DIDDocument, kid: string): JsonWebKey => {
    console.log(did);
    const verificationMethod: VerificationMethod | undefined = this.keyAgreementVerificationMethod(did, kid);

    if (verificationMethod) {
      return this.extractJWK(verificationMethod);
    }

    throw new Error(`Couldn't resolve public key for DID [${did.id}] with kid [${kid}]`);
  };

  private keyAgreementVerificationMethod(did: DIDDocument, kid: string): VerificationMethod | undefined {
    let verificationMethods: VerificationMethod[] | undefined = [];

    if (this.hasKeyAgreements(did)) {
      verificationMethods = did.keyAgreement?.map((agreement) => this.resolveVerificationMethod(did, agreement));
    } else if (this.hasCapabilityInvocations(did)) {
      verificationMethods = did.capabilityInvocation?.map((capability) =>
        this.resolveVerificationMethod(did, capability),
      );
    }

    return verificationMethods?.find((v) => v.id === kid);
  }

  private hasCapabilityInvocations(did: DIDDocument): boolean | undefined {
    return did.capabilityInvocation && did.capabilityInvocation.length > 0;
  }

  private hasKeyAgreements(did: DIDDocument): boolean | undefined {
    return did.keyAgreement && did.keyAgreement.length > 0;
  }

  private resolveVerificationMethod(did: DIDDocument, keyAgreement: string | VerificationMethod): VerificationMethod {
    if (typeof keyAgreement === 'string') {
      const method = did.verificationMethod?.find((v) => v.id === keyAgreement);
      if (method) {
        return method;
      }

      throw new Error(`Malformed DIDDocument [${did.id}]: Missing keyAgreement [${keyAgreement}]`);
    }

    return keyAgreement;
  }

  private extractJWK(verificationMethod: VerificationMethod): JsonWebKey {
    if (verificationMethod.publicKeyJwk) {
      return verificationMethod.publicKeyJwk;
    }

    if (verificationMethod.publicKeyMultibase) {
      return this.toJWK(verificationMethod.type, decode(verificationMethod.publicKeyMultibase));
    }

    const bases: Map<BaseName, string | undefined> = new Map([
      ['base58btc', verificationMethod.publicKeyBase58],
      ['base64', verificationMethod.publicKeyBase64],
      ['base16', this.preformatHex(verificationMethod.publicKeyHex)],
    ]);

    for (const [enc, method] of bases.entries()) {
      if (method) {
        return this.toJWK(verificationMethod.type, encoding(enc).decode(method));
      }
    }

    throw new Error('Unsupported key format');
  }

  private readonly toJWK = (methodType: string, publicKeyBinary: Uint8Array): JsonWebKey => {
    if (methodType.includes('X25519')) {
      return exportJWK(publicKeyBinary, 'X25519');
    } else if (methodType.includes('Ed25519')) {
      return exportJWK(ed2x25519(publicKeyBinary), 'X25519');
    } else if (methodType.includes('Secp256k1')) {
      return exportJWK(publicKeyBinary, 'K-256');
    }

    throw new Error(`Unsupported VerificationMethod type: ${methodType}`);
  };

  private readonly preformatHex = (hexString?: string): string | undefined => {
    if (hexString && (hexString.startsWith('0x') || hexString.startsWith('0X'))) {
      return hexString.substr(2);
    }

    return hexString;
  };
}
