import { DIDDocument, VerificationMethod } from 'did-resolver';
import { BaseName, decode, encoding } from 'multibase';
import { convertPublicKey as ed2x25519 } from 'ed2curve-esm';
import { toJWK as exportJWK, JWK } from '@identity.com/jwk';

export class DIDKeyResolver {
  public resolveKey = (did: DIDDocument, kid?: string): JWK => {
    const verificationMethod = this.keyAgreementVerificationMethod(did, kid);

    if (!verificationMethod) {
      throw new Error(`Couldn't resolve public key for DID [${did.id}] with kid [${kid ?? 'undefined'}]`);
    }

    return this.extractJWK(verificationMethod);
  };

  private keyAgreementVerificationMethod(did: DIDDocument, kid?: string): VerificationMethod | null {
    const verificationMethods: VerificationMethod[] | undefined = this.getVerificationMethods(did);
    if (verificationMethods.length === 0) {
      return null;
    }

    if (!kid) {
      if (verificationMethods.length > 1) {
        throw new Error('More than one key found in DID. Please specify "kid" parameter');
      }
      return verificationMethods[0];
    }

    return verificationMethods.find((v) => v.id === kid) ?? null;
  }

  private getVerificationMethods(did: DIDDocument): VerificationMethod[] {
    if (this.hasKeyAgreements(did)) {
      return did.keyAgreement?.map((agreement) => this.resolveVerificationMethod(did, agreement)) ?? [];
    } else if (this.hasCapabilityInvocations(did)) {
      return did.capabilityInvocation?.map((capability) => this.resolveVerificationMethod(did, capability)) ?? [];
    }
    return [];
  }

  private hasCapabilityInvocations(did: DIDDocument): boolean {
    return (did.capabilityInvocation?.length ?? 0) > 0;
  }

  private hasKeyAgreements(did: DIDDocument): boolean {
    return (did.keyAgreement?.length ?? 0) > 0;
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

  private extractJWK(verificationMethod: VerificationMethod): JWK {
    if (verificationMethod.publicKeyJwk) {
      //TODO: add checks
      return verificationMethod.publicKeyJwk as JWK;
    }

    if (verificationMethod.publicKeyMultibase) {
      return this.toJWK(verificationMethod.type, decode(verificationMethod.publicKeyMultibase));
    }

    const bases: Map<BaseName, string | undefined> = new Map([
      ['base58btc', verificationMethod.publicKeyBase58],
      ['base64url', verificationMethod.publicKeyBase64],
      ['base16', this.preformatHex(verificationMethod.publicKeyHex)],
    ]);

    for (const [enc, method] of bases.entries()) {
      if (method) {
        return this.toJWK(verificationMethod.type, encoding(enc).decode(method));
      }
    }

    throw new Error('Unsupported key format');
  }

  private readonly toJWK = (methodType: string, publicKeyBinary: Uint8Array): JWK => {
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
