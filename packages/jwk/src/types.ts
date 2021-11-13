export type X25519 = 'X25519';
export type EC256 = 'P-256' | 'K-256';
export type ECDHCurve = X25519 | EC256;

export type EC256JWK = JsonWebKey & {
  kty: 'EC';
  crv: EC256;
  x: string;
  y: string;
  kid?: string;
};
export type X25519JWK = JsonWebKey & {
  kty: 'OKP';
  crv: X25519;
  x: string;
  kid?: string;
};
export type JWK = EC256JWK | X25519JWK;
export const CURVES: ECDHCurve[] = ['K-256', 'P-256', 'X25519'];
