import { ECDHCurve } from '@identity.com/jwk';
import { Dictionary } from '../types/types';
import { invertSimpleObject } from '../utils/utils';

export const ECDH = 'ECDH';
export const ECDH_ES = 'ECDH-ES';

const ALG_TAGS = {
  A128W: -3,
  A192KW: -4,
  A256KW: -5,
  'ECDH-ES+A256KW': -31,
  A256GCM: 3,
};

const TRANSLATORS = {
  kid: (value: string): Uint8Array => new TextEncoder().encode(value),
  alg: (value: string): number => strictLookup(value, ALG_TAGS, 'alg'),
};

const UNTRANSLATORS = {
  kid: (value: Uint8Array): string => new TextDecoder().decode(value),
  alg: (value: number) => strictLookup(value, invertSimpleObject(ALG_TAGS), 'alg'),
};

const HEADER_PARAMETERS = {
  partyUNonce: -22,
  epk: -1,
  alg: 1,
  kid: 4,
  iv: 5,
};

const KEY_PARAMETERS = {
  crv: -1,
  x: -2,
  y: -3,
  d: -4,
  kty: 1,
};

const KEY_TYPES = {
  OKP: 1,
  EC: 2,
  RSA: 3,
  Symmetric: 4,
};

const KEY_CRV: Record<ECDHCurve, number> = {
  'P-256': 1,
  X25519: 6,
  'K-256': 8,
};

const KEY_TRANSLATORS = {
  kty: (key: string) => strictLookup(key, KEY_TYPES, 'kty'),
  crv: (key: string) => strictLookup(key, KEY_CRV, 'crv'),
};

const KEY_UNTRANSLATORS = {
  kty: (key: string) => strictLookup(key, invertSimpleObject(KEY_TYPES), 'kty'),
  crv: (key: string) => strictLookup(key, invertSimpleObject(KEY_CRV), 'crv'),
};

const strictLookup = <T>(key: string | number, target: Dictionary<T>, paramName: string): T => {
  if (!target[key]) {
    throw new Error(`Unknown ${paramName} key: ${key}`);
  }

  return target[key];
};

export const translateKey = (obj: Dictionary<unknown>): Map<string, string> =>
  translate(obj, KEY_PARAMETERS, KEY_TRANSLATORS);

export const untranslateKey = (obj: Dictionary<unknown>): Map<string, string> =>
  translate(obj, invertSimpleObject(KEY_PARAMETERS), KEY_UNTRANSLATORS);

export const translateHeaders = (obj: Dictionary<unknown>): Map<string, string> =>
  translate(obj, HEADER_PARAMETERS, TRANSLATORS);

export const untranslateHeaders = (obj: Dictionary<unknown>): Map<string, string> =>
  translate(obj, invertSimpleObject(HEADER_PARAMETERS), UNTRANSLATORS);

export const translate = (
  obj: Dictionary<unknown>,
  mainTranslator: Dictionary<string | number>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  propertiesTranslator: Record<string, (key: any) => unknown>,
): Map<string, string> => {
  const result = new Map<string, string>();
  for (const param in obj) {
    if (!Object.prototype.hasOwnProperty.call(obj, param)) {
      // skip inherited properties
      continue;
    }

    if (!mainTranslator[param]) {
      throw new Error("Unknown parameter, '" + param + "'");
    }
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    let value = obj[param];
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
    if (propertiesTranslator[param]) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      value = propertiesTranslator[param](value);
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
    } else if (propertiesTranslator[mainTranslator[param]]) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      value = propertiesTranslator[mainTranslator[param]](value);
    }
    if (value !== undefined && value !== null) {
      result.set(mainTranslator[param].toString(), value as string);
    }
  }
  return result;
};
