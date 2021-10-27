'use strict';

import { invertSimpleObject } from '../utils';

export const ECDH = 'ECDH';
export const ECDH_ES = 'ECDH-ES';

const ALG_TAGS = {
  A128W: -3,
  A192KW: -4,
  A256KW: -5,
  'ECDH-ES-A256KW': -31,
  A256GCM: 3,
};

const TRANSLATORS = {
  kid: (value) => new TextEncoder().encode(value),
  alg: (value) => strictLookup(value, ALG_TAGS, 'alg'),
};

const UNTRANSLATORS = {
  kid: (value) => new TextDecoder().decode(value),
  alg: (value) => strictLookup(value, invertSimpleObject(ALG_TAGS), 'alg'),
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
  EC2: 2,
  RSA: 3,
  Symmetric: 4,
};

const KEY_TYPES_TO_ALGORITHMS = {
  EC: ECDH,
  EC2: ECDH,
  OKP: ECDH_ES
};

export const KEY_CRV = {
  'P-256': 1,
  'X25519': 6,
  'K-256': 8,
};

export const CRV_ALG = {
  'P-256': ECDH,
  'K-256': ECDH,
  'X25519': ECDH_ES,
}

const KEY_TRANSLATORS = {
  kty: (key) => strictLookup(key, KEY_TYPES, 'kty'),
  crv: (key) => strictLookup(key, KEY_CRV, 'crv'),
};

const KEY_UNTRANSLATORS = {
  kty: (key) => strictLookup(key, invertSimpleObject(KEY_TYPES), 'kty'),
  crv: (key) => strictLookup(key, invertSimpleObject(KEY_CRV), 'crv'),
};

const strictLookup = (key, target, paramName) => {
  if (!target[key]) {
    throw new Error(`Unknown ${paramName} key: ${key}`);
  }

  return target[key];
};

export const translateKey = (obj) =>
  translate(obj, KEY_PARAMETERS, KEY_TRANSLATORS);

export const untranslateKey = (obj) =>
  translate(obj, invertSimpleObject(KEY_PARAMETERS), KEY_UNTRANSLATORS);

export const translateHeaders = (obj) =>
  translate(obj, HEADER_PARAMETERS, TRANSLATORS);

export const untranslateHeaders = (obj) =>
  translate(obj, invertSimpleObject(HEADER_PARAMETERS), UNTRANSLATORS);

export const translateKeyTypeToAlgorithm = (keyType) =>
  strictLookup(keyType, KEY_TYPES_TO_ALGORITHMS, 'key type');

export const translate = (obj, mainTranslator, propertiesTranslator) => {
  const result = new Map();
  for (const param in obj) {
    if (!Object.prototype.hasOwnProperty.call(obj, param)) {
      // skip inherited properties
      continue;
    }

    if (!mainTranslator[param]) {
      throw new Error("Unknown parameter, '" + param + "'");
    }
    let value = obj[param];
    if (propertiesTranslator[param]) {
      value = propertiesTranslator[param](obj[param]);
    } else if (propertiesTranslator[mainTranslator[param]]) {
      value = propertiesTranslator[mainTranslator[param]](obj[param]);
    }
    if (value !== undefined && value !== null) {
      result.set(mainTranslator[param].toString(), value);
    }
  }
  return result;
};
