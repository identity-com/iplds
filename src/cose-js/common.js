/* jshint esversion: 6 */
/* jslint node: true */
'use strict';
var _ = require('lodash'); // @lodash/es - treeshakable

const AlgToTags = {
  'A128W': -3,
  'A192KW': -4,
  'A256KW': -5,
  'ECDH-ES-A256KW': -31,
  'A256GCM': 3,
};

const Translators = {
  'kid': (value) => {
    return Buffer.from(value, 'utf8');
  },
  'alg': (value) => {
    if (!(AlgToTags[value])) {
      throw new Error('Unknown \'alg\' parameter, ' + value);
    }
    return AlgToTags[value];
  }
};

const HeaderParameters = {
  'partyUNonce': -22,
  'epk': -1,
  'alg': 1,
  'kid': 4,
  'iv': 5,
};

exports.EMPTY_BUFFER = Buffer.alloc(0);

const KeyParameters = {
  'crv': -1,
  'x': -2,
  'y': -3,
  'd': -4,
  'kty': 1
};

const UnKeyParameters = _.invert(KeyParameters);

const KeyTypes = {
  'OKP': 1,
  'EC2': 2,
  'RSA': 3,
  'Symmetric': 4
};

const KeyCrv = {
  'P-256': 1,
};

const KeyTranslators = {
  'kty': (value) => {
    if (!(KeyTypes[value])) {
      throw new Error('Unknown \'kty\' parameter, ' + value);
    }
    return KeyTypes[value];
  },
  'crv': (value) => {
    if (!(KeyCrv[value])) {
      throw new Error('Unknown \'crv\' parameter, ' + value);
    }
    return KeyCrv[value];
  }
};

export const TranslateKey = (key) => 
  translate(key, KeyParameters, KeyTranslators);

export function TranslateHeaders(key) {
  return translate(key, HeaderParameters, Translators);
};

export function UntranslateHeaders(headers) {
  return translate(headers, _.invert(HeaderParameters), _.invert(Translators));
};

export function UntranslateKey(key) {
  return translate(key, _.invert(KeyParameters), _.invert(KeyTranslators));
};

export function translate(obj, mainTranslator, propertiesTranslator) {
  const result = new Map();
  for (const param in obj) {
    if (!mainTranslator[param]) {
      throw new Error('Unknown parameter, \'' + param + '\'');
    }
    let value = obj[param];
    if (propertiesTranslator[param]) {
      value = propertiesTranslator[param](obj[param]);
    }
    if (value !== undefined && value !== null) {
      result.set(mainTranslator[param].toString(), value);
    }
  }
  return result;
};

export function untranslate(map, mainTranslator, propertiesTranslator) {
  const result = new Map();
  for (let [key, value] in obj) {
    if (!mainTranslator[param]) {
      throw new Error('Unknown parameter, \'' + param + '\'');
    }
    let value = obj[param];
    if (propertiesTranslator[param]) {
      value = propertiesTranslator[param](obj[param]);
    }
    if (value !== undefined && value !== null) {
      result.set(mainTranslator[param].toString(), value);
    }
  }
  return result;
};