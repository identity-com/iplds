// const IPFS = require('ipfs-core')
import { decode as cborDecode } from 'cborg';
import { Crypto } from '@peculiar/webcrypto';
import { create } from 'ipfs-http-client';
import * as coseDecrypt from './coseDecrypt';
// import { crypto } from 'crypto';
// import { parseJwk } from 'jose/jwk/parse'
import * as coseEncrypt from './coseEncrypt';
import { IPSecureContext } from './IPSecureContext';
import { IPFSS } from './ipfss';

export const sum = (a: number, b: number) => {
  if ('development' === process.env.NODE_ENV) {
    console.log('boop');
  }
  return a + b;
};

export const put = async (s: string) => {
  const client = create();
  const { cid } = await client.add(s);
  console.info(cid);

  return cid;
};

export const storeSimpleGraph = async (o1: string, o2: string, o3: string) => {
  const client = create();
  const cid1 = await client.dag.put({ value: o1 });
  const cid2 = await client.dag.put({ value: o2 });
  const cid3 = await client.dag.put({ s1: cid1, s2: cid2, s3: o3 });

  console.info(cid3);

  const root = await client.dag.get(cid3);
  console.info(root);

  return cid3;
};

export const testCoseEncrypt = async () => {
  const crypto = new Crypto();

  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  const privateKey = keyPair.privateKey;
  const publicKey = keyPair.publicKey;

  const cek = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  const keyMgmt = await coseEncrypt.keyAgreement(publicKey, cek);

  const encryptedCose = await coseEncrypt.encrypt(
    [1, 2, 3],
    'meriadoc.brandybuck@buckland.example', /* kid - unused in POC */
    keyMgmt
  );

  console.info(`Encoded: ${Buffer.from(encryptedCose).toString('hex')}`);

  const result = await coseDecrypt.decrypt(encryptedCose, privateKey);

  console.info(`Decoded&decrypted: ${result}`);
  console.info(`Decrypted s: ${cborDecode(result[2])[1]}`);
}

export const testStorage = async() => {

  const crypto = new Crypto();

  const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const privateKey = keyPair.privateKey;
  const publicKey = keyPair.publicKey;

  const ipfss = new IPFSS(new IPSecureContext());

  const rootMetadata = await manualStoreGraph(publicKey);
  console.info('Root metadata: ', rootMetadata);

  const partObject = await ipfss.readSubGraph(rootMetadata, '/p', privateKey);
  console.info('Rebuilt part-object: ', partObject);

  const wholeObject = await ipfss.readGraph(rootMetadata, privateKey);
  console.info('Rebuilt object: ', wholeObject);

  const toPin = await ipfss.pinGraph(rootMetadata, privateKey);
  console.info(toPin);
}

const testApiTree = async() => {
  const crypto = new Crypto();

  const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const privateKey = keyPair.privateKey;
  const publicKey = keyPair.publicKey;

  const ipfss = new IPFSS(new IPSecureContext());

  const rootMetadata = await apiStoreTree(publicKey);
  console.info('Root metadata: ', rootMetadata);

  const wholeObject = await ipfss.readGraph(rootMetadata, privateKey);
  console.info(`Rebuilt object: ${wholeObject}`);
}

const testApiGraph = async() => {
  const crypto = new Crypto();

  const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const privateKey = keyPair.privateKey;
  const publicKey = keyPair.publicKey;

  const ctx = new IPSecureContext();
  const ipfss = new IPFSS(ctx);

  const rootMetadata = await apiStoreGraph(publicKey);
  console.info('Root metadata: ', rootMetadata);

  const wholeObject = await ipfss.readGraph(rootMetadata, privateKey);
  console.info(`Rebuilt object: ${wholeObject}`);
}

const apiStoreTree = async (publicKey: CryptoKey): Promise<Uint8Array> => {
  const x = {descr: 'some string'};
  const s = {descr: 'some other thing'};

  const p = {
    descr: 'mid level object',
    x: x,
    s: s
  };

  const ctx = new IPSecureContext();
  const ipfss = new IPFSS(ctx);

  ctx.add(p);
  ctx.add(p, '/x');
  ctx.add(p, '/s');


  return await ipfss.storeObjectWithContext(p, publicKey);
}

const apiStoreGraph = async (publicKey: CryptoKey): Promise<Uint8Array> => {
  const ctx = new IPSecureContext();
  const ipfss = new IPFSS(ctx);

  const x = {descr: 'some string'};
  const s = {descr: 'some other thing'};

  const p = {
    descr: 'mid level object',
    x: x,
    s: s
  };

  const q = {
    descr: 'another mid level object',
    x: x,
    z1: {
      descr: 'embedded object'
    },
    z2: {
      descr: 'another embedded object'
    }
  };

  const a = {
    descr: 'top-level object',
    p: p,
    q: q,
    z1: {
      descr: 'embedded object'
    }
  };

  ctx.add(a);
  ctx.add(a, '/p');
  ctx.add(a, '/q');
  ctx.add(p, '/x');
  ctx.add(p, '/s');

  return await ipfss.storeObjectWithContext(a, publicKey);
}

const manualStoreGraph = async (publicKey: CryptoKey): Promise<Uint8Array> => {
  const x = {descr: 'some string'};
  const s = {descr: 'some other thing'};

  const ipfss = new IPFSS(new IPSecureContext());

  const [xCID, xKey] = await ipfss.storeLeafObject(x);
  const [sCID, sKey] = await ipfss.storeLeafObject(s);

  const pKey = await ipfss.newCEK();
  const md10 = await ipfss.storeMetadata(pKey, publicKey, [xCID], xKey);
  const md9 = await ipfss.storeMetadata(pKey, publicKey, [sCID], sKey);

  const p = {
    descr: 'mid level object',
    x: xCID,
    s: sCID
  };

  const pCID = await ipfss.storeObject(p, pKey);

  const qKey = await ipfss.newCEK();
  const md11 = await ipfss.storeMetadata(qKey, publicKey, [xCID], xKey);

  const q = {
    descr: 'another mid level object',
    x: xCID
  };
  const qCID = await ipfss.storeObject(q, qKey);

  const aKey = await ipfss.newCEK();
  const md17 = await ipfss.storeMetadata(aKey, publicKey, [pCID, md10, md9], pKey);
  const md18 = await ipfss.storeMetadata(aKey, publicKey, [qCID, md11], qKey);

  const a = {
    descr: 'top-level object',
    p: pCID,
    q: qCID
  };
  const aCID = await ipfss.storeObject(a, aKey);

  return ipfss.generateRootMetadata(publicKey, [aCID, md17, md18], aKey);
}

async function main() {
//  await testCoseEncrypt();
  // await testStorage();
  // await testApiTree();
  await testApiGraph();
}

main().then(() => {console.log('done')}, console.error);

