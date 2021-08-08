import { Crypto } from '@peculiar/webcrypto';
import { encode, decode } from "cborg";
import { CID, create } from "ipfs-http-client";
import { Cose, getCEK, getContent, RecipientAddress } from "./cose";
import { SUBTLE_ENCRYPTION_ALG } from "./coseEncrypt";
import * as coseEncrypt from './coseEncrypt';
import * as coseDecrypt from './coseDecrypt';
import { concat } from './buffer_utils';
import { CtxNode, IPSecureContext } from './IPSecureContext';
import _ from 'lodash';

const FIXED_IV = new TextEncoder().encode('0123456789AB');

class SecureMetadata {
    objCID: CID; 
    metadataCIDs: Array<CID>;
    cek: CryptoKey;

    constructor(obj: CID, md: Array<CID>, key: CryptoKey) {
        this.objCID = obj;
        this.metadataCIDs = md;
        this.cek = key;
    }

    static async fromCose(coseMetadata: Cose): Promise<SecureMetadata> {
        const cids: Array<CID> = decode(getContent(coseMetadata));
        const crypto = new Crypto();
        const cek = await crypto.subtle.importKey(
            "raw",
            getCEK(coseMetadata),
            "AES-GCM",
            true,
            ["encrypt", "decrypt"]
        );
            
        return new SecureMetadata(
            SecureMetadata.buildCID(cids[0]), 
            cids.slice(1).map(SecureMetadata.buildCID), 
            cek);
    }

    static buildCID(unCast: CID) {
        return new CID(unCast.version, unCast.codec, unCast.multihash, unCast.multibaseName)
    }
}

export class IPFSS {

    private ctx: IPSecureContext;

    constructor(ctx: IPSecureContext) {
        this.ctx = ctx;
    }

    public async newCEK(): Promise<CryptoKey> {
        const crypto = new Crypto();
        const cek = await crypto.subtle.generateKey(
            {
            name: "AES-GCM",
            length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );

        return cek;
    }

    /**
     * 
     * @param o 
     * @returns random a tuple of resulting CID and the key used to encrypt the object
     */
    public async storeLeafObject(o: Object): Promise<[CID, CryptoKey]> {
        const cek = await this.newCEK();
        const cid = await this.storeObject(o, cek);

        return [cid, cek];
    }

    /**
     * 
     * @param o - Object to encode to CBOR and then encrypt
     * @param cek - AES encryption key
     * @returns Resulting CID
     */
    public async storeObject(o: any, cek: CryptoKey): Promise<CID> {
        const client = this.createIPFSClient();
        const encrypted = await this.outerEncrypt(encode(o), cek);
        const cid = await client.dag.put(encrypted);

        return cid;
    }

    /**
     * Store Metadata encrypted with the provided CEK (encryptWith)
     * 
     * @param encryptWith
     * @param recipientPublic 
     * @param encryptedCIDs 
     * @param keyToEncrypt 
     * @returns 
     */
    public async storeMetadata(outerKey: CryptoKey, recipientPublic: CryptoKey, encryptedCIDs: Array<CID>, innerCEK: CryptoKey): Promise<CID> {
        const client = this.createIPFSClient();

        const encryptedCose = await this.prepareMetadataCose(recipientPublic, encryptedCIDs, innerCEK);
        const cid = await client.dag.put(await this.outerEncrypt(encryptedCose, outerKey));

        return cid;
    }

    async prepareMetadataCose(recipientPublic: CryptoKey, encryptedCIDs: Array<CID>, innerCEK: CryptoKey): Promise<Uint8Array> {
        const keyMgmt = await coseEncrypt.keyAgreement(recipientPublic, innerCEK);

        return (await coseEncrypt.encrypt(
            encryptedCIDs,
            "meriadoc.brandybuck@buckland.example", /* kid - unused for now... */
            keyMgmt
        ));
    }

    public async generateRootMetadata(publicKey: CryptoKey, cids: Array<CID>, cek: CryptoKey): Promise<Uint8Array> {
        return this.prepareMetadataCose(publicKey, cids, cek);
    }


    public async readGraph(rootMetadata: Uint8Array, recipientPrivate: CryptoKey): Promise<Object> {
        const actualMetadata = await coseDecrypt.decrypt(rootMetadata, recipientPrivate);
        console.debug(`actualMetadata: ${actualMetadata}`);

        return this.readObject(await SecureMetadata.fromCose(actualMetadata), recipientPrivate);
    }

    public async readSubGraph(rootMetadata: Uint8Array, path: string, recipientPrivate: CryptoKey): Promise<Object> {
        const actualMetadata = SecureMetadata.fromCose(await coseDecrypt.decrypt(rootMetadata, recipientPrivate));
        if (path.startsWith("/"))
            path = path.substring(1)
        
        const subRootMetadata = path.split("/").reduce((md, path) => this.getNextMetadata(md, path, recipientPrivate), actualMetadata);

        return this.readObject(await subRootMetadata, recipientPrivate);
    }

    async getNextMetadata(fMetadata: Promise<SecureMetadata>, key: string, recipientPrivate: CryptoKey): Promise<SecureMetadata> {
        const metadata = await fMetadata;
        const obj = await this.readEncryptedObject(metadata.objCID, metadata.cek); // TODO: Store property name in the metadata?
        
        const res = metadata.metadataCIDs
            .map(async cid => await this.readEncryptedMetadata(cid, recipientPrivate, metadata.cek))
            .find(async md => (await md).objCID.toBaseEncodedString() === SecureMetadata.buildCID(obj[key]).toBaseEncodedString())

        if (res === undefined)
            throw new TypeError(`Couldn't find the object ${key}`);

        return res;
    }

    async readObject(metadata: SecureMetadata, recipientPrivate: CryptoKey): Promise<any> {
        console.debug(`metadata: ${metadata}`);
        const result = await this.readEncryptedObject(metadata.objCID, metadata.cek);
        console.debug(`result: ${result}`);

        let metadataIdx = await Promise.all(metadata.metadataCIDs
            .map(async childMetadataCID => (await this.readEncryptedMetadata(childMetadataCID, recipientPrivate, metadata.cek))))
            .then(res => res.reduce((acc: any, md: SecureMetadata) => (acc[md.objCID.toBaseEncodedString()] = md, acc), {}));

        for (let key in result) { // TODO: go inside recursively?
            if (this.isCID(result[key])) {
                result[key] = await this.readObject(metadataIdx[SecureMetadata.buildCID(result[key]).toBaseEncodedString()], recipientPrivate);
            }
        }

        return result;
    }

    public async pinGraph(rootMetadata: Uint8Array, recipientPrivate: CryptoKey) {
        const actualMetadata = await coseDecrypt.decrypt(rootMetadata, recipientPrivate);
        console.debug(`actualMetadata: ${actualMetadata}`);

        return this.collectCIDs(await SecureMetadata.fromCose(actualMetadata), recipientPrivate, new Set());
    }

    async collectCIDs(metadata: SecureMetadata, recipientPrivate: CryptoKey, acc: Set<string>): Promise<Set<string>> {
        acc.add(metadata.objCID.toBaseEncodedString());
        metadata.metadataCIDs.forEach(v => acc.add(v.toBaseEncodedString()));

        const metadataChildren = metadata.metadataCIDs.map(async mdCID => (await this.readEncryptedMetadata(mdCID, recipientPrivate, metadata.cek)));
        const allMD = Array.from((await Promise.all(metadataChildren)));

        for (let i = 0; i < allMD.length; i++) {
            await this.collectCIDs(allMD[i], recipientPrivate, acc);
        }

        return acc;
    }

    async outerEncrypt(bytes: Uint8Array, cek: CryptoKey): Promise<Uint8Array> {
        const crypto = new Crypto();

        const randomIV = coseEncrypt.generateIV();
        const params: AesGcmParams = {
            name: SUBTLE_ENCRYPTION_ALG,
            iv: randomIV
        };

        const encObj = await crypto.subtle.encrypt(params, cek, bytes);
        return concat(randomIV, new Uint8Array(encObj));
    }

    async outerDecrypt(bytes: Uint8Array, cek: CryptoKey): Promise<Uint8Array> {
        const crypto = new Crypto();
        
        const randomIV = bytes.subarray(0, coseEncrypt.IV_BYTES);
        const params: AesGcmParams = {
            name: SUBTLE_ENCRYPTION_ALG,
            iv: randomIV
        };

        const encObj = new Uint8Array(await crypto.subtle.decrypt(params, cek, bytes.subarray(coseEncrypt.IV_BYTES)));

        return encObj;
    }

    async readEncryptedObject(cid: CID, cek: CryptoKey): Promise<any> {
        const client = this.createIPFSClient();
        let actualObject = decode(await this.outerDecrypt((await client.dag.get(cid)).value, cek));

        return actualObject;
    }

    async readEncryptedMetadata(cid: CID, recipientPrivate: CryptoKey, cek: CryptoKey): Promise<SecureMetadata> {
        const client = this.createIPFSClient();
        let encryptedMetadata = await this.outerDecrypt((await client.dag.get(cid)).value, cek);
        const actualMetadata = await coseDecrypt.decrypt(encryptedMetadata, recipientPrivate);

        console.debug(`Result: ${actualMetadata}`);

        return SecureMetadata.fromCose(actualMetadata);
    }

    isCID(x: any): boolean {
        return x.version && x.codec && x.multihash && x.multibaseName;
    }

    public async storeObjectWithContext(root: any, receiverKey: CryptoKey) {
        this.ctx.refresh();
        await this.prepareGraph(root, receiverKey);

        const storedRoot = this.ctx.stored.get(root)!;
        return this.prepareMetadataCose(receiverKey, [storedRoot[0], ...this.ctx.encryptedMetadata.get(storedRoot[0])!.get(receiverKey)!], storedRoot[1])
    }

    /**
     * Store every object defined as to-be-separated in ctx and replace these with their CIDs within the root's DAG
     * 
     * @param root 
     * @param ctx 
     */
    async prepareGraph(root: any, receiverKey: CryptoKey) {

        while (this.ctx.toStore.size > 0) { // TODO: Replace with a back-linking structure
            this.fixLinksAndCountDependencies(root, root);
            await this.storeNodesWithResolvedDependencies(receiverKey);
        }
    }

    fixLinksAndCountDependencies(parent: any, obj: any): number {
        let depCount: number = 0;

        for (let key in obj) {
            if (this.ctx.toSeparate.has(obj[key])) {
                // TODO: Create metadata?
                if (this.ctx.stored.has(obj[key])) {// Already stored in IPFS
                    const cid = this.ctx.stored.get(obj[key])![0];
                    if (!this.ctx.separatedCIDs.has(parent))
                    this.ctx.separatedCIDs.set(parent, [cid])
                    else
                    this.ctx.separatedCIDs.get(parent)!.push(cid);
                    obj[key] = cid;
                } else
                    depCount += this.fixLinksAndCountDependencies(obj[key], obj[key]) + 1;
            } else if (!_.isArrayLike(obj[key]) && _.isObjectLike(obj[key])) {
                depCount += this.fixLinksAndCountDependencies(parent, obj[key]);
            } else if (_.isArray(obj[key])) {
                depCount += obj[key].reduce((acc: number, childObject: any) => acc += this.fixLinksAndCountDependencies(parent, childObject), 0);
            }
        }

        if (parent === obj)
        this.ctx.nodes.get(parent)!.depCount = depCount;

        return depCount;
    }

    async storeNodesWithResolvedDependencies(receiverKey: CryptoKey) {
        for (const node of this.ctx.nodes.entries()) {
            await this.separate(node, receiverKey);
        }
    }

    async separate(node: [any, CtxNode], receiverKey: CryptoKey) {
        if (node[1].depCount == 0) {
            const cek = await this.newCEK();
            const stored = await this.storeObject(node[0], cek);
            this.ctx.registerStorageResult(node[0], [stored, cek], receiverKey);

            const childCIDs = this.ctx.separatedCIDs.get(node[0]) || [];
            for (let objectCID of childCIDs) {
                const mdCID = await this.storeMetadata(cek, receiverKey, [objectCID, ...this.ctx.encryptedMetadata.get(objectCID)!.get(receiverKey)!], this.ctx.mdBase.get(objectCID)!);
                this.ctx.encryptedMetadata.get(stored)!.get(receiverKey)!.push(mdCID);
            }
        }
    }

    createIPFSClient() {
        return create({url: this.ctx.apiEndpoint});
    }
}