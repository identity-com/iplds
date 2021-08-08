import { CID } from "ipfs-http-client";
import _ from "lodash";

export class IPSecureContext {

    apiEndpoint: string|undefined;
    toSeparate = new Set<any> ();
    toStore = new Set<any> ();
    stored = new WeakMap<any, [CID, CryptoKey]> ();
    nodes = new Map<any, CtxNode>();
    separatedCIDs = new Map<any, Array<CID>>();
    mdBase = new Map<CID, CryptoKey>();
    encryptedMetadata = new Map<CID, Map<CryptoKey, Array<CID>>>();
    
    // idx = new WeakMap<any, number>();
    // byIdx = new Map<number, any>();

    constructor(apiEndpoint?: string) {
        if (apiEndpoint)
            this.apiEndpoint = apiEndpoint;
    }

    add(obj: any): this;
    add(obj: any, path: string): this

    add(obj: any, path?: string): this {

        const targetObj = path ? _.get(obj, toLodashPath(path)) : obj;
            // this.idx.set(_.get(obj, path), )
        this.toSeparate.add(targetObj);
        this.nodes.set(targetObj, new CtxNode(targetObj));
        
        return this;
    }

    registerStorageResult(obj: any, storageResult: [CID, CryptoKey], receiverKey: CryptoKey) {
        this.stored.set(obj, storageResult);
        this.mdBase.set(storageResult[0], storageResult[1]);
        
        const initMDs = new Map<CryptoKey, Array<CID>>();
        initMDs.set(receiverKey, []);
        this.encryptedMetadata.set(storageResult[0], initMDs);

        this.toStore.delete(obj);
    }

    refresh() {
        this.toStore = new Set();
        this.toSeparate.forEach(v => {
            if (!this.stored.has(v))
                this.toStore.add(v);
        });
    }

}

export class CtxNode {
    depCount: number = 0;
    obj: any;

    constructor(obj: any) {
        this.obj = obj;
    }
}

function toLodashPath(path: string): string {
    let res = path.replaceAll('/', '.');
    if (res.startsWith('.'))
        res = res.substr(1);

    return res;
}
