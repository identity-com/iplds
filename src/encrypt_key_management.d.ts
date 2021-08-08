// import { KeyLike } from "jose/webcrypto/types";

declare module 'encrypt_key_management' {
    export async function encryptKeyManagement(alg: string, enc: string, key: import('jose/webcrypto/types').KeyLike, providedCek:KeyLike, providedParameters:any = {}): any
}