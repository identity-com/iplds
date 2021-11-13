import { CipherText, Cose } from './types';

export const getCEK = (cose: Cose): CipherText => cose[3][0][2];
export const getContent = (cose: Cose): CipherText => cose[2];
export const getIV = (cose: Cose): Uint8Array => cose[1].iv;
export const getRecipientId = (cose: Cose): string => cose[3][0][1].kid.toString();
