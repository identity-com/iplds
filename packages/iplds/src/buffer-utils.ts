import { concat } from './utils';

const MAX_INT32 = 2 ** 32;

const writeUInt32BE = (buf: Uint8Array, value: number, offset?: number): void => {
  if (value < 0 || value >= MAX_INT32) {
    throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`);
  }
  buf.set([value >>> 24, value >>> 16, value >>> 8, value & 0xff], offset);
};

export const uint32be = (value: number): Uint8Array => {
  const buf = new Uint8Array(4);
  writeUInt32BE(buf, value);
  return buf;
};

export const lengthAndInput = (input: Uint8Array): Uint8Array => concat(uint32be(input.length), input);

// Implementation from:
// https://github.com/decentralized-identity/did-jwt
export const concatKDF = async (
  digest: (alg: string, data: BufferSource) => Promise<Uint8Array>,
  secret: Uint8Array,
  keyLen: number,
  alg: string,
): Promise<Uint8Array> => {
  if (keyLen !== 256) {
    throw new Error(`Unsupported key length: ${keyLen}`);
  }
  const value = concat(
    lengthAndInput(new TextEncoder().encode(alg)),
    lengthAndInput(new Uint8Array(0)), // apu
    lengthAndInput(new Uint8Array(0)), // apv
    uint32be(keyLen),
  );
  // since our key lenght is 256 we only have to do one round
  const roundNumber = 1;
  return await digest('sha256', concat(uint32be(roundNumber), secret, value));
};
