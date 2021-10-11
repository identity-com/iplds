import { concat } from './utils';

export const encoder = new TextEncoder();
export const decoder = new TextDecoder();
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

export const concatKdf = async (
  digest: (alg: string, data: BufferSource) => Promise<Uint8Array>,
  secret: Uint8Array,
  bits: number,
  value: Uint8Array,
): Promise<Uint8Array> => {
  const iterations = Math.ceil((bits >> 3) / 32);
  let res = Uint8Array.of();
  for (let iter = 1; iter <= iterations; iter++) {
    const buf = new Uint8Array(4 + secret.length + value.length);
    buf.set(uint32be(iter));
    buf.set(secret, 4);
    buf.set(value, 4 + secret.length);
    if (res.length === 0) {
      res = await digest('sha256', buf);
    } else {
      res = concat(res, await digest('sha256', buf));
    }
  }
  return res.slice(0, bits >> 3);
};
