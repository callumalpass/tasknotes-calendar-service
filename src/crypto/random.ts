export interface RandomByteSource {
  bytes(length: number): Uint8Array;
}

export const webCryptoRandom: RandomByteSource = {
  bytes(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 1 || length > 65_536) {
      throw new RangeError("random byte length must be an integer from 1 through 65536");
    }

    return crypto.getRandomValues(new Uint8Array(length));
  },
};

export function randomBytes(source: RandomByteSource, length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 1 || length > 65_536) {
    throw new RangeError("random byte length must be an integer from 1 through 65536");
  }

  const result = source.bytes(length);
  if (result.length !== length) {
    throw new Error("random byte source returned an unexpected number of bytes");
  }

  return Uint8Array.from(result);
}
