export function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(bytes)));
}

export function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  const comparedLength = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;

  for (let index = 0; index < comparedLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }

  return difference === 0;
}
