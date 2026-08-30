export const DEVICE_CLIENT_KINDS = ["web", "ios", "android", "obsidian"] as const;
export const MAX_DEVICE_NAME_BYTES = 128;

const textEncoder = new TextEncoder();

export type DeviceClientKind = (typeof DEVICE_CLIENT_KINDS)[number];

export function isValidDeviceName(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) return false;
  if (textEncoder.encode(value).length > MAX_DEVICE_NAME_BYTES) return false;
  return !Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
}

export function isDeviceClientKind(value: unknown): value is DeviceClientKind {
  return DEVICE_CLIENT_KINDS.some((candidate) => candidate === value);
}
