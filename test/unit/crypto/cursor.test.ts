import { describe, expect, it } from "vitest";

import { CursorError, openEventCursor, sealEventCursor } from "../../../src/crypto/cursor";
import type { EventCursorBinding } from "../../../src/crypto/cursor";
import type { RandomByteSource } from "../../../src/crypto/random";

const NOW = 1_788_048_000;
const KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const OTHER_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 2);
const BINDING: EventCursorBinding = {
  principalId: "principal-a",
  connectionId: "connection-a",
  connectionGeneration: 3,
  calendarId: "calendar-a",
  rangeStart: "2026-08-01T00:00:00.000Z",
  rangeEnd: "2026-09-01T00:00:00.000Z",
};

function deterministicRandom(fill: number): RandomByteSource {
  return {
    bytes(length): Uint8Array {
      return new Uint8Array(length).fill(fill);
    },
  };
}

describe("event cursors", () => {
  it("round-trips an opaque provider page token", async () => {
    const cursor = await sealEventCursor("opaque/provider+token=", BINDING, NOW, KEY);

    expect(cursor).not.toContain("opaque");
    await expect(openEventCursor(cursor, BINDING, NOW + 599, KEY)).resolves.toBe(
      "opaque/provider+token=",
    );
  });

  it("uses a random IV for otherwise identical cursors", async () => {
    const first = await sealEventCursor("page", BINDING, NOW, KEY, deterministicRandom(1));
    const second = await sealEventCursor("page", BINDING, NOW, KEY, deterministicRandom(2));

    expect(first).not.toBe(second);
    await expect(openEventCursor(first, BINDING, NOW, KEY)).resolves.toBe("page");
    await expect(openEventCursor(second, BINDING, NOW, KEY)).resolves.toBe("page");
  });

  it.each([
    ["principal", { principalId: "principal-b" }],
    ["connection", { connectionId: "connection-b" }],
    ["generation", { connectionGeneration: 4 }],
    ["calendar", { calendarId: "calendar-b" }],
    ["range start", { rangeStart: "2026-08-02T00:00:00.000Z" }],
    ["range end", { rangeEnd: "2026-09-02T00:00:00.000Z" }],
  ] satisfies readonly (readonly [string, Partial<EventCursorBinding>])[])(
    "rejects replay under another %s binding",
    async (_name, replacement) => {
      const cursor = await sealEventCursor("page", BINDING, NOW, KEY);

      await expect(
        openEventCursor(cursor, { ...BINDING, ...replacement }, NOW, KEY),
      ).rejects.toBeInstanceOf(CursorError);
    },
  );

  it("rejects expiry at the exact ten-minute boundary", async () => {
    const cursor = await sealEventCursor("page", BINDING, NOW, KEY);

    await expect(openEventCursor(cursor, BINDING, NOW + 599, KEY)).resolves.toBe("page");
    await expect(openEventCursor(cursor, BINDING, NOW + 600, KEY)).rejects.toBeInstanceOf(
      CursorError,
    );
  });

  it.each(["", "c2.abc.def", "c1.only-two", "c1.***.abc", `c1.${"a".repeat(5000)}.abc`])(
    "rejects malformed cursor %j",
    async (cursor) => {
      await expect(openEventCursor(cursor, BINDING, NOW, KEY)).rejects.toBeInstanceOf(CursorError);
    },
  );

  it("rejects tampering and the wrong key", async () => {
    const cursor = await sealEventCursor("page", BINDING, NOW, KEY, deterministicRandom(4));
    const last = cursor.at(-1) ?? "A";
    const tampered = `${cursor.slice(0, -1)}${last === "A" ? "B" : "A"}`;

    await expect(openEventCursor(tampered, BINDING, NOW, KEY)).rejects.toBeInstanceOf(CursorError);
    await expect(openEventCursor(cursor, BINDING, NOW, OTHER_KEY)).rejects.toBeInstanceOf(
      CursorError,
    );
  });

  it.each([
    ["empty page token", "", BINDING, NOW, KEY],
    ["oversized page token", "x".repeat(2049), BINDING, NOW, KEY],
    ["escape-expanded page token", String.fromCharCode(0).repeat(2048), BINDING, NOW, KEY],
    ["invalid generation", "page", { ...BINDING, connectionGeneration: 0 }, NOW, KEY],
    ["invalid time", "page", BINDING, -1, KEY],
    ["short key", "page", BINDING, NOW, KEY.subarray(0, 31)],
  ] as const)("rejects %s while sealing", async (_name, token, binding, now, key) => {
    await expect(sealEventCursor(token, binding, now, key)).rejects.toBeInstanceOf(CursorError);
  });
});
