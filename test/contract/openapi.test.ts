import { describe, expect, it } from "vitest";

import spec from "../../openapi/v1.yaml?raw";
import {
  CLIENT_KINDS,
  MAX_CURSOR_LENGTH,
  MAX_JSON_BODY_BYTES,
  MAX_RANGE_DAYS,
  ROUTE_NAMES,
  routes,
} from "../../src/contracts";

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

describe("OpenAPI and runtime contract", () => {
  it("declares every runtime route once with the same method, path, and operation name", () => {
    const operationIds = [...spec.matchAll(/^\s+operationId: ([A-Za-z]+)$/gm)].map(
      (match) => match[1],
    );
    expect(operationIds.sort()).toEqual([...ROUTE_NAMES].sort());

    for (const route of routes) {
      const routeBlock = new RegExp(
        `^  ${escapeRegex(route.path)}:\\n    ${route.method.toLowerCase()}:\\n(?:.|\\n)*?^      operationId: ${route.name}$`,
        "m",
      );
      expect(spec, `${route.method} ${route.path}`).toMatch(routeBlock);
      expect(spec.match(new RegExp(`operationId: ${route.name}\\b`, "g"))).toHaveLength(1);
    }
  });

  it("keeps security and limit constants visible in the public document", () => {
    expect(spec).toContain(`x-max-body-bytes: ${MAX_JSON_BODY_BYTES}`);
    expect(spec).toContain(`maxLength: ${MAX_CURSOR_LENGTH}`);
    expect(spec).toContain(`${MAX_RANGE_DAYS} days`);
    expect(spec).toContain("maximum: 300");
    expect(spec).toContain('const: "private, no-store"');
    expect(spec).toContain("const: nosniff");
    expect(spec).toContain(`enum: [${CLIENT_KINDS.join(", ")}]`);
    expect(spec).toContain("{42}[AEIMQUYcgkosw048]");
    expect(spec).toContain("{21}[AQgw]");
  });

  it("documents the strict status union, opaque recurrence IDs, and tombstone pair variants", () => {
    expect(spec).toMatch(
      /Event:\n(?:.|\n)*?oneOf:\n\s+- \$ref: "#\/components\/schemas\/ConfirmedEvent"\n\s+- \$ref: "#\/components\/schemas\/TentativeEvent"\n\s+- \$ref: "#\/components\/schemas\/CancelledEvent"/u,
    );
    expect(spec).toContain("CancelledEventWithInterval");
    expect(spec).toContain("CancelledEventWithoutInterval");
    expect(spec).toContain("required: [series_id, original_start]");
    expect(spec).toContain("Opaque deterministic event identifier.");
    expect(spec).toContain("Opaque deterministic series identifier.");
    expect(spec).toContain("all-day end date is preserved exactly from Google");
    expect(spec).toContain("is exclusive");
    expect(spec).toContain("present interval increases strictly");
  });

  it("documents strict objects, UUID locators, one-calendar reads, and no write surface", () => {
    expect(spec).toContain("additionalProperties: false");
    expect(spec).toContain("format: uuid");
    expect(spec).toContain("maxItems: 1");
    expect(spec).toContain("one calendar and one provider page");
    expect(spec).not.toMatch(/^\s+(put|patch):$/m);
    expect(spec).not.toContain("Microsoft");
  });
});
