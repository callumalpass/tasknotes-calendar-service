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

describe("OpenAPI and runtime contract", () => {
  it("declares every runtime route once with the same method, path, and operation name", () => {
    const operationIds = [...spec.matchAll(/^\s+operationId: ([A-Za-z]+)$/gm)].map(
      (match) => match[1],
    );
    expect(operationIds.sort()).toEqual([...ROUTE_NAMES].sort());

    for (const route of routes) {
      const pathBlock = spec.split(`  ${route.path}:\n`)[1]?.split(/^ {2}\//m)[0];
      const routeBlock = new RegExp(
        `^    ${route.method.toLowerCase()}:\n(?:.|\n)*?^      operationId: ${route.name}$`,
        "m",
      );
      expect(pathBlock, `${route.method} ${route.path}`).toMatch(routeBlock);
      expect(spec.match(new RegExp(`operationId: ${route.name}\\b`, "g"))).toHaveLength(1);
    }
  });

  it("documents HTML callback completion and sign-in-only confirmation", () => {
    expect(spec).toContain("text/html:");
    expect(spec).toContain("Unknown callback");
    expect(spec).toContain("required: [polling_secret, code_verifier, confirmation_code]");
    expect(spec).toContain("#/components/requestBodies/SignInRedeem");
    expect(spec).toContain("#/components/requestBodies/TransactionRedeem");
    expect(spec).toContain("Content-Security-Policy:");
    expect(spec.split("  schemas:\n")[1]).toContain("    SignInRedeemRequest:\n");
    expect(spec.split("  requestBodies:\n")[1]?.split("  schemas:\n")[0]).not.toContain(
      "    SignInRedeemRequest:\n",
    );
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

  it("documents calendar display data and the event display fields on every variant", () => {
    for (const field of ["transparency", "event_type", "self_response"]) {
      expect(spec.match(new RegExp(`^ {8}${field}: \\{ \\$ref: `, "gm"))).toHaveLength(4);
      expect(spec.match(new RegExp(`^ {10}${field},$`, "gm"))).toHaveLength(4);
    }
    expect(spec).toContain("enum: [opaque, transparent]");
    expect(spec).toContain(
      "enum: [default, focus_time, out_of_office, working_location, birthday, from_gmail]",
    );
    expect(spec).toContain("enum: [accepted, declined, tentative, needs_action, null]");
    expect(spec).toContain("No other attendee is read.");
    expect(spec).toContain('pattern: "^#[0-9a-f]{6}$"');
    expect(spec).toContain("can_write, time_zone, is_primary, is_selected, color]");
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
    expect(spec).toContain("present interval does not decrease");
  });

  it("documents strict objects, UUID locators, one-calendar reads, and conditional writes", () => {
    expect(spec).toContain("additionalProperties: false");
    expect(spec).toContain("format: uuid");
    expect(spec).toContain("maxItems: 1");
    expect(spec).toContain("one calendar and one provider page");
    expect(spec).toMatch(/^\s+patch:$/m);
    expect(spec).toContain("name: If-Match");
    expect(spec).not.toContain("Microsoft");
  });
});
