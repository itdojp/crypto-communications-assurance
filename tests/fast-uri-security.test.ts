import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";

import { describe, expect, it } from "vitest";
import { parse } from "yaml";

import { compileContract } from "../packages/contracts/src/index.js";

// Resolve the transitive copy used by the contracts package's AJV, not a
// separately installed test-only fast-uri. All URI strings are synthetic data;
// none is fetched, resolved through DNS, or used as a live target.
const contractsRequire = createRequire(
  new URL("../packages/contracts/package.json", import.meta.url),
);
const ajvRequire = createRequire(contractsRequire.resolve("ajv/package.json"));
const uri = ajvRequire("fast-uri") as {
  normalize(value: string): string;
  resolve(base: string, relative: string): string;
};
const base = "https://base.invalid/";

describe("synthetic-only fast-uri dependency security regressions", () => {
  it("pins the patched version in policy, lockfile, and AJV's installed dependency", async () => {
    const manifest = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    ) as { pnpm?: { overrides?: Record<string, string> } };
    const lock = parse(
      await readFile(new URL("../pnpm-lock.yaml", import.meta.url), "utf8"),
    ) as {
      overrides: Record<string, string>;
      packages: Record<string, unknown>;
      snapshots: Record<string, { dependencies?: Record<string, string> }>;
    };

    expect(manifest.pnpm?.overrides?.["fast-uri"]).toBe("3.1.6");
    expect(lock.overrides["fast-uri"]).toBe("3.1.6");
    for (const section of [lock.packages, lock.snapshots]) {
      expect(Object.keys(section).filter((key) => key.startsWith("fast-uri@")))
        .toEqual(["fast-uri@3.1.6"]);
    }
    expect(lock.snapshots["ajv@8.20.0"]?.dependencies?.["fast-uri"]).toBe("3.1.6");
    expect((ajvRequire("fast-uri/package.json") as { version: string }).version)
      .toBe("3.1.6");
  });

  it.each([
    { kind: "backslash authority", value: "https:\\\\synthetic.invalid/path" },
    { kind: "encoded authority in scheme", value: "%2f%2fsynthetic.invalid:/x" },
    { kind: "encoded control characters in scheme", value: "x%0d%0a:/x" },
    { kind: "malformed IPv6 host", value: "http://[1:2:3]/x" },
  ])("rejects resolution of $kind without making a request", ({ value }) => {
    expect(() => uri.resolve(base, value)).toThrow();
  });

  it.each(["%2f%2fsynthetic.invalid:/x", "x%0d%0a:/x"])(
    "does not turn a malformed scheme into URI structure or control bytes: %s",
    (value) => {
      // normalize preserves malformed input; it is not a validation/approval API.
      expect(uri.normalize(value)).toBe(value);
    },
  );

  it("preserves encoded hostname data instead of decoding it repeatedly", () => {
    const value = "https://%2561.synthetic.invalid/x";
    expect(uri.normalize(value)).toBe(value);
    expect(uri.resolve(base, value)).toBe(value);
  });

  it("canonicalizes a scheme-relative IDN using the resolved special scheme", () => {
    expect(uri.resolve(base, "//ｅｘａｍｐｌｅ.invalid/x"))
      .toBe("https://example.invalid/x");
  });

  it("preserves local Draft 2020-12 reference validation through the contracts API", () => {
    const validate = compileContract({
      $schema: "https://json-schema.org/draft/2020-12/schema",
      $id: "https://synthetic.invalid/schema/root.json",
      type: "object",
      additionalProperties: false,
      required: ["value"],
      properties: { value: { $ref: "#/$defs/value" } },
      $defs: { value: { type: "string", const: "synthetic-test-only" } },
    });
    expect(validate({ value: "synthetic-test-only" }).valid).toBe(true);
    expect(validate({ value: 42 }).valid).toBe(false);
    expect(validate({ value: "synthetic-test-only", extra: true }).valid).toBe(false);
  });
});
