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
type UriComponents = {
  scheme?: string;
  host?: string;
  port?: string | number;
  path?: string;
  error?: string;
};
const uri = ajvRequire("fast-uri") as {
  parse(value: string, options?: { unicodeSupport: boolean }): UriComponents;
  serialize(value: UriComponents): string;
  normalize(value: string, options?: { unicodeSupport: boolean }): string;
  normalize(value: UriComponents): UriComponents;
  equal(left: string | UriComponents, right: string | UriComponents,
    options?: { unicodeSupport: boolean }): boolean;
  resolve(base: string, relative: string, options?: { unicodeSupport: boolean }): string;
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

    expect(manifest.pnpm?.overrides?.["fast-uri"]).toBe("3.1.8");
    expect(lock.overrides["fast-uri"]).toBe("3.1.8");
    for (const section of [lock.packages, lock.snapshots]) {
      expect(Object.keys(section).filter((key) => key.startsWith("fast-uri@")))
        .toEqual(["fast-uri@3.1.8"]);
    }
    expect(lock.snapshots["ajv@8.20.0"]?.dependencies?.["fast-uri"]).toBe("3.1.8");
    expect((ajvRequire("fast-uri/package.json") as { version: string }).version)
      .toBe("3.1.8");
  });

  it.each([
    { encoded: "//%53YNTHETIC.invalid/local", canonical: "//synthetic.invalid/local" },
    { encoded: "//syntheti%43.invalid/local", canonical: "//synthetic.invalid/local" },
  ])("folds decoded host case consistently: $encoded", ({ encoded, canonical }) => {
    expect(uri.parse(encoded).host).toBe("synthetic.invalid");
    expect(uri.normalize(encoded)).toBe(canonical);
    expect(uri.normalize(uri.normalize(encoded))).toBe(canonical);
    expect(uri.equal(encoded, canonical)).toBe(true);
    expect(uri.resolve("synthetic://base.invalid/", encoded))
      .toBe(uri.resolve("synthetic://base.invalid/", canonical));
  });

  it("preserves reserved and nested host escapes while folding host case", () => {
    expect(uri.normalize("//%53ynthetic.invalid%2fextra"))
      .toBe("//synthetic.invalid%2Fextra");
    expect(uri.normalize("//%2553ynthetic.invalid"))
      .toBe("//%2553ynthetic.invalid");
  });

  it.each([
    ["//Reader@%53ynthetic.invalid/x", "//reader@synthetic.invalid/x"],
    ["//%53ynthetic.invalid/Upper", "//synthetic.invalid/upper"],
    ["//%53ynthetic.invalid/?Key=Value", "//synthetic.invalid/?key=value"],
  ])("does not case-fold non-host components: %s", (left, right) => {
    expect(uri.parse(left).host).toBe(uri.parse(right).host);
    expect(uri.equal(left, right)).toBe(false);
  });

  it.each([
    "@other.invalid", "8081@other.invalid", "123/path", "123?query",
    "123#fragment", "123:456", "-1", "1.5", 1.5, NaN, Infinity, "\u0661",
  ])("rejects malformed component port %s without accepting equality", (port) => {
    const components = { scheme: "https", host: "trusted.invalid", port, path: "/local" };
    expect(() => uri.serialize({ ...components })).toThrow("URI port is malformed.");
    // Object normalization returns components, not a URL string. Assert the
    // library rejection itself, without passing its result to another parser.
    expect(() => uri.normalize({ ...components })).toThrow("URI port is malformed.");
    expect(uri.equal({ ...components }, { ...components })).toBe(false);
  });

  it.each([8192, "8192", "00081", ""])(
    "preserves valid digit/empty port serialization: %s",
    (port) => {
      // A non-special scheme avoids HTTP default-port normalization. This tests
      // component syntax only, not whether a port is usable by a network client.
      const components = { scheme: "synthetic", host: "trusted.invalid", port };
      expect(uri.serialize({ ...components })).toBe(`synthetic://trusted.invalid:${port}`);
      expect(uri.normalize({ ...components }).host).toBe("trusted.invalid");
      expect(uri.equal({ ...components }, { ...components })).toBe(true);
    },
  );

  it.each([
    "https://[2001/", "https://[/", "https://[synthetic.invalid/",
    "https://user@[@other.invalid/local", "https://user@]other.invalid/local",
    "https://user@prefix[@other.invalid/local",
  ])("fails closed on malformed authority brackets: %s", (value) => {
    for (const options of [undefined, { unicodeSupport: true }]) {
      expect(uri.parse(value, options).error).toBe("URI host is malformed.");
      // String normalization preserves the invalid input; preservation is not
      // acceptance. Error, equality and resolution are asserted separately.
      expect(uri.normalize(value, options)).toBe(value);
      expect(uri.equal(value, value, options)).toBe(false);
      expect(() => uri.resolve(base, value, options)).toThrow("URI host is malformed.");
    }
  });

  it.each(["https://[2001:db8::1]/local", "https://[2001:db8::2]:8192/local"])(
    "preserves valid documentation-only IPv6 literals: %s",
    (value) => {
      expect(uri.parse(value).error).toBeUndefined();
      expect(uri.normalize(value)).toBe(value);
      expect(uri.equal(value, value)).toBe(true);
      expect(uri.resolve(base, value)).toBe(value);
    },
  );

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
