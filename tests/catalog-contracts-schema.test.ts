import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

import { beforeAll, describe, expect, it } from "vitest";

import {
  compileContractBytes,
  decodeStrictJsonObject,
  type ContractBytesValidationResult,
} from "../packages/contracts/src/index.js";

const loadBytes = (relativePath: string): Promise<Buffer> =>
  readFile(new URL(relativePath, import.meta.url));
const loadJson = async (relativePath: string): Promise<unknown> => {
  const decoded = decodeStrictJsonObject(await loadBytes(relativePath));
  if (!decoded.valid) throw new Error(`${relativePath}: strict decode failed`);
  return decoded.value;
};
const digest = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

describe("CCA-120 closed catalog schemas", () => {
  let propertyValidator: (bytes: Uint8Array) => ContractBytesValidationResult;
  let attackerValidator: (bytes: Uint8Array) => ContractBytesValidationResult;
  let threatValidator: (bytes: Uint8Array) => ContractBytesValidationResult;
  let manifestValidator: (bytes: Uint8Array) => ContractBytesValidationResult;

  beforeAll(async () => {
    const [property, attacker, threat, manifest] = await Promise.all([
      loadJson("../schema/cryptocomm-property-catalog-v1.schema.json"),
      loadJson("../schema/cryptocomm-attacker-catalog-v1.schema.json"),
      loadJson("../schema/cryptocomm-threat-catalog-v1.schema.json"),
      loadJson("../schema/cryptocomm-pack-manifest-v1.schema.json"),
    ]);
    propertyValidator = compileContractBytes(property as object);
    attackerValidator = compileContractBytes(attacker as object);
    threatValidator = compileContractBytes(threat as object);
    manifestValidator = compileContractBytes(manifest as object);
  });

  it.each([
    ["authoritative property catalog", "../pack/catalogs/v1/property-catalog.json", () => propertyValidator],
    ["authoritative attacker catalog", "../pack/catalogs/v1/attacker-catalog.json", () => attackerValidator],
    ["authoritative threat catalog", "../pack/catalogs/v1/threat-catalog.json", () => threatValidator],
    ["synthetic property fixture", "../fixtures/valid/property-catalog-v1.json", () => propertyValidator],
    ["synthetic attacker fixture", "../fixtures/valid/attacker-catalog-v1.json", () => attackerValidator],
    ["synthetic threat fixture", "../fixtures/valid/threat-catalog-v1.json", () => threatValidator],
    ["synthetic CCA-110 manifest", "../fixtures/valid/cca-120-catalog-manifest-v1.json", () => manifestValidator],
  ])("accepts %s through strict bytes and schema validation", async (_name, file, getValidator) => {
    expect(getValidator()(await loadBytes(file))).toMatchObject({ valid: true, stage: "validated" });
  });

  it.each([
    ["property", "../fixtures/valid/property-catalog-v1.json", () => propertyValidator],
    ["attacker", "../fixtures/valid/attacker-catalog-v1.json", () => attackerValidator],
    ["threat", "../fixtures/valid/threat-catalog-v1.json", () => threatValidator],
  ])("rejects escaped duplicate names before %s schema validation", async (_name, file, getValidator) => {
    const original = await loadBytes(file);
    const candidate = Buffer.concat([
      Buffer.from('{"catalog\\u0049d":"synthetic-shadow",', "utf8"),
      original.subarray(1),
    ]);
    const validation = getValidator()(candidate);
    expect(validation.valid).toBe(false);
    if (!validation.valid) {
      expect(validation.stage).toBe("decode");
      if (validation.stage === "decode") {
        expect(validation.errors).toMatchObject([{ code: "JSON_DUPLICATE_MEMBER", path: "/catalogId" }]);
      }
    }
  });

  it.each([
    ["malformed property ID", "../fixtures/invalid/property-catalog-malformed-id.json", () => propertyValidator, "propertyNames"],
    ["attacker without capabilities", "../fixtures/invalid/attacker-catalog-no-capabilities.json", () => attackerValidator, "minItems"],
    ["threat without capabilities", "../fixtures/invalid/threat-catalog-no-capabilities.json", () => threatValidator, "minItems"],
    ["threat without affected properties", "../fixtures/invalid/threat-catalog-no-affected-properties.json", () => threatValidator, "minItems"],
    ["unknown category", "../fixtures/invalid/property-catalog-unknown-category.json", () => propertyValidator, "enum"],
    ["excessive entry count", "../fixtures/invalid/property-catalog-excessive-entries.json", () => propertyValidator, "maxProperties"],
    ["excessive reference count", "../fixtures/invalid/property-catalog-excessive-references.json", () => propertyValidator, "maxItems"],
    ["unsafe safety flag", "../fixtures/invalid/property-catalog-unsafe-safety.json", () => propertyValidator, "const"],
    ["undeclared field", "../fixtures/invalid/threat-catalog-undeclared-field.json", () => threatValidator, "additionalProperties"],
    ["unknown relationship field", "../fixtures/invalid/threat-catalog-unknown-relationship.json", () => threatValidator, "additionalProperties"],
    ["missing explicit assumptions", "../fixtures/invalid/threat-catalog-missing-assumptions.json", () => threatValidator, "minItems"],
  ])("schema-rejects synthetic negative fixture: %s", async (_name, file, getValidator, keyword) => {
    const validation = getValidator()(await loadBytes(file));
    expect(validation.valid).toBe(false);
    if (!validation.valid) {
      expect(validation.stage).toBe("schema");
      if (validation.stage === "schema") expect(validation.errors.some((error) => error.keyword === keyword)).toBe(true);
    }
  });

  it.each([
    ["key/ID mismatch", "../fixtures/invalid/property-catalog-key-id-mismatch.json", () => propertyValidator],
    ["dangling property reference", "../fixtures/invalid/property-catalog-dangling-reference.json", () => propertyValidator],
    ["self dependency", "../fixtures/invalid/property-catalog-self-dependency.json", () => propertyValidator],
    ["dependency cycle", "../fixtures/invalid/property-catalog-dependency-cycle.json", () => propertyValidator],
    ["duplicate semantic ID", "../fixtures/invalid/property-catalog-duplicate-entry-id.json", () => propertyValidator],
    ["dangling capability", "../fixtures/invalid/attacker-catalog-dangling-capability.json", () => attackerValidator],
    ["dangling affected property", "../fixtures/invalid/threat-catalog-dangling-property.json", () => threatValidator],
  ])("keeps %s as a separate semantic rejection boundary", async (_name, file, getValidator) => {
    expect(getValidator()(await loadBytes(file))).toMatchObject({ valid: true, stage: "validated" });
  });

  it("keeps all three schemas closed Draft 2020-12 contracts", async () => {
    const cases = [
      ["../schema/cryptocomm-property-catalog-v1.schema.json", "cryptocomm-property-catalog/v1"],
      ["../schema/cryptocomm-attacker-catalog-v1.schema.json", "cryptocomm-attacker-catalog/v1"],
      ["../schema/cryptocomm-threat-catalog-v1.schema.json", "cryptocomm-threat-catalog/v1"],
    ] as const;
    for (const [file, schemaVersion] of cases) {
      const schema = (await loadJson(file)) as Record<string, unknown> & { properties: Record<string, { const?: string }> };
      expect(schema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
      expect(schema.additionalProperties).toBe(false);
      expect(schema.properties.schemaVersion?.const).toBe(schemaVersion);
    }
  });

  it("content-binds exact authoritative catalog bytes in the synthetic manifest", async () => {
    const decoded = decodeStrictJsonObject<{
      artifacts: Record<string, { digest: { value: string }; artifactType: string; contract: { contractId: string } }>;
      source: { repositoryId: string };
      fixtureClassification: string;
    }>(await loadBytes("../fixtures/valid/cca-120-catalog-manifest-v1.json"));
    if (!decoded.valid) throw new Error("synthetic manifest failed strict decoding");
    expect(decoded.value.source.repositoryId).toBe("synthetic:example/cca-120-source");
    expect(decoded.value.fixtureClassification).toBe("synthetic-test-only");
    expect(Object.keys(decoded.value.artifacts)).toHaveLength(3);
    for (const [artifactPath, declaration] of Object.entries(decoded.value.artifacts)) {
      expect(declaration.artifactType).toBe("catalog");
      expect(declaration.contract.contractId).toMatch(/^cryptocomm-(property|attacker|threat)-catalog\/v1$/);
      expect(declaration.digest.value).toBe(digest(await readFile(new URL(`../${artifactPath}`, import.meta.url))));
    }
  });

  it("strict-decodes every new JSON artifact", async () => {
    const roots = ["../pack/catalogs/v1", "../fixtures/valid", "../fixtures/invalid"];
    const selected = [
      "../schema/cryptocomm-property-catalog-v1.schema.json",
      "../schema/cryptocomm-attacker-catalog-v1.schema.json",
      "../schema/cryptocomm-threat-catalog-v1.schema.json",
    ];
    for (const root of roots) {
      const directory = new URL(root + "/", import.meta.url);
      for (const name of await readdir(directory)) {
        if (!name.endsWith(".json")) continue;
        if (root.includes("pack/") || name.includes("catalog")) selected.push(path.posix.join(root, name));
      }
    }
    expect(selected.length).toBeGreaterThanOrEqual(29);
    for (const file of selected.sort()) {
      expect(decodeStrictJsonObject(await loadBytes(file)).valid, file).toBe(true);
    }
  });
});
