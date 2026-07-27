import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import {
  attackerCapabilityDomains,
  decodeStrictJsonObject,
  maximumAttackerEntries,
  maximumCapabilityEntries,
  maximumPropertyEntries,
  maximumThreatEntries,
  propertyCatalogCategories,
  validateAttackerCatalog,
  validateCatalogSet,
  validatePropertyCatalog,
  validateThreatCatalog,
  type AttackerCatalog,
  type CatalogValidationResult,
  type PropertyCatalog,
  type ThreatCatalog,
} from "../packages/contracts/src/index.js";

const loadBytes = (relativePath: string): Promise<Buffer> =>
  readFile(new URL(relativePath, import.meta.url));
const loadStrict = async <T extends object>(relativePath: string): Promise<T> => {
  const decoded = decodeStrictJsonObject<T>(await loadBytes(relativePath));
  if (!decoded.valid) throw new Error(`${relativePath}: strict decode failed`);
  return decoded.value;
};
const codes = (validation: CatalogValidationResult): readonly string[] =>
  validation.diagnostics.map((entry) => entry.code);

const authoritativeInput = async () => ({
  propertyCatalogBytes: await loadBytes("../pack/catalogs/v1/property-catalog.json"),
  attackerCatalogBytes: await loadBytes("../pack/catalogs/v1/attacker-catalog.json"),
  threatCatalogBytes: await loadBytes("../pack/catalogs/v1/threat-catalog.json"),
});
const fixtureInput = async () => ({
  propertyCatalogBytes: await loadBytes("../fixtures/valid/property-catalog-v1.json"),
  attackerCatalogBytes: await loadBytes("../fixtures/valid/attacker-catalog-v1.json"),
  threatCatalogBytes: await loadBytes("../fixtures/valid/threat-catalog-v1.json"),
});

describe("CCA-120 deterministic catalog semantics", () => {
  it("accepts the complete authoritative cross-catalog set", async () => {
    expect(validateCatalogSet(await authoritativeInput())).toEqual({ valid: true, diagnostics: [] });
  });

  it("accepts the explicitly synthetic complete cross-catalog fixture set", async () => {
    expect(validateCatalogSet(await fixtureInput())).toEqual({ valid: true, diagnostics: [] });
  });

  it("accepts each synthetic catalog independently through exact bytes", async () => {
    expect(validatePropertyCatalog(await loadBytes("../fixtures/valid/property-catalog-v1.json"))).toEqual({ valid: true, diagnostics: [] });
    expect(validateAttackerCatalog(await loadBytes("../fixtures/valid/attacker-catalog-v1.json"))).toEqual({ valid: true, diagnostics: [] });
    expect(validateThreatCatalog(await loadBytes("../fixtures/valid/threat-catalog-v1.json"))).toEqual({ valid: true, diagnostics: [] });
  });

  it.each([
    ["malformed ID", "property", "../fixtures/invalid/property-catalog-malformed-id.json", "ENTRY_ID_INVALID"],
    ["key/ID mismatch", "property", "../fixtures/invalid/property-catalog-key-id-mismatch.json", "ENTRY_KEY_ID_MISMATCH"],
    ["dangling property", "property", "../fixtures/invalid/property-catalog-dangling-reference.json", "PROPERTY_REFERENCE_DANGLING"],
    ["self dependency", "property", "../fixtures/invalid/property-catalog-self-dependency.json", "PROPERTY_SELF_DEPENDENCY"],
    ["dependency cycle", "property", "../fixtures/invalid/property-catalog-dependency-cycle.json", "PROPERTY_DEPENDENCY_CYCLE"],
    ["duplicate semantic ID", "property", "../fixtures/invalid/property-catalog-duplicate-entry-id.json", "DUPLICATE_ENTRY_ID"],
    ["attacker dangling capability", "attacker", "../fixtures/invalid/attacker-catalog-dangling-capability.json", "CAPABILITY_REFERENCE_DANGLING"],
    ["attacker without capabilities", "attacker", "../fixtures/invalid/attacker-catalog-no-capabilities.json", "ATTACKER_CAPABILITIES_REQUIRED"],
    ["threat without capabilities", "threat", "../fixtures/invalid/threat-catalog-no-capabilities.json", "THREAT_CAPABILITIES_REQUIRED"],
    ["threat without properties", "threat", "../fixtures/invalid/threat-catalog-no-affected-properties.json", "THREAT_PROPERTIES_REQUIRED"],
    ["unknown category", "property", "../fixtures/invalid/property-catalog-unknown-category.json", "CATEGORY_UNKNOWN"],
    ["excessive entries", "property", "../fixtures/invalid/property-catalog-excessive-entries.json", "CATALOG_SIZE_LIMIT_EXCEEDED"],
    ["excessive references", "property", "../fixtures/invalid/property-catalog-excessive-references.json", "REFERENCE_LIMIT_EXCEEDED"],
    ["unsafe safety", "property", "../fixtures/invalid/property-catalog-unsafe-safety.json", "SAFETY_BOUNDARY_VIOLATION"],
    ["unknown relationship", "threat", "../fixtures/invalid/threat-catalog-unknown-relationship.json", "RELATIONSHIP_UNKNOWN"],
    ["missing assumptions", "threat", "../fixtures/invalid/threat-catalog-missing-assumptions.json", "ASSUMPTIONS_REQUIRED"],
  ] as const)("rejects %s with stable diagnostic %s", async (_name, kind, file, expected) => {
    const bytes = await loadBytes(file);
    const validation = kind === "property" ? validatePropertyCatalog(bytes) : kind === "attacker" ? validateAttackerCatalog(bytes) : validateThreatCatalog(bytes);
    expect(codes(validation)).toContain(expected);
  });

  it("rejects cross-catalog dangling affected-property references", async () => {
    const input = await fixtureInput();
    input.threatCatalogBytes = await loadBytes("../fixtures/invalid/threat-catalog-dangling-property.json");
    expect(codes(validateCatalogSet(input))).toContain("PROPERTY_REFERENCE_DANGLING");
  });

  it("reports missing required category coverage deterministically", async () => {
    const property = await loadStrict<PropertyCatalog>("../fixtures/valid/property-catalog-v1.json");
    const mutable = structuredClone(property) as PropertyCatalog & { properties: Record<string, unknown> };
    const missing = Object.keys(mutable.properties).find((id) => id.startsWith("property.evidence-publication."));
    if (missing === undefined) throw new Error("expected evidence-publication fixture property");
    delete mutable.properties[missing];
    expect(codes(validatePropertyCatalog(Buffer.from(JSON.stringify(mutable))))).toContain("REQUIRED_CATEGORY_MISSING");
  });

  it("keeps substantive authoritative catalogs within reviewed bounds", async () => {
    const [properties, attackers, threats] = await Promise.all([
      loadStrict<PropertyCatalog>("../pack/catalogs/v1/property-catalog.json"),
      loadStrict<AttackerCatalog>("../pack/catalogs/v1/attacker-catalog.json"),
      loadStrict<ThreatCatalog>("../pack/catalogs/v1/threat-catalog.json"),
    ]);
    expect(Object.keys(properties.properties)).toHaveLength(maximumPropertyEntries);
    expect(Object.keys(attackers.capabilities)).toHaveLength(maximumCapabilityEntries);
    expect(Object.keys(attackers.attackers)).toHaveLength(8);
    expect(Object.keys(attackers.attackers).length).toBeLessThanOrEqual(maximumAttackerEntries);
    expect(Object.keys(threats.threats)).toHaveLength(36);
    expect(Object.keys(threats.threats).length).toBeLessThanOrEqual(maximumThreatEntries);
    expect(new Set(Object.values(properties.properties).map((entry) => entry.category))).toEqual(new Set(propertyCatalogCategories));
    expect(new Set(Object.values(attackers.capabilities).map((entry) => entry.domain))).toEqual(new Set(attackerCapabilityDomains));
    expect(new Set(Object.values(threats.threats).map((entry) => entry.category))).toEqual(new Set(propertyCatalogCategories));
  });

  it("keeps threat relationships capability-derived and free of a second attacker authority", async () => {
    const [attackers, threats] = await Promise.all([
      loadStrict<AttackerCatalog>("../pack/catalogs/v1/attacker-catalog.json"),
      loadStrict<ThreatCatalog>("../pack/catalogs/v1/threat-catalog.json"),
    ]);
    const referenced = new Set([
      ...Object.values(attackers.attackers).flatMap((entry) => entry.capabilities),
      ...Object.values(threats.threats).flatMap((entry) => entry.capabilities),
    ]);
    expect([...referenced].every((id) => Object.hasOwn(attackers.capabilities, id))).toBe(true);
    expect(Object.keys(attackers.capabilities).every((id) => referenced.has(id))).toBe(true);
    for (const threat of Object.values(threats.threats)) {
      expect(Object.hasOwn(threat as unknown as object, "attackers")).toBe(false);
      expect(threat.capabilities.length).toBeGreaterThan(0);
      expect(threat.affectedProperties.length).toBeGreaterThan(0);
      expect(threat.preconditions.length).toBeGreaterThan(0);
      expect(threat.assumptions.length).toBeGreaterThan(0);
      expect(threat.exclusions.length).toBeGreaterThan(0);
      expect(threat.impact.length).toBeGreaterThan(0);
    }
  });

  it("resolves every machine-readable coverage-matrix identifier", async () => {
    const [properties, attackers, threats, coverage] = await Promise.all([
      loadStrict<PropertyCatalog>("../pack/catalogs/v1/property-catalog.json"),
      loadStrict<AttackerCatalog>("../pack/catalogs/v1/attacker-catalog.json"),
      loadStrict<ThreatCatalog>("../pack/catalogs/v1/threat-catalog.json"),
      loadStrict<{ classification: string; scope: string; rows: Array<{ scopeCategory: string; propertyIds: string[]; capabilityIds: string[]; threatIds: string[]; sourceRefs: string[] }> }>("../pack/catalogs/v1/coverage-matrix.json"),
    ]);
    expect(coverage).toMatchObject({ classification: "public-review-matrix", scope: "CCA-120 Issue #7" });
    expect(coverage.rows).toHaveLength(13);
    for (const row of coverage.rows) {
      expect(row.propertyIds.length, row.scopeCategory).toBeGreaterThan(0);
      expect(row.capabilityIds.length, row.scopeCategory).toBeGreaterThan(0);
      expect(row.threatIds.length, row.scopeCategory).toBeGreaterThan(0);
      expect(row.sourceRefs.length, row.scopeCategory).toBeGreaterThan(0);
      expect(row.propertyIds.every((id) => Object.hasOwn(properties.properties, id))).toBe(true);
      expect(row.capabilityIds.every((id) => Object.hasOwn(attackers.capabilities, id))).toBe(true);
      expect(row.threatIds.every((id) => Object.hasOwn(threats.threats, id))).toBe(true);
    }
  });

  it("keeps normative catalogs free of runtime identity, approval, private evidence, and status fields", async () => {
    const values = await Promise.all([
      loadStrict<PropertyCatalog>("../pack/catalogs/v1/property-catalog.json"),
      loadStrict<AttackerCatalog>("../pack/catalogs/v1/attacker-catalog.json"),
      loadStrict<ThreatCatalog>("../pack/catalogs/v1/threat-catalog.json"),
    ]);
    const forbidden = new Set(["timestamp", "createdAt", "updatedAt", "runId", "hostname", "token", "secret", "privateEvidence", "humanApproved", "approval", "status", "riskScore", "severity", "likelihood", "mitigation"]);
    const pending: unknown[] = [...values];
    while (pending.length > 0) {
      const current = pending.pop();
      if (current === null || typeof current !== "object") continue;
      for (const [key, value] of Object.entries(current)) {
        expect(forbidden.has(key), key).toBe(false);
        pending.push(value);
      }
    }
  });

  it("returns strict exact-byte diagnostics before semantic inspection", async () => {
    const input = await authoritativeInput();
    input.propertyCatalogBytes = Buffer.from('{"catalogId":"one","catalog\\u0049d":"two"}');
    const validation = validateCatalogSet(input);
    expect(codes(validation)).toEqual(["JSON_DUPLICATE_MEMBER"]);
    expect(validation.diagnostics[0]?.path).toBe("/propertyCatalog/catalogId");
  });
});
