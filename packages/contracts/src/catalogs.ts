import {
  decodeStrictJsonObject,
  strictJsonDiagnosticCodes,
  strictJsonDiagnosticDescriptions,
  type StrictJsonDiagnostic,
} from "./strict-json.js";

export const propertyCatalogCategories = [
  "confidentiality",
  "integrity",
  "authentication",
  "binding",
  "replay-ordering",
  "randomness",
  "key-management",
  "downgrade-agility",
  "compromise-recovery",
  "metadata-privacy",
  "resilience",
  "evidence-publication",
] as const;
export type PropertyCatalogCategory = (typeof propertyCatalogCategories)[number];

export const attackerCapabilityDomains = [
  "network",
  "participation",
  "endpoint",
  "infrastructure",
  "secret-compromise",
  "time-state",
  "input-resource",
  "supply-chain",
  "observation",
  "physical",
] as const;
export type AttackerCapabilityDomain = (typeof attackerCapabilityDomains)[number];

export const propertyEvidenceKinds = [
  "specification",
  "behavioral-test",
  "adversarial-test",
  "formal-model",
  "machine-checked-proof",
  "runtime-control",
  "operational-procedure",
  "human-review",
] as const;
export type PropertyEvidenceKind = (typeof propertyEvidenceKinds)[number];

export const maximumPropertyEntries = 40;
export const maximumCapabilityEntries = 28;
export const maximumAttackerEntries = 10;
export const maximumThreatEntries = 40;
export const maximumPropertyReferences = 8;
export const maximumAttackerCapabilityReferences = 16;
export const maximumThreatReferences = 8;

export interface CatalogSafetyBoundary {
  readonly executable: false;
  readonly networkRequired: false;
  readonly secretsAllowed: false;
}

export interface PropertyCatalogEntry {
  readonly id: string;
  readonly title: string;
  readonly definition: string;
  readonly category: PropertyCatalogCategory;
  readonly assumptions: readonly string[];
  readonly exclusions: readonly string[];
  readonly dependsOn?: readonly string[];
  readonly requiredEvidenceKinds?: readonly PropertyEvidenceKind[];
  readonly sourceRefs: readonly string[];
}

export interface PropertyCatalog {
  readonly schemaVersion: "cryptocomm-property-catalog/v1";
  readonly catalogId: string;
  readonly catalogVersion: string;
  readonly properties: Readonly<Record<string, PropertyCatalogEntry>>;
  readonly safety: CatalogSafetyBoundary;
  readonly fixtureClassification?: "synthetic-test-only";
}

export interface AttackerCapabilityEntry {
  readonly id: string;
  readonly title: string;
  readonly definition: string;
  readonly domain: AttackerCapabilityDomain;
  readonly assumptions: readonly string[];
  readonly exclusions: readonly string[];
  readonly sourceRefs: readonly string[];
}

export interface AttackerModelEntry {
  readonly id: string;
  readonly title: string;
  readonly definition: string;
  readonly capabilities: readonly string[];
  readonly assumptions: readonly string[];
  readonly exclusions: readonly string[];
  readonly sourceRefs: readonly string[];
}

export interface AttackerCatalog {
  readonly schemaVersion: "cryptocomm-attacker-catalog/v1";
  readonly catalogId: string;
  readonly catalogVersion: string;
  readonly capabilities: Readonly<Record<string, AttackerCapabilityEntry>>;
  readonly attackers: Readonly<Record<string, AttackerModelEntry>>;
  readonly safety: CatalogSafetyBoundary;
  readonly fixtureClassification?: "synthetic-test-only";
}

export interface ThreatCatalogEntry {
  readonly id: string;
  readonly title: string;
  readonly definition: string;
  readonly category: PropertyCatalogCategory;
  readonly capabilities: readonly string[];
  readonly affectedProperties: readonly string[];
  readonly preconditions: readonly string[];
  readonly assumptions: readonly string[];
  readonly exclusions: readonly string[];
  readonly impact: string;
  readonly sourceRefs: readonly string[];
}

export interface ThreatCatalog {
  readonly schemaVersion: "cryptocomm-threat-catalog/v1";
  readonly catalogId: string;
  readonly catalogVersion: string;
  readonly threats: Readonly<Record<string, ThreatCatalogEntry>>;
  readonly safety: CatalogSafetyBoundary;
  readonly fixtureClassification?: "synthetic-test-only";
}

export interface CatalogSetInput {
  readonly propertyCatalogBytes: Uint8Array;
  readonly attackerCatalogBytes: Uint8Array;
  readonly threatCatalogBytes: Uint8Array;
}

export const catalogDiagnosticCodes = [
  ...strictJsonDiagnosticCodes,
  "CATALOG_STRUCTURE_INVALID",
  "CATALOG_ID_INVALID",
  "ENTRY_ID_INVALID",
  "ENTRY_KEY_ID_MISMATCH",
  "DUPLICATE_ENTRY_ID",
  "ENTRY_DOMAIN_MISMATCH",
  "PROPERTY_REFERENCE_DANGLING",
  "CAPABILITY_REFERENCE_DANGLING",
  "PROPERTY_SELF_DEPENDENCY",
  "PROPERTY_DEPENDENCY_CYCLE",
  "ATTACKER_CAPABILITIES_REQUIRED",
  "THREAT_CAPABILITIES_REQUIRED",
  "THREAT_PROPERTIES_REQUIRED",
  "CATEGORY_UNKNOWN",
  "RELATIONSHIP_UNKNOWN",
  "EVIDENCE_KIND_UNKNOWN",
  "CATALOG_SIZE_LIMIT_EXCEEDED",
  "REFERENCE_LIMIT_EXCEEDED",
  "REQUIRED_CATEGORY_MISSING",
  "SAFETY_BOUNDARY_VIOLATION",
  "ASSUMPTIONS_REQUIRED",
  "EXCLUSIONS_REQUIRED",
  "THREAT_PRECONDITIONS_REQUIRED",
  "THREAT_IMPACT_REQUIRED",
] as const;
export type CatalogDiagnosticCode = (typeof catalogDiagnosticCodes)[number];

export const catalogDiagnosticDescriptions: Readonly<
  Record<CatalogDiagnosticCode, string>
> = {
  ...strictJsonDiagnosticDescriptions,
  CATALOG_STRUCTURE_INVALID:
    "The strict-decoded value does not contain the catalog structure required for semantic validation.",
  CATALOG_ID_INVALID: "The catalog identifier is not a bounded stable identifier.",
  ENTRY_ID_INVALID: "A catalog entry identifier does not use its required stable namespace.",
  ENTRY_KEY_ID_MISMATCH: "A catalog map key differs from the contained entry identifier.",
  DUPLICATE_ENTRY_ID: "More than one map entry declares the same semantic identifier.",
  ENTRY_DOMAIN_MISMATCH:
    "An entry category or domain differs from the domain segment in its identifier.",
  PROPERTY_REFERENCE_DANGLING: "A property relationship references no declared property.",
  CAPABILITY_REFERENCE_DANGLING:
    "An attacker or threat relationship references no declared capability.",
  PROPERTY_SELF_DEPENDENCY: "A property depends on itself.",
  PROPERTY_DEPENDENCY_CYCLE: "The property dependency graph contains a cycle.",
  ATTACKER_CAPABILITIES_REQUIRED:
    "An attacker model must reference at least one capability.",
  THREAT_CAPABILITIES_REQUIRED: "A threat must reference at least one capability.",
  THREAT_PROPERTIES_REQUIRED: "A threat must reference at least one affected property.",
  CATEGORY_UNKNOWN: "An entry uses a category or domain outside the closed vocabulary.",
  RELATIONSHIP_UNKNOWN:
    "An entry uses an unknown relationship field or a relationship identifier from the wrong namespace.",
  EVIDENCE_KIND_UNKNOWN:
    "A property names an abstract evidence kind outside the closed evidence-lane vocabulary.",
  CATALOG_SIZE_LIMIT_EXCEEDED:
    "A catalog entry map exceeds its contract-specific bounded size.",
  REFERENCE_LIMIT_EXCEEDED:
    "An entry relationship exceeds its contract-specific bounded reference count.",
  REQUIRED_CATEGORY_MISSING:
    "The complete catalog set does not represent one of the required Issue scope categories.",
  SAFETY_BOUNDARY_VIOLATION:
    "The catalog does not preserve executable=false, networkRequired=false, and secretsAllowed=false.",
  ASSUMPTIONS_REQUIRED: "A catalog entry must declare at least one explicit assumption.",
  EXCLUSIONS_REQUIRED: "A catalog entry must declare at least one explicit exclusion.",
  THREAT_PRECONDITIONS_REQUIRED: "A threat must declare at least one explicit precondition.",
  THREAT_IMPACT_REQUIRED: "A threat must declare a bounded impact statement.",
};

export interface CatalogDiagnostic {
  readonly code: CatalogDiagnosticCode;
  readonly path: string;
  readonly message: string;
}
export interface CatalogValidationSuccess {
  readonly valid: true;
  readonly diagnostics: readonly [];
}
export interface CatalogValidationFailure {
  readonly valid: false;
  readonly diagnostics: readonly CatalogDiagnostic[];
}
export type CatalogValidationResult =
  | CatalogValidationSuccess
  | CatalogValidationFailure;

const catalogIdPattern = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const propertyIdPattern = /^property\.([a-z][a-z0-9-]{0,31})\.([a-z][a-z0-9-]{0,63})$/;
const capabilityIdPattern = /^capability\.([a-z][a-z0-9-]{0,31})\.([a-z][a-z0-9-]{0,63})$/;
const attackerIdPattern = /^attacker\.([a-z][a-z0-9-]{0,63})$/;
const threatIdPattern = /^threat\.([a-z][a-z0-9-]{0,31})\.([a-z][a-z0-9-]{0,63})$/;
const unknownRelationshipFields = [
  "attackers",
  "controls",
  "evidenceResults",
  "mitigations",
  "relatedProperties",
  "relatedThreats",
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function escapePointer(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function diagnostic(code: CatalogDiagnosticCode, path: string): CatalogDiagnostic {
  return { code, path, message: catalogDiagnosticDescriptions[code] };
}

function result(diagnostics: readonly CatalogDiagnostic[]): CatalogValidationResult {
  const unique = new Map<string, CatalogDiagnostic>();
  for (const entry of diagnostics) unique.set(entry.code + "\0" + entry.path, entry);
  const compare = (left: string, right: string): number =>
    left < right ? -1 : left > right ? 1 : 0;
  const stable = [...unique.values()].sort(
    (left, right) => compare(left.code, right.code) || compare(left.path, right.path),
  );
  return stable.length === 0
    ? { valid: true, diagnostics: [] }
    : { valid: false, diagnostics: stable };
}

function prefixedStrictDiagnostics(
  diagnostics: readonly StrictJsonDiagnostic[],
  prefix: string,
): readonly CatalogDiagnostic[] {
  return diagnostics.map((entry) => ({
    code: entry.code,
    path: prefix + entry.path,
    message: entry.message,
  }));
}

function boundedOwnKeys(
  value: Record<string, unknown>,
  maximum: number,
): { readonly keys: readonly string[]; readonly exceeded: boolean } {
  const keys: string[] = [];
  for (const key in value) {
    if (!Object.hasOwn(value, key)) continue;
    if (keys.length === maximum) return { keys, exceeded: true };
    keys.push(key);
  }
  return { keys: keys.sort(), exceeded: false };
}

function safetyValid(value: unknown): boolean {
  return (
    isRecord(value) &&
    value.executable === false &&
    value.networkRequired === false &&
    value.secretsAllowed === false
  );
}

function validateCatalogRoot(
  value: Record<string, unknown>,
  prefix: string,
): CatalogDiagnostic[] {
  const diagnostics: CatalogDiagnostic[] = [];
  if (typeof value.catalogId !== "string" || !catalogIdPattern.test(value.catalogId)) {
    diagnostics.push(diagnostic("CATALOG_ID_INVALID", prefix + "/catalogId"));
  }
  if (!safetyValid(value.safety)) {
    diagnostics.push(diagnostic("SAFETY_BOUNDARY_VIOLATION", prefix + "/safety"));
  }
  return diagnostics;
}

function validateStatements(entry: Record<string, unknown>, path: string): CatalogDiagnostic[] {
  const diagnostics: CatalogDiagnostic[] = [];
  if (!Array.isArray(entry.assumptions) || entry.assumptions.length === 0) {
    diagnostics.push(diagnostic("ASSUMPTIONS_REQUIRED", path + "/assumptions"));
  }
  if (!Array.isArray(entry.exclusions) || entry.exclusions.length === 0) {
    diagnostics.push(diagnostic("EXCLUSIONS_REQUIRED", path + "/exclusions"));
  }
  return diagnostics;
}

function validateUnknownRelationships(
  entry: Record<string, unknown>,
  path: string,
): CatalogDiagnostic[] {
  return unknownRelationshipFields
    .filter((field) => Object.hasOwn(entry, field))
    .map((field) => diagnostic("RELATIONSHIP_UNKNOWN", path + "/" + field));
}

function scanEntryMap(
  candidate: unknown,
  maximum: number,
  path: string,
): {
  readonly map?: Record<string, unknown>;
  readonly keys: readonly string[];
  readonly diagnostics: readonly CatalogDiagnostic[];
} {
  if (!isRecord(candidate)) {
    return {
      keys: [],
      diagnostics: [diagnostic("CATALOG_STRUCTURE_INVALID", path)],
    };
  }
  const scan = boundedOwnKeys(candidate, maximum);
  return {
    map: candidate,
    keys: scan.keys,
    diagnostics: scan.exceeded
      ? [diagnostic("CATALOG_SIZE_LIMIT_EXCEEDED", path)]
      : [],
  };
}

function entryIdentityDiagnostics(
  map: Record<string, unknown>,
  keys: readonly string[],
  path: string,
  pattern: RegExp,
): CatalogDiagnostic[] {
  const diagnostics: CatalogDiagnostic[] = [];
  const seenIds = new Set<string>();
  for (const key of keys) {
    const entryPath = path + "/" + escapePointer(key);
    const entry = map[key];
    if (!isRecord(entry)) {
      diagnostics.push(diagnostic("CATALOG_STRUCTURE_INVALID", entryPath));
      continue;
    }
    const id = entry.id;
    if (typeof id !== "string" || !pattern.test(id)) {
      diagnostics.push(diagnostic("ENTRY_ID_INVALID", entryPath + "/id"));
      continue;
    }
    if (key !== id) diagnostics.push(diagnostic("ENTRY_KEY_ID_MISMATCH", entryPath));
    if (seenIds.has(id)) diagnostics.push(diagnostic("DUPLICATE_ENTRY_ID", entryPath + "/id"));
    seenIds.add(id);
  }
  return diagnostics;
}

function categoryDiagnostics(
  entry: Record<string, unknown>,
  entryPath: string,
  idPattern: RegExp,
  allowed: readonly string[],
  field: "category" | "domain",
): CatalogDiagnostic[] {
  const diagnostics: CatalogDiagnostic[] = [];
  const category = entry[field];
  if (typeof category !== "string" || !allowed.includes(category)) {
    diagnostics.push(diagnostic("CATEGORY_UNKNOWN", entryPath + "/" + field));
    return diagnostics;
  }
  const id = entry.id;
  const match = typeof id === "string" ? idPattern.exec(id) : null;
  if (match?.[1] !== category) {
    diagnostics.push(diagnostic("ENTRY_DOMAIN_MISMATCH", entryPath + "/" + field));
  }
  return diagnostics;
}

function referenceArray(
  value: unknown,
  maximum: number,
  requiredCode: CatalogDiagnosticCode | undefined,
  path: string,
): { readonly values: readonly unknown[]; readonly diagnostics: readonly CatalogDiagnostic[] } {
  if (!Array.isArray(value) || value.length === 0) {
    return {
      values: [],
      diagnostics: requiredCode === undefined ? [] : [diagnostic(requiredCode, path)],
    };
  }
  if (value.length > maximum) {
    return {
      values: value.slice(0, maximum),
      diagnostics: [diagnostic("REFERENCE_LIMIT_EXCEEDED", path)],
    };
  }
  return { values: value, diagnostics: [] };
}

function validatePropertyCatalogParsed(value: Record<string, unknown>): CatalogDiagnostic[] {
  const prefix = "/propertyCatalog";
  const diagnostics = validateCatalogRoot(value, prefix);
  const scan = scanEntryMap(value.properties, maximumPropertyEntries, prefix + "/properties");
  diagnostics.push(...scan.diagnostics);
  if (scan.map === undefined) return diagnostics;
  diagnostics.push(
    ...entryIdentityDiagnostics(scan.map, scan.keys, prefix + "/properties", propertyIdPattern),
  );
  const represented = new Set<string>();
  const adjacency = new Map<string, string[]>();
  for (const key of scan.keys) {
    const entry = scan.map[key];
    if (!isRecord(entry)) continue;
    const path = prefix + "/properties/" + escapePointer(key);
    diagnostics.push(...validateStatements(entry, path));
    diagnostics.push(...validateUnknownRelationships(entry, path));
    diagnostics.push(
      ...categoryDiagnostics(entry, path, propertyIdPattern, propertyCatalogCategories, "category"),
    );
    if (typeof entry.category === "string" && propertyCatalogCategories.includes(entry.category as PropertyCatalogCategory)) {
      represented.add(entry.category);
    }
    const evidence = referenceArray(
      entry.requiredEvidenceKinds,
      maximumPropertyReferences,
      undefined,
      path + "/requiredEvidenceKinds",
    );
    diagnostics.push(...evidence.diagnostics);
    for (const [index, kind] of evidence.values.entries()) {
      if (typeof kind !== "string" || !propertyEvidenceKinds.includes(kind as PropertyEvidenceKind)) {
        diagnostics.push(diagnostic("EVIDENCE_KIND_UNKNOWN", path + "/requiredEvidenceKinds/" + index));
      }
    }
    const dependencies = entry.dependsOn === undefined
      ? { values: [] as readonly unknown[], diagnostics: [] as readonly CatalogDiagnostic[] }
      : referenceArray(entry.dependsOn, maximumPropertyReferences, undefined, path + "/dependsOn");
    diagnostics.push(...dependencies.diagnostics);
    const validDependencies: string[] = [];
    for (const [index, reference] of dependencies.values.entries()) {
      const referencePath = path + "/dependsOn/" + index;
      if (typeof reference !== "string" || !propertyIdPattern.test(reference)) {
        diagnostics.push(diagnostic("RELATIONSHIP_UNKNOWN", referencePath));
      } else if (reference === key) {
        diagnostics.push(diagnostic("PROPERTY_SELF_DEPENDENCY", referencePath));
      } else if (!Object.hasOwn(scan.map, reference)) {
        diagnostics.push(diagnostic("PROPERTY_REFERENCE_DANGLING", referencePath));
      } else {
        validDependencies.push(reference);
      }
    }
    adjacency.set(key, validDependencies.sort());
  }
  for (const category of propertyCatalogCategories) {
    if (!represented.has(category)) {
      diagnostics.push(
        diagnostic("REQUIRED_CATEGORY_MISSING", prefix + "/properties/$category/" + category),
      );
    }
  }
  diagnostics.push(...propertyCycleDiagnostics(adjacency, prefix + "/properties"));
  return diagnostics;
}

function propertyCycleDiagnostics(
  adjacency: ReadonlyMap<string, readonly string[]>,
  prefix: string,
): readonly CatalogDiagnostic[] {
  const diagnostics: CatalogDiagnostic[] = [];
  const state = new Map<string, 0 | 1 | 2>();
  const visit = (id: string): void => {
    state.set(id, 1);
    for (const dependency of adjacency.get(id) ?? []) {
      const dependencyState = state.get(dependency) ?? 0;
      if (dependencyState === 0) visit(dependency);
      else if (dependencyState === 1) {
        diagnostics.push(
          diagnostic("PROPERTY_DEPENDENCY_CYCLE", prefix + "/" + escapePointer(id) + "/dependsOn"),
        );
      }
    }
    state.set(id, 2);
  };
  for (const id of [...adjacency.keys()].sort()) {
    if ((state.get(id) ?? 0) === 0) visit(id);
  }
  return diagnostics;
}

function validateAttackerCatalogParsed(value: Record<string, unknown>): CatalogDiagnostic[] {
  const prefix = "/attackerCatalog";
  const diagnostics = validateCatalogRoot(value, prefix);
  const capabilityScan = scanEntryMap(value.capabilities, maximumCapabilityEntries, prefix + "/capabilities");
  const attackerScan = scanEntryMap(value.attackers, maximumAttackerEntries, prefix + "/attackers");
  diagnostics.push(...capabilityScan.diagnostics, ...attackerScan.diagnostics);
  const represented = new Set<string>();
  if (capabilityScan.map !== undefined) {
    diagnostics.push(...entryIdentityDiagnostics(capabilityScan.map, capabilityScan.keys, prefix + "/capabilities", capabilityIdPattern));
    for (const key of capabilityScan.keys) {
      const entry = capabilityScan.map[key];
      if (!isRecord(entry)) continue;
      const path = prefix + "/capabilities/" + escapePointer(key);
      diagnostics.push(...validateStatements(entry, path), ...validateUnknownRelationships(entry, path));
      diagnostics.push(...categoryDiagnostics(entry, path, capabilityIdPattern, attackerCapabilityDomains, "domain"));
      if (typeof entry.domain === "string" && attackerCapabilityDomains.includes(entry.domain as AttackerCapabilityDomain)) represented.add(entry.domain);
    }
    for (const domain of attackerCapabilityDomains) {
      if (!represented.has(domain)) diagnostics.push(diagnostic("REQUIRED_CATEGORY_MISSING", prefix + "/capabilities/$domain/" + domain));
    }
  }
  if (attackerScan.map !== undefined) {
    diagnostics.push(...entryIdentityDiagnostics(attackerScan.map, attackerScan.keys, prefix + "/attackers", attackerIdPattern));
    for (const key of attackerScan.keys) {
      const entry = attackerScan.map[key];
      if (!isRecord(entry)) continue;
      const path = prefix + "/attackers/" + escapePointer(key);
      diagnostics.push(...validateStatements(entry, path), ...validateUnknownRelationships(entry, path));
      const references = referenceArray(entry.capabilities, maximumAttackerCapabilityReferences, "ATTACKER_CAPABILITIES_REQUIRED", path + "/capabilities");
      diagnostics.push(...references.diagnostics);
      for (const [index, reference] of references.values.entries()) {
        const referencePath = path + "/capabilities/" + index;
        if (typeof reference !== "string" || !capabilityIdPattern.test(reference)) diagnostics.push(diagnostic("RELATIONSHIP_UNKNOWN", referencePath));
        else if (capabilityScan.map !== undefined && !Object.hasOwn(capabilityScan.map, reference)) diagnostics.push(diagnostic("CAPABILITY_REFERENCE_DANGLING", referencePath));
      }
    }
  }
  return diagnostics;
}

function validateThreatCatalogParsed(
  value: Record<string, unknown>,
  propertyMap?: Record<string, unknown>,
  capabilityMap?: Record<string, unknown>,
): CatalogDiagnostic[] {
  const prefix = "/threatCatalog";
  const diagnostics = validateCatalogRoot(value, prefix);
  const scan = scanEntryMap(value.threats, maximumThreatEntries, prefix + "/threats");
  diagnostics.push(...scan.diagnostics);
  if (scan.map === undefined) return diagnostics;
  diagnostics.push(...entryIdentityDiagnostics(scan.map, scan.keys, prefix + "/threats", threatIdPattern));
  const represented = new Set<string>();
  for (const key of scan.keys) {
    const entry = scan.map[key];
    if (!isRecord(entry)) continue;
    const path = prefix + "/threats/" + escapePointer(key);
    diagnostics.push(...validateStatements(entry, path), ...validateUnknownRelationships(entry, path));
    diagnostics.push(...categoryDiagnostics(entry, path, threatIdPattern, propertyCatalogCategories, "category"));
    if (typeof entry.category === "string" && propertyCatalogCategories.includes(entry.category as PropertyCatalogCategory)) represented.add(entry.category);
    const capabilities = referenceArray(entry.capabilities, maximumThreatReferences, "THREAT_CAPABILITIES_REQUIRED", path + "/capabilities");
    diagnostics.push(...capabilities.diagnostics);
    for (const [index, reference] of capabilities.values.entries()) {
      const referencePath = path + "/capabilities/" + index;
      if (typeof reference !== "string" || !capabilityIdPattern.test(reference)) diagnostics.push(diagnostic("RELATIONSHIP_UNKNOWN", referencePath));
      else if (capabilityMap !== undefined && !Object.hasOwn(capabilityMap, reference)) diagnostics.push(diagnostic("CAPABILITY_REFERENCE_DANGLING", referencePath));
    }
    const properties = referenceArray(entry.affectedProperties, maximumThreatReferences, "THREAT_PROPERTIES_REQUIRED", path + "/affectedProperties");
    diagnostics.push(...properties.diagnostics);
    for (const [index, reference] of properties.values.entries()) {
      const referencePath = path + "/affectedProperties/" + index;
      if (typeof reference !== "string" || !propertyIdPattern.test(reference)) diagnostics.push(diagnostic("RELATIONSHIP_UNKNOWN", referencePath));
      else if (propertyMap !== undefined && !Object.hasOwn(propertyMap, reference)) diagnostics.push(diagnostic("PROPERTY_REFERENCE_DANGLING", referencePath));
    }
    if (!Array.isArray(entry.preconditions) || entry.preconditions.length === 0) diagnostics.push(diagnostic("THREAT_PRECONDITIONS_REQUIRED", path + "/preconditions"));
    if (typeof entry.impact !== "string" || entry.impact.length === 0 || entry.impact.length > 512) diagnostics.push(diagnostic("THREAT_IMPACT_REQUIRED", path + "/impact"));
  }
  for (const category of propertyCatalogCategories) {
    if (!represented.has(category)) diagnostics.push(diagnostic("REQUIRED_CATEGORY_MISSING", prefix + "/threats/$category/" + category));
  }
  return diagnostics;
}

function decodeCatalog<T extends object>(
  bytes: Uint8Array,
  prefix: string,
): { readonly value?: T; readonly diagnostics: readonly CatalogDiagnostic[] } {
  const decoded = decodeStrictJsonObject<T>(bytes);
  return decoded.valid
    ? { value: decoded.value, diagnostics: [] }
    : { diagnostics: prefixedStrictDiagnostics(decoded.diagnostics, prefix) };
}

export function validatePropertyCatalog(bytes: Uint8Array): CatalogValidationResult {
  const decoded = decodeCatalog<PropertyCatalog>(bytes, "/propertyCatalog");
  if (decoded.value === undefined) return result(decoded.diagnostics);
  return result(validatePropertyCatalogParsed(decoded.value as unknown as Record<string, unknown>));
}

export function validateAttackerCatalog(bytes: Uint8Array): CatalogValidationResult {
  const decoded = decodeCatalog<AttackerCatalog>(bytes, "/attackerCatalog");
  if (decoded.value === undefined) return result(decoded.diagnostics);
  return result(validateAttackerCatalogParsed(decoded.value as unknown as Record<string, unknown>));
}

export function validateThreatCatalog(bytes: Uint8Array): CatalogValidationResult {
  const decoded = decodeCatalog<ThreatCatalog>(bytes, "/threatCatalog");
  if (decoded.value === undefined) return result(decoded.diagnostics);
  return result(validateThreatCatalogParsed(decoded.value as unknown as Record<string, unknown>));
}

export function validateCatalogSet(input: CatalogSetInput): CatalogValidationResult {
  const propertyDecoded = decodeCatalog<PropertyCatalog>(input.propertyCatalogBytes, "/propertyCatalog");
  const attackerDecoded = decodeCatalog<AttackerCatalog>(input.attackerCatalogBytes, "/attackerCatalog");
  const threatDecoded = decodeCatalog<ThreatCatalog>(input.threatCatalogBytes, "/threatCatalog");
  const diagnostics: CatalogDiagnostic[] = [
    ...propertyDecoded.diagnostics,
    ...attackerDecoded.diagnostics,
    ...threatDecoded.diagnostics,
  ];
  if (propertyDecoded.value === undefined || attackerDecoded.value === undefined || threatDecoded.value === undefined) return result(diagnostics);
  const property = propertyDecoded.value as unknown as Record<string, unknown>;
  const attacker = attackerDecoded.value as unknown as Record<string, unknown>;
  const threat = threatDecoded.value as unknown as Record<string, unknown>;
  diagnostics.push(...validatePropertyCatalogParsed(property));
  diagnostics.push(...validateAttackerCatalogParsed(attacker));
  diagnostics.push(...validateThreatCatalogParsed(
    threat,
    isRecord(property.properties) ? property.properties : undefined,
    isRecord(attacker.capabilities) ? attacker.capabilities : undefined,
  ));
  return result(diagnostics);
}
