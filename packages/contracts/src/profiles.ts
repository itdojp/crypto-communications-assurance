import { createHash } from "node:crypto";

import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";

import attackerCatalogSchema from "../../../schema/cryptocomm-attacker-catalog-v1.schema.json" with { type: "json" };
import capabilityModuleCatalogSchema from "../../../schema/cryptocomm-capability-module-catalog-v1.schema.json" with { type: "json" };
import profileRequestSchema from "../../../schema/cryptocomm-profile-request-v1.schema.json" with { type: "json" };
import propertyCatalogSchema from "../../../schema/cryptocomm-property-catalog-v1.schema.json" with { type: "json" };
import resolvedProfileSchema from "../../../schema/cryptocomm-resolved-profile-v1.schema.json" with { type: "json" };
import threatCatalogSchema from "../../../schema/cryptocomm-threat-catalog-v1.schema.json" with { type: "json" };

import {
  validateCatalogSet,
  type AttackerCatalog,
  type CatalogDiagnosticCode,
  type PropertyCatalog,
  type ThreatCatalog,
} from "./catalogs.js";
import {
  decodeStrictJsonObject,
  type StrictJsonDiagnostic,
  type StrictJsonDiagnosticCode,
} from "./strict-json.js";

export const maximumCapabilityModules = 64;
export const maximumModuleRequirements = 8;
export const maximumModuleSelections = 32;
export const maximumModuleConflicts = 64;
export const maximumRequestedModules = 32;
export const maximumProfileDiagnostics = 256;

export interface ExactDigest {
  readonly algorithm: "sha256";
  readonly value: string;
}

export interface ExactCatalogBinding {
  readonly contractId: string;
  readonly catalogId: string;
  readonly catalogVersion: string;
  readonly digest: ExactDigest;
}

export interface ProfileSafetyBoundary {
  readonly executable: false;
  readonly networkRequired: false;
  readonly secretsAllowed: false;
}

export interface ModuleSelections {
  readonly properties: readonly string[];
  readonly capabilities: readonly string[];
  readonly attackers: readonly string[];
  readonly threats: readonly string[];
}

interface CapabilityModuleBase {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly assumptions: readonly string[];
  readonly exclusions: readonly string[];
}

export interface AvailableCapabilityModule extends CapabilityModuleBase {
  readonly state: "available";
  readonly selections: ModuleSelections;
  readonly requires: readonly string[];
}

export interface UnsupportedCapabilityModule extends CapabilityModuleBase {
  readonly state: "unsupported";
  readonly reason: string;
  readonly scope: string;
}

export type CapabilityModule =
  | AvailableCapabilityModule
  | UnsupportedCapabilityModule;

export interface CapabilityModuleCatalog {
  readonly schemaVersion: "cryptocomm-capability-module-catalog/v1";
  readonly catalogId: string;
  readonly catalogVersion: string;
  readonly catalogBindings: {
    readonly propertyCatalog: ExactCatalogBinding;
    readonly attackerCatalog: ExactCatalogBinding;
    readonly threatCatalog: ExactCatalogBinding;
  };
  readonly modules: Readonly<Record<string, CapabilityModule>>;
  readonly conflicts: readonly (readonly [string, string])[];
  readonly safety: ProfileSafetyBoundary;
  readonly fixtureClassification?: "synthetic-test-only";
}

export interface ProfileRequest {
  readonly schemaVersion: "cryptocomm-profile-request/v1";
  readonly profileId: string;
  readonly moduleCatalog: ExactCatalogBinding;
  readonly requestedModules: readonly string[];
  readonly safety: ProfileSafetyBoundary;
  readonly fixtureClassification?: "synthetic-test-only";
}

export type ModuleResolutionState =
  | "resolved"
  | "unknown"
  | "unsupported"
  | "unresolvable";

interface ModuleOutcomeBase {
  readonly id: string;
  readonly state: ModuleResolutionState;
  readonly requested: boolean;
  readonly requiredBy: readonly string[];
}

export interface ResolvedModuleOutcome extends ModuleOutcomeBase {
  readonly state: "resolved";
}

export interface UnknownModuleOutcome extends ModuleOutcomeBase {
  readonly state: "unknown";
}

export interface UnsupportedModuleOutcome extends ModuleOutcomeBase {
  readonly state: "unsupported";
  readonly reason: string;
  readonly scope: string;
}

export interface UnresolvableModuleOutcome extends ModuleOutcomeBase {
  readonly state: "unresolvable";
  readonly conflictsWith: readonly string[];
  readonly unresolvedDependencies: readonly string[];
}

export type ModuleOutcome =
  | ResolvedModuleOutcome
  | UnknownModuleOutcome
  | UnsupportedModuleOutcome
  | UnresolvableModuleOutcome;

export type InclusionReason =
  | "module-selection"
  | "property-dependency"
  | "attacker-capability"
  | "threat-capability"
  | "threat-affected-property";

export interface SelectionSource {
  readonly sourceModuleId: string;
  readonly inclusionReasons: readonly InclusionReason[];
}

export interface ResolvedSelection {
  readonly id: string;
  readonly sources: readonly SelectionSource[];
}

export interface SourceStatement {
  readonly sourceModuleId: string;
  readonly statement: string;
}

export interface ResolvedProfile {
  readonly schemaVersion: "cryptocomm-resolved-profile/v1";
  readonly profileId: string;
  readonly state: "complete" | "incomplete";
  readonly inputBindings: {
    readonly moduleCatalog: ExactCatalogBinding;
    readonly propertyCatalog: ExactCatalogBinding;
    readonly attackerCatalog: ExactCatalogBinding;
    readonly threatCatalog: ExactCatalogBinding;
  };
  readonly requestedModules: readonly string[];
  readonly modules: Readonly<Record<string, ModuleOutcome>>;
  readonly selections: {
    readonly properties: Readonly<Record<string, ResolvedSelection>>;
    readonly capabilities: Readonly<Record<string, ResolvedSelection>>;
    readonly attackers: Readonly<Record<string, ResolvedSelection>>;
    readonly threats: Readonly<Record<string, ResolvedSelection>>;
  };
  readonly assumptions: readonly SourceStatement[];
  readonly exclusions: readonly SourceStatement[];
  readonly fixtureClassification?: "synthetic-test-only";
  readonly safety: ProfileSafetyBoundary;
}

export interface CapabilityModuleCatalogInput {
  readonly propertyCatalogBytes: Uint8Array;
  readonly attackerCatalogBytes: Uint8Array;
  readonly threatCatalogBytes: Uint8Array;
  readonly moduleCatalogBytes: Uint8Array;
}

export interface ProfileResolutionInput extends CapabilityModuleCatalogInput {
  readonly requestBytes: Uint8Array;
}

export interface ResolvedProfileValidationInput extends ProfileResolutionInput {
  readonly resolvedProfileBytes: Uint8Array;
}

export const profileDiagnosticCodes = [
  "CONTRACT_SCHEMA_INVALID",
  "BINDING_CONTRACT_MISMATCH",
  "BINDING_ID_MISMATCH",
  "BINDING_VERSION_MISMATCH",
  "BINDING_DIGEST_MISMATCH",
  "MODULE_ID_INVALID",
  "MODULE_KEY_ID_MISMATCH",
  "MODULE_SELECTION_DUPLICATE",
  "PROPERTY_SELECTION_DANGLING",
  "CAPABILITY_SELECTION_DANGLING",
  "ATTACKER_SELECTION_DANGLING",
  "THREAT_SELECTION_DANGLING",
  "MODULE_SELF_DEPENDENCY",
  "MODULE_DEPENDENCY_DUPLICATE",
  "MODULE_DEPENDENCY_DANGLING",
  "MODULE_DEPENDENCY_CYCLE",
  "CONFLICT_SELF",
  "CONFLICT_DUPLICATE",
  "CONFLICT_NON_CANONICAL",
  "CONFLICT_MODULE_DANGLING",
  "MODULE_INTRINSIC_CONFLICT",
  "REQUEST_MODULE_DUPLICATE",
  "SAFETY_BOUNDARY_VIOLATION",
  "RESOLVED_PROFILE_INCONSISTENT",
  "DIAGNOSTIC_LIMIT_EXCEEDED",
] as const;

export type ProfileSpecificDiagnosticCode =
  (typeof profileDiagnosticCodes)[number];
export type ProfileDiagnosticCode =
  | ProfileSpecificDiagnosticCode
  | CatalogDiagnosticCode
  | StrictJsonDiagnosticCode;

const profileDiagnosticDescriptions: Readonly<
  Record<ProfileSpecificDiagnosticCode, string>
> = {
  CONTRACT_SCHEMA_INVALID:
    "A strict-decoded input does not conform to its closed Draft 2020-12 contract.",
  BINDING_CONTRACT_MISMATCH:
    "An exact input binding names a contract other than the supplied artifact contract.",
  BINDING_ID_MISMATCH:
    "An exact input binding names a catalog identifier other than the supplied artifact identifier.",
  BINDING_VERSION_MISMATCH:
    "An exact input binding names a catalog version other than the supplied artifact version.",
  BINDING_DIGEST_MISMATCH:
    "An exact input binding does not match the SHA-256 of the supplied original bytes.",
  MODULE_ID_INVALID: "A module identifier does not use module.<domain>.<name>.",
  MODULE_KEY_ID_MISMATCH:
    "A module map key differs from the contained module identifier.",
  MODULE_SELECTION_DUPLICATE:
    "A module repeats one direct catalog selection within the same entry class.",
  PROPERTY_SELECTION_DANGLING:
    "A module selects no declared property catalog entry.",
  CAPABILITY_SELECTION_DANGLING:
    "A module selects no declared attacker-capability catalog entry.",
  ATTACKER_SELECTION_DANGLING:
    "A module selects no declared attacker-model catalog entry.",
  THREAT_SELECTION_DANGLING:
    "A module selects no declared threat catalog entry.",
  MODULE_SELF_DEPENDENCY: "A module requires itself.",
  MODULE_DEPENDENCY_DUPLICATE:
    "A module repeats one required-module reference.",
  MODULE_DEPENDENCY_DANGLING:
    "A module requires an identifier absent from the module catalog.",
  MODULE_DEPENDENCY_CYCLE:
    "The directed module dependency graph contains a cycle.",
  CONFLICT_SELF: "A conflict pair names the same module twice.",
  CONFLICT_DUPLICATE:
    "A conflict pair duplicates an existing unordered pair, including reversed order.",
  CONFLICT_NON_CANONICAL:
    "A conflict pair is not in ascending code-unit module-ID order.",
  CONFLICT_MODULE_DANGLING:
    "A conflict pair names an identifier absent from the module catalog.",
  MODULE_INTRINSIC_CONFLICT:
    "One module dependency closure contains both sides of a declared conflict.",
  REQUEST_MODULE_DUPLICATE:
    "A profile request repeats one module identifier.",
  SAFETY_BOUNDARY_VIOLATION:
    "An artifact does not preserve executable=false, networkRequired=false, and secretsAllowed=false.",
  RESOLVED_PROFILE_INCONSISTENT:
    "The supplied resolved profile is not the exact deterministic resolution of the supplied inputs.",
  DIAGNOSTIC_LIMIT_EXCEEDED:
    "Validation produced more than the bounded diagnostic limit; remaining diagnostics were omitted deterministically.",
};

export interface ProfileDiagnostic {
  readonly code: ProfileDiagnosticCode;
  readonly path: string;
  readonly message: string;
}

export interface ProfileValidationSuccess {
  readonly valid: true;
  readonly diagnostics: readonly [];
}

export interface ProfileValidationFailure {
  readonly valid: false;
  readonly diagnostics: readonly ProfileDiagnostic[];
}

export type ProfileValidationResult =
  | ProfileValidationSuccess
  | ProfileValidationFailure;

export interface ProfileResolutionSuccess {
  readonly valid: true;
  readonly profile: ResolvedProfile;
  readonly bytes: Uint8Array;
  readonly diagnostics: readonly [];
}

export interface ProfileResolutionFailure {
  readonly valid: false;
  readonly diagnostics: readonly ProfileDiagnostic[];
}

export type ProfileResolutionResult =
  | ProfileResolutionSuccess
  | ProfileResolutionFailure;

const moduleIdPattern =
  /^module\.([a-z][a-z0-9-]{0,31})\.([a-z][a-z0-9-]{0,63})$/;

const compare = (left: string, right: string): number =>
  left < right ? -1 : left > right ? 1 : 0;

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  validateFormats: false,
});
const schemaValidators = {
  propertyCatalog: ajv.compile(propertyCatalogSchema as object),
  attackerCatalog: ajv.compile(attackerCatalogSchema as object),
  threatCatalog: ajv.compile(threatCatalogSchema as object),
  moduleCatalog: ajv.compile(capabilityModuleCatalogSchema as object),
  request: ajv.compile(profileRequestSchema as object),
  resolvedProfile: ajv.compile(resolvedProfileSchema as object),
} as const;

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function escapePointer(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function specificDiagnostic(
  code: ProfileSpecificDiagnosticCode,
  path: string,
): ProfileDiagnostic {
  return { code, path, message: profileDiagnosticDescriptions[code] };
}

function stableDiagnostics(
  diagnostics: readonly ProfileDiagnostic[],
): readonly ProfileDiagnostic[] {
  const unique = new Map<string, ProfileDiagnostic>();
  for (const entry of diagnostics) {
    unique.set(`${entry.code}\0${entry.path}`, entry);
  }
  let stable = [...unique.values()].sort(
    (left, right) =>
      compare(left.code, right.code) || compare(left.path, right.path),
  );
  if (stable.length > maximumProfileDiagnostics) {
    stable = [
      ...stable.slice(0, maximumProfileDiagnostics - 1),
      specificDiagnostic("DIAGNOSTIC_LIMIT_EXCEEDED", ""),
    ].sort(
      (left, right) =>
        compare(left.code, right.code) || compare(left.path, right.path),
    );
  }
  return stable;
}

function validationResult(
  diagnostics: readonly ProfileDiagnostic[],
): ProfileValidationResult {
  const stable = stableDiagnostics(diagnostics);
  return stable.length === 0
    ? { valid: true, diagnostics: [] }
    : { valid: false, diagnostics: stable };
}

function resolutionFailure(
  diagnostics: readonly ProfileDiagnostic[],
): ProfileResolutionFailure {
  return { valid: false, diagnostics: stableDiagnostics(diagnostics) };
}

function prefixedStrictDiagnostics(
  diagnostics: readonly StrictJsonDiagnostic[],
  prefix: string,
): readonly ProfileDiagnostic[] {
  return diagnostics.map((entry) => ({
    code: entry.code,
    path: prefix + entry.path,
    message: entry.message,
  }));
}

function schemaErrorPath(prefix: string, error: ErrorObject): string {
  const parameters = error.params as Record<string, unknown>;
  const named =
    typeof parameters.missingProperty === "string"
      ? parameters.missingProperty
      : typeof parameters.additionalProperty === "string"
        ? parameters.additionalProperty
        : undefined;
  return (
    prefix +
    error.instancePath +
    (named === undefined ? "" : "/" + escapePointer(named))
  );
}

function schemaDiagnostics(
  validator: ValidateFunction,
  value: object,
  prefix: string,
): readonly ProfileDiagnostic[] {
  if (validator(value)) return [];
  return (validator.errors ?? []).map((error) => ({
    code: "CONTRACT_SCHEMA_INVALID",
    path: schemaErrorPath(prefix, error),
    message: `${profileDiagnosticDescriptions.CONTRACT_SCHEMA_INVALID} Keyword: ${error.keyword}.`,
  }));
}

interface DecodedArtifact<T extends object> {
  readonly value?: T;
  readonly diagnostics: readonly ProfileDiagnostic[];
}

function decodeArtifact<T extends object>(
  bytes: Uint8Array,
  prefix: string,
): DecodedArtifact<T> {
  const decoded = decodeStrictJsonObject<T>(bytes);
  return decoded.valid
    ? { value: decoded.value, diagnostics: [] }
    : {
        diagnostics: prefixedStrictDiagnostics(decoded.diagnostics, prefix),
      };
}

function safetyValid(value: ProfileSafetyBoundary): boolean {
  return (
    value.executable === false &&
    value.networkRequired === false &&
    value.secretsAllowed === false
  );
}

function duplicateDiagnostics(
  values: readonly string[],
  code:
    | "MODULE_SELECTION_DUPLICATE"
    | "MODULE_DEPENDENCY_DUPLICATE"
    | "REQUEST_MODULE_DUPLICATE",
  path: string,
): readonly ProfileDiagnostic[] {
  const diagnostics: ProfileDiagnostic[] = [];
  const seen = new Set<string>();
  for (const [index, value] of values.entries()) {
    if (seen.has(value)) {
      diagnostics.push(specificDiagnostic(code, `${path}/${index}`));
    }
    seen.add(value);
  }
  return diagnostics;
}

function moduleCycleDiagnostics(
  adjacency: ReadonlyMap<string, readonly string[]>,
): readonly ProfileDiagnostic[] {
  const diagnostics: ProfileDiagnostic[] = [];
  const state = new Map<string, 0 | 1 | 2>();
  const stack: Array<{
    readonly id: string;
    readonly dependencies: readonly string[];
    index: number;
  }> = [];

  for (const root of [...adjacency.keys()].sort(compare)) {
    if ((state.get(root) ?? 0) !== 0) continue;
    state.set(root, 1);
    stack.push({ id: root, dependencies: adjacency.get(root) ?? [], index: 0 });
    while (stack.length > 0) {
      const current = stack.at(-1);
      if (current === undefined) break;
      const dependency = current.dependencies[current.index];
      if (dependency === undefined) {
        state.set(current.id, 2);
        stack.pop();
        continue;
      }
      current.index += 1;
      const dependencyState = state.get(dependency) ?? 0;
      if (dependencyState === 1) {
        diagnostics.push(
          specificDiagnostic(
            "MODULE_DEPENDENCY_CYCLE",
            `/moduleCatalog/modules/${escapePointer(current.id)}/requires`,
          ),
        );
      } else if (dependencyState === 0 && adjacency.has(dependency)) {
        state.set(dependency, 1);
        stack.push({
          id: dependency,
          dependencies: adjacency.get(dependency) ?? [],
          index: 0,
        });
      }
    }
  }
  return diagnostics;
}

function dependencyClosure(
  root: string,
  adjacency: ReadonlyMap<string, readonly string[]>,
): ReadonlySet<string> {
  const closure = new Set<string>();
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined || closure.has(current)) continue;
    closure.add(current);
    for (const dependency of adjacency.get(current) ?? []) {
      if (!closure.has(dependency)) pending.push(dependency);
    }
  }
  return closure;
}

function validateModuleCatalogSemantics(
  catalog: CapabilityModuleCatalog,
  propertyCatalog: PropertyCatalog,
  attackerCatalog: AttackerCatalog,
  threatCatalog: ThreatCatalog,
): readonly ProfileDiagnostic[] {
  const diagnostics: ProfileDiagnostic[] = [];
  if (!safetyValid(catalog.safety)) {
    diagnostics.push(
      specificDiagnostic("SAFETY_BOUNDARY_VIOLATION", "/moduleCatalog/safety"),
    );
  }

  const adjacency = new Map<string, readonly string[]>();
  for (const id of Object.keys(catalog.modules).sort(compare)) {
    const module = catalog.modules[id];
    if (module === undefined) continue;
    const path = `/moduleCatalog/modules/${escapePointer(id)}`;
    if (!moduleIdPattern.test(module.id)) {
      diagnostics.push(specificDiagnostic("MODULE_ID_INVALID", `${path}/id`));
    }
    if (id !== module.id) {
      diagnostics.push(specificDiagnostic("MODULE_KEY_ID_MISMATCH", path));
    }
    if (module.state !== "available") continue;

    const selections = [
      [
        "properties",
        module.selections.properties,
        propertyCatalog.properties,
        "PROPERTY_SELECTION_DANGLING",
      ],
      [
        "capabilities",
        module.selections.capabilities,
        attackerCatalog.capabilities,
        "CAPABILITY_SELECTION_DANGLING",
      ],
      [
        "attackers",
        module.selections.attackers,
        attackerCatalog.attackers,
        "ATTACKER_SELECTION_DANGLING",
      ],
      [
        "threats",
        module.selections.threats,
        threatCatalog.threats,
        "THREAT_SELECTION_DANGLING",
      ],
    ] as const;
    for (const [name, values, target, danglingCode] of selections) {
      diagnostics.push(
        ...duplicateDiagnostics(
          values,
          "MODULE_SELECTION_DUPLICATE",
          `${path}/selections/${name}`,
        ),
      );
      for (const [index, selection] of values.entries()) {
        if (!Object.hasOwn(target, selection)) {
          diagnostics.push(
            specificDiagnostic(
              danglingCode,
              `${path}/selections/${name}/${index}`,
            ),
          );
        }
      }
    }

    diagnostics.push(
      ...duplicateDiagnostics(
        module.requires,
        "MODULE_DEPENDENCY_DUPLICATE",
        `${path}/requires`,
      ),
    );
    const validDependencies: string[] = [];
    for (const [index, dependency] of module.requires.entries()) {
      if (dependency === id) {
        diagnostics.push(
          specificDiagnostic(
            "MODULE_SELF_DEPENDENCY",
            `${path}/requires/${index}`,
          ),
        );
      } else if (!Object.hasOwn(catalog.modules, dependency)) {
        diagnostics.push(
          specificDiagnostic(
            "MODULE_DEPENDENCY_DANGLING",
            `${path}/requires/${index}`,
          ),
        );
      } else {
        validDependencies.push(dependency);
      }
    }
    adjacency.set(id, validDependencies.sort(compare));
  }

  diagnostics.push(...moduleCycleDiagnostics(adjacency));

  const conflictKeys = new Set<string>();
  const validConflicts: Array<readonly [string, string]> = [];
  for (const [index, pair] of catalog.conflicts.entries()) {
    const [left, right] = pair;
    const path = `/moduleCatalog/conflicts/${index}`;
    if (left === right) {
      diagnostics.push(specificDiagnostic("CONFLICT_SELF", path));
    }
    if (compare(left, right) >= 0) {
      diagnostics.push(specificDiagnostic("CONFLICT_NON_CANONICAL", path));
    }
    const canonical = [left, right].sort(compare).join("\0");
    if (conflictKeys.has(canonical)) {
      diagnostics.push(specificDiagnostic("CONFLICT_DUPLICATE", path));
    } else {
      conflictKeys.add(canonical);
    }
    let dangling = false;
    for (const [position, moduleId] of pair.entries()) {
      if (!Object.hasOwn(catalog.modules, moduleId)) {
        dangling = true;
        diagnostics.push(
          specificDiagnostic(
            "CONFLICT_MODULE_DANGLING",
            `${path}/${position}`,
          ),
        );
      }
    }
    if (left !== right && compare(left, right) < 0 && !dangling) {
      validConflicts.push(pair);
    }
  }

  for (const moduleId of [...adjacency.keys()].sort(compare)) {
    const closure = dependencyClosure(moduleId, adjacency);
    if (
      validConflicts.some(
        ([left, right]) => closure.has(left) && closure.has(right),
      )
    ) {
      diagnostics.push(
        specificDiagnostic(
          "MODULE_INTRINSIC_CONFLICT",
          `/moduleCatalog/modules/${escapePointer(moduleId)}/requires`,
        ),
      );
    }
  }
  return diagnostics;
}

function verifyBinding(
  binding: ExactCatalogBinding,
  actual: {
    readonly schemaVersion: string;
    readonly catalogId: string;
    readonly catalogVersion: string;
  },
  bytes: Uint8Array,
  path: string,
): readonly ProfileDiagnostic[] {
  const diagnostics: ProfileDiagnostic[] = [];
  if (binding.contractId !== actual.schemaVersion) {
    diagnostics.push(
      specificDiagnostic("BINDING_CONTRACT_MISMATCH", `${path}/contractId`),
    );
  }
  if (binding.catalogId !== actual.catalogId) {
    diagnostics.push(specificDiagnostic("BINDING_ID_MISMATCH", `${path}/catalogId`));
  }
  if (binding.catalogVersion !== actual.catalogVersion) {
    diagnostics.push(
      specificDiagnostic("BINDING_VERSION_MISMATCH", `${path}/catalogVersion`),
    );
  }
  if (
    binding.digest.algorithm !== "sha256" ||
    binding.digest.value !== sha256(bytes)
  ) {
    diagnostics.push(
      specificDiagnostic("BINDING_DIGEST_MISMATCH", `${path}/digest`),
    );
  }
  return diagnostics;
}

interface DecodedCatalogInputs {
  readonly propertyCatalog: PropertyCatalog;
  readonly attackerCatalog: AttackerCatalog;
  readonly threatCatalog: ThreatCatalog;
  readonly moduleCatalog: CapabilityModuleCatalog;
}

function catalogInputDiagnostics(
  input: CapabilityModuleCatalogInput,
  decoded: DecodedCatalogInputs,
): readonly ProfileDiagnostic[] {
  const diagnostics: ProfileDiagnostic[] = [];
  const catalogValidation = validateCatalogSet(input);
  diagnostics.push(
    ...catalogValidation.diagnostics.map((entry) => ({
      code: entry.code,
      path: entry.path,
      message: entry.message,
    })),
  );
  diagnostics.push(
    ...validateModuleCatalogSemantics(
      decoded.moduleCatalog,
      decoded.propertyCatalog,
      decoded.attackerCatalog,
      decoded.threatCatalog,
    ),
  );
  diagnostics.push(
    ...verifyBinding(
      decoded.moduleCatalog.catalogBindings.propertyCatalog,
      decoded.propertyCatalog,
      input.propertyCatalogBytes,
      "/moduleCatalog/catalogBindings/propertyCatalog",
    ),
    ...verifyBinding(
      decoded.moduleCatalog.catalogBindings.attackerCatalog,
      decoded.attackerCatalog,
      input.attackerCatalogBytes,
      "/moduleCatalog/catalogBindings/attackerCatalog",
    ),
    ...verifyBinding(
      decoded.moduleCatalog.catalogBindings.threatCatalog,
      decoded.threatCatalog,
      input.threatCatalogBytes,
      "/moduleCatalog/catalogBindings/threatCatalog",
    ),
  );
  return diagnostics;
}

export function validateCapabilityModuleCatalog(
  input: CapabilityModuleCatalogInput,
): ProfileValidationResult {
  const property = decodeArtifact<PropertyCatalog>(
    input.propertyCatalogBytes,
    "/propertyCatalog",
  );
  const attacker = decodeArtifact<AttackerCatalog>(
    input.attackerCatalogBytes,
    "/attackerCatalog",
  );
  const threat = decodeArtifact<ThreatCatalog>(
    input.threatCatalogBytes,
    "/threatCatalog",
  );
  const modules = decodeArtifact<CapabilityModuleCatalog>(
    input.moduleCatalogBytes,
    "/moduleCatalog",
  );
  const decodeDiagnostics = [
    ...property.diagnostics,
    ...attacker.diagnostics,
    ...threat.diagnostics,
    ...modules.diagnostics,
  ];
  if (
    property.value === undefined ||
    attacker.value === undefined ||
    threat.value === undefined ||
    modules.value === undefined
  ) {
    return validationResult(decodeDiagnostics);
  }

  const schemaErrors = [
    ...schemaDiagnostics(
      schemaValidators.propertyCatalog,
      property.value,
      "/propertyCatalog",
    ),
    ...schemaDiagnostics(
      schemaValidators.attackerCatalog,
      attacker.value,
      "/attackerCatalog",
    ),
    ...schemaDiagnostics(
      schemaValidators.threatCatalog,
      threat.value,
      "/threatCatalog",
    ),
    ...schemaDiagnostics(
      schemaValidators.moduleCatalog,
      modules.value,
      "/moduleCatalog",
    ),
  ];
  if (schemaErrors.length > 0) return validationResult(schemaErrors);

  return validationResult(
    catalogInputDiagnostics(input, {
      propertyCatalog: property.value,
      attackerCatalog: attacker.value,
      threatCatalog: threat.value,
      moduleCatalog: modules.value,
    }),
  );
}

interface SelectionAccumulator {
  readonly id: string;
  readonly sources: Map<string, Set<InclusionReason>>;
}

function addSelection(
  map: Map<string, SelectionAccumulator>,
  id: string,
  sourceModuleId: string,
  reason: InclusionReason,
): boolean {
  let entry = map.get(id);
  if (entry === undefined) {
    entry = { id, sources: new Map() };
    map.set(id, entry);
  }
  let reasons = entry.sources.get(sourceModuleId);
  const newSource = reasons === undefined;
  if (reasons === undefined) {
    reasons = new Set();
    entry.sources.set(sourceModuleId, reasons);
  }
  reasons.add(reason);
  return newSource;
}

function selectionRecord(
  accumulator: SelectionAccumulator,
): ResolvedSelection {
  return {
    id: accumulator.id,
    sources: [...accumulator.sources.entries()]
      .sort(([left], [right]) => compare(left, right))
      .map(([sourceModuleId, reasons]) => ({
        sourceModuleId,
        inclusionReasons: [...reasons].sort(compare),
      })),
  };
}

function selectionMap(
  accumulators: ReadonlyMap<string, SelectionAccumulator>,
): Readonly<Record<string, ResolvedSelection>> {
  return Object.fromEntries(
    [...accumulators.entries()]
      .sort(([left], [right]) => compare(left, right))
      .map(([id, accumulator]) => [id, selectionRecord(accumulator)]),
  );
}

function binding(
  contractId: string,
  catalogId: string,
  catalogVersion: string,
  bytes: Uint8Array,
): ExactCatalogBinding {
  return {
    contractId,
    catalogId,
    catalogVersion,
    digest: { algorithm: "sha256", value: sha256(bytes) },
  };
}

function buildResolvedProfile(
  input: ProfileResolutionInput,
  catalogs: DecodedCatalogInputs,
  request: ProfileRequest,
): ResolvedProfile {
  const requestedModules = [...request.requestedModules].sort(compare);
  const requestedSet = new Set(requestedModules);
  const closure = new Set<string>();
  const requiredBy = new Map<string, Set<string>>();
  const pending = [...requestedModules].reverse();
  while (pending.length > 0) {
    const moduleId = pending.pop();
    if (moduleId === undefined || closure.has(moduleId)) continue;
    closure.add(moduleId);
    const module = catalogs.moduleCatalog.modules[moduleId];
    if (module?.state !== "available") continue;
    for (const dependency of [...module.requires].sort(compare)) {
      let parents = requiredBy.get(dependency);
      if (parents === undefined) {
        parents = new Set();
        requiredBy.set(dependency, parents);
      }
      parents.add(moduleId);
      if (!closure.has(dependency)) pending.push(dependency);
    }
  }

  const states = new Map<string, ModuleResolutionState>();
  const conflictsWith = new Map<string, Set<string>>();
  for (const moduleId of closure) {
    const module = catalogs.moduleCatalog.modules[moduleId];
    states.set(
      moduleId,
      module === undefined
        ? "unknown"
        : module.state === "unsupported"
          ? "unsupported"
          : "resolved",
    );
  }
  for (const [left, right] of catalogs.moduleCatalog.conflicts) {
    if (!closure.has(left) || !closure.has(right)) continue;
    for (const [moduleId, other] of [
      [left, right],
      [right, left],
    ] as const) {
      const module = catalogs.moduleCatalog.modules[moduleId];
      if (module === undefined) continue;
      states.set(moduleId, "unresolvable");
      let conflicts = conflictsWith.get(moduleId);
      if (conflicts === undefined) {
        conflicts = new Set();
        conflictsWith.set(moduleId, conflicts);
      }
      conflicts.add(other);
    }
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const moduleId of [...closure].sort(compare)) {
      const module = catalogs.moduleCatalog.modules[moduleId];
      if (module?.state !== "available" || states.get(moduleId) !== "resolved") {
        continue;
      }
      if (module.requires.some((dependency) => states.get(dependency) !== "resolved")) {
        states.set(moduleId, "unresolvable");
        changed = true;
      }
    }
  }

  const outcomes: Record<string, ModuleOutcome> = {};
  for (const moduleId of [...closure].sort(compare)) {
    const module = catalogs.moduleCatalog.modules[moduleId];
    const state = states.get(moduleId);
    const requested = requestedSet.has(moduleId);
    const parents = [...(requiredBy.get(moduleId) ?? [])].sort(compare);
    if (module === undefined || state === "unknown") {
      outcomes[moduleId] = {
        id: moduleId,
        state: "unknown",
        requested,
        requiredBy: parents,
      };
    } else if (module.state === "unsupported" && state === "unsupported") {
      outcomes[moduleId] = {
        id: moduleId,
        state: "unsupported",
        requested,
        requiredBy: parents,
        reason: module.reason,
        scope: module.scope,
      };
    } else if (state === "unresolvable") {
      outcomes[moduleId] = {
        id: moduleId,
        state: "unresolvable",
        requested,
        requiredBy: parents,
        conflictsWith: [...(conflictsWith.get(moduleId) ?? [])].sort(compare),
        unresolvedDependencies:
          module.state === "available"
            ? module.requires
                .filter((dependency) => states.get(dependency) !== "resolved")
                .sort(compare)
            : [],
      };
    } else {
      outcomes[moduleId] = {
        id: moduleId,
        state: "resolved",
        requested,
        requiredBy: parents,
      };
    }
  }

  const properties = new Map<string, SelectionAccumulator>();
  const capabilities = new Map<string, SelectionAccumulator>();
  const attackers = new Map<string, SelectionAccumulator>();
  const threats = new Map<string, SelectionAccumulator>();
  for (const [moduleId, outcome] of Object.entries(outcomes)) {
    if (outcome.state !== "resolved") continue;
    const module = catalogs.moduleCatalog.modules[moduleId];
    if (module?.state !== "available") continue;
    for (const id of module.selections.properties) {
      addSelection(properties, id, moduleId, "module-selection");
    }
    for (const id of module.selections.capabilities) {
      addSelection(capabilities, id, moduleId, "module-selection");
    }
    for (const id of module.selections.attackers) {
      addSelection(attackers, id, moduleId, "module-selection");
      for (const capability of catalogs.attackerCatalog.attackers[id]?.capabilities ?? []) {
        addSelection(capabilities, capability, moduleId, "attacker-capability");
      }
    }
    for (const id of module.selections.threats) {
      addSelection(threats, id, moduleId, "module-selection");
      const threat = catalogs.threatCatalog.threats[id];
      if (threat === undefined) continue;
      for (const capability of threat.capabilities) {
        addSelection(capabilities, capability, moduleId, "threat-capability");
      }
      for (const property of threat.affectedProperties) {
        addSelection(properties, property, moduleId, "threat-affected-property");
      }
    }
  }

  const propertyPending = [...properties.values()].flatMap((entry) =>
    [...entry.sources.keys()].map((sourceModuleId) => ({
      propertyId: entry.id,
      sourceModuleId,
    })),
  );
  while (propertyPending.length > 0) {
    const current = propertyPending.pop();
    if (current === undefined) break;
    for (
      const dependency of
        catalogs.propertyCatalog.properties[current.propertyId]?.dependsOn ?? []
    ) {
      const newSource = addSelection(
        properties,
        dependency,
        current.sourceModuleId,
        "property-dependency",
      );
      if (newSource) {
        propertyPending.push({
          propertyId: dependency,
          sourceModuleId: current.sourceModuleId,
        });
      }
    }
  }

  const assumptions: SourceStatement[] = [];
  const exclusions: SourceStatement[] = [];
  for (const moduleId of [...closure].sort(compare)) {
    const module = catalogs.moduleCatalog.modules[moduleId];
    if (module === undefined) continue;
    assumptions.push(
      ...module.assumptions.map((statement) => ({
        sourceModuleId: moduleId,
        statement,
      })),
    );
    exclusions.push(
      ...module.exclusions.map((statement) => ({
        sourceModuleId: moduleId,
        statement,
      })),
    );
  }
  const compareStatement = (left: SourceStatement, right: SourceStatement): number =>
    compare(left.sourceModuleId, right.sourceModuleId) ||
    compare(left.statement, right.statement);

  return {
    schemaVersion: "cryptocomm-resolved-profile/v1",
    profileId: request.profileId,
    state: Object.values(outcomes).every((outcome) => outcome.state === "resolved")
      ? "complete"
      : "incomplete",
    inputBindings: {
      moduleCatalog: binding(
        catalogs.moduleCatalog.schemaVersion,
        catalogs.moduleCatalog.catalogId,
        catalogs.moduleCatalog.catalogVersion,
        input.moduleCatalogBytes,
      ),
      propertyCatalog: binding(
        catalogs.propertyCatalog.schemaVersion,
        catalogs.propertyCatalog.catalogId,
        catalogs.propertyCatalog.catalogVersion,
        input.propertyCatalogBytes,
      ),
      attackerCatalog: binding(
        catalogs.attackerCatalog.schemaVersion,
        catalogs.attackerCatalog.catalogId,
        catalogs.attackerCatalog.catalogVersion,
        input.attackerCatalogBytes,
      ),
      threatCatalog: binding(
        catalogs.threatCatalog.schemaVersion,
        catalogs.threatCatalog.catalogId,
        catalogs.threatCatalog.catalogVersion,
        input.threatCatalogBytes,
      ),
    },
    requestedModules,
    modules: outcomes,
    selections: {
      properties: selectionMap(properties),
      capabilities: selectionMap(capabilities),
      attackers: selectionMap(attackers),
      threats: selectionMap(threats),
    },
    assumptions: assumptions.sort(compareStatement),
    exclusions: exclusions.sort(compareStatement),
    ...(request.fixtureClassification === undefined
      ? {}
      : { fixtureClassification: request.fixtureClassification }),
    safety: {
      executable: false,
      networkRequired: false,
      secretsAllowed: false,
    },
  };
}

export function serializeResolvedProfile(profile: ResolvedProfile): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(profile, undefined, 2)}\n`);
}

export function resolveProfile(
  input: ProfileResolutionInput,
): ProfileResolutionResult {
  const property = decodeArtifact<PropertyCatalog>(
    input.propertyCatalogBytes,
    "/propertyCatalog",
  );
  const attacker = decodeArtifact<AttackerCatalog>(
    input.attackerCatalogBytes,
    "/attackerCatalog",
  );
  const threat = decodeArtifact<ThreatCatalog>(
    input.threatCatalogBytes,
    "/threatCatalog",
  );
  const modules = decodeArtifact<CapabilityModuleCatalog>(
    input.moduleCatalogBytes,
    "/moduleCatalog",
  );
  const request = decodeArtifact<ProfileRequest>(input.requestBytes, "/request");
  const decodeDiagnostics = [
    ...property.diagnostics,
    ...attacker.diagnostics,
    ...threat.diagnostics,
    ...modules.diagnostics,
    ...request.diagnostics,
  ];
  if (
    property.value === undefined ||
    attacker.value === undefined ||
    threat.value === undefined ||
    modules.value === undefined ||
    request.value === undefined
  ) {
    return resolutionFailure(decodeDiagnostics);
  }

  const schemaErrors = [
    ...schemaDiagnostics(
      schemaValidators.propertyCatalog,
      property.value,
      "/propertyCatalog",
    ),
    ...schemaDiagnostics(
      schemaValidators.attackerCatalog,
      attacker.value,
      "/attackerCatalog",
    ),
    ...schemaDiagnostics(
      schemaValidators.threatCatalog,
      threat.value,
      "/threatCatalog",
    ),
    ...schemaDiagnostics(
      schemaValidators.moduleCatalog,
      modules.value,
      "/moduleCatalog",
    ),
    ...schemaDiagnostics(schemaValidators.request, request.value, "/request"),
  ];
  if (schemaErrors.length > 0) return resolutionFailure(schemaErrors);

  const catalogs: DecodedCatalogInputs = {
    propertyCatalog: property.value,
    attackerCatalog: attacker.value,
    threatCatalog: threat.value,
    moduleCatalog: modules.value,
  };
  const semanticDiagnostics = [
    ...catalogInputDiagnostics(input, catalogs),
    ...duplicateDiagnostics(
      request.value.requestedModules,
      "REQUEST_MODULE_DUPLICATE",
      "/request/requestedModules",
    ),
    ...(safetyValid(request.value.safety)
      ? []
      : [specificDiagnostic("SAFETY_BOUNDARY_VIOLATION", "/request/safety")]),
    ...verifyBinding(
      request.value.moduleCatalog,
      modules.value,
      input.moduleCatalogBytes,
      "/request/moduleCatalog",
    ),
  ];
  if (semanticDiagnostics.length > 0) {
    return resolutionFailure(semanticDiagnostics);
  }

  const profile = buildResolvedProfile(input, catalogs, request.value);
  const bytes = serializeResolvedProfile(profile);
  const generatedSchemaErrors = schemaDiagnostics(
    schemaValidators.resolvedProfile,
    profile,
    "/resolvedProfile",
  );
  if (generatedSchemaErrors.length > 0) {
    return resolutionFailure(generatedSchemaErrors);
  }
  return { valid: true, profile, bytes, diagnostics: [] };
}

export function validateResolvedProfile(
  input: ResolvedProfileValidationInput,
): ProfileValidationResult {
  const candidate = decodeArtifact<ResolvedProfile>(
    input.resolvedProfileBytes,
    "/resolvedProfile",
  );
  if (candidate.value === undefined) {
    return validationResult(candidate.diagnostics);
  }
  const candidateSchemaErrors = schemaDiagnostics(
    schemaValidators.resolvedProfile,
    candidate.value,
    "/resolvedProfile",
  );
  if (candidateSchemaErrors.length > 0) {
    return validationResult(candidateSchemaErrors);
  }

  const expected = resolveProfile(input);
  if (!expected.valid) return validationResult(expected.diagnostics);
  if (
    Buffer.compare(
      Buffer.from(input.resolvedProfileBytes),
      Buffer.from(expected.bytes),
    ) !== 0
  ) {
    return validationResult([
      specificDiagnostic("RESOLVED_PROFILE_INCONSISTENT", "/resolvedProfile"),
    ]);
  }
  return { valid: true, diagnostics: [] };
}
