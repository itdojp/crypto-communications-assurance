import { createHash } from "node:crypto";

import assuranceProfileSchema from "../../../integrations/ae-framework/pins/c5da6115638fdbfeebbc458b39fa6916db66afb0/schema/assurance-profile.schema.json" with { type: "json" };
import contextPackSchema from "../../../integrations/ae-framework/pins/c5da6115638fdbfeebbc458b39fa6916db66afb0/schema/context-pack-v1.schema.json" with { type: "json" };
import securityAuditScopeSchema from "../../../integrations/ae-framework/pins/c5da6115638fdbfeebbc458b39fa6916db66afb0/schema/security-audit-scope-v1.schema.json" with { type: "json" };
import securityClaimSchema from "../../../integrations/ae-framework/pins/c5da6115638fdbfeebbc458b39fa6916db66afb0/schema/security-claim-v1.schema.json" with { type: "json" };
import securityThreatModelSchema from "../../../integrations/ae-framework/pins/c5da6115638fdbfeebbc458b39fa6916db66afb0/schema/security-threat-model-v1.schema.json" with { type: "json" };
import attackerCatalogSchema from "../../../schema/cryptocomm-attacker-catalog-v1.schema.json" with { type: "json" };
import capabilityModuleCatalogSchema from "../../../schema/cryptocomm-capability-module-catalog-v1.schema.json" with { type: "json" };
import renderPlanSchema from "../../../schema/cryptocomm-ae-render-plan-v1.schema.json" with { type: "json" };
import propertyCatalogSchema from "../../../schema/cryptocomm-property-catalog-v1.schema.json" with { type: "json" };
import resolvedProfileSchema from "../../../schema/cryptocomm-resolved-profile-v1.schema.json" with { type: "json" };
import threatCatalogSchema from "../../../schema/cryptocomm-threat-catalog-v1.schema.json" with { type: "json" };

import {
  validateCapabilityModuleCatalog,
  validateResolvedProfile,
  type CapabilityModuleCatalog,
  type ProfileRequest,
  type ResolvedProfile,
} from "./profiles.js";
import {
  type AttackerCatalog,
  type PropertyCatalog,
  type PropertyEvidenceKind,
  type ThreatCatalog,
} from "./catalogs.js";
import {
  compileContractBytes,
  type ContractBytesValidationResult,
} from "./validation.js";
import { decodeStrictJsonObject } from "./strict-json.js";

export const aeNativeArtifactKinds = [
  "assurance-profile/v1",
  "security-claim/v1",
  "security-threat-model/v1",
  "security-audit-scope/v1",
] as const;
export type AeNativeArtifactKind = (typeof aeNativeArtifactKinds)[number];

export const aeUpstreamSchemaRoles = [
  "assuranceProfile",
  "securityClaim",
  "securityThreatModel",
  "securityAuditScope",
  "contextPack",
] as const;
export type AeUpstreamSchemaRole = (typeof aeUpstreamSchemaRoles)[number];

export const aeCcaInputRoles = [
  "propertyCatalog",
  "attackerCatalog",
  "threatCatalog",
  "capabilityModuleCatalog",
  "resolvedProfile",
] as const;
export type AeCcaInputRole = (typeof aeCcaInputRoles)[number];

export const maximumAeRenderDiagnostics = 256;

export interface AeRenderDiagnostic {
  readonly code: string;
  readonly path: string;
  readonly message: string;
  readonly severity: "error" | "information";
}

interface ExactBinding {
  readonly contractId: string;
  readonly path: string;
  readonly sha256: string;
  readonly byteLength: number;
}

interface SchemaBinding {
  readonly path: string;
  readonly blobSha: string;
  readonly sha256: string;
  readonly byteLength: number;
}

type MappingDisposition = "render" | "unsupported" | "excluded-by-operator";

interface ContextPackBinding extends ExactBinding {
  readonly id: string;
  readonly contractId: "context-pack/v1";
  readonly validateWithPinnedSchema: true;
}

interface OutputSelection {
  readonly artifactKind: AeNativeArtifactKind;
  readonly disposition: MappingDisposition;
  readonly outputPath?: string;
  readonly reason?: string;
}

interface SourceRef {
  readonly kind:
    | "spec"
    | "design"
    | "bug-bounty-scope"
    | "issue"
    | "security-policy"
    | "other";
  readonly uri: string;
  readonly section: string;
  readonly description?: string;
}

interface ScopeRefs {
  readonly objectIds?: readonly string[];
  readonly morphismIds?: readonly string[];
  readonly diagramIds?: readonly string[];
  readonly acceptanceTestIds?: readonly string[];
}

interface EvidenceMapping {
  readonly decisionId: string;
  readonly sourceEvidenceKind: PropertyEvidenceKind;
  readonly disposition: MappingDisposition;
  readonly rendered?: {
    readonly projection: "direct" | "lossy";
    readonly requiredLanes: readonly string[];
    readonly requiredEvidenceKinds: readonly string[];
    readonly lossExplanation?: string;
  };
  readonly reason?: string;
}

interface ClaimMapping {
  readonly propertyId: string;
  readonly disposition: MappingDisposition;
  readonly reason?: string;
  readonly claim?: {
    readonly claimId: string;
    readonly statement: string;
    readonly type: "invariant" | "precondition" | "postcondition" | "assumption";
    readonly kind: string;
    readonly criticality: string;
    readonly targetLevel: string;
    readonly minIndependentSources?: number;
    readonly requiredLanes: readonly string[];
    readonly requiredEvidenceKinds: readonly string[];
    readonly evidenceMappings: readonly EvidenceMapping[];
    readonly sourceRefs: readonly SourceRef[];
    readonly threatTags: {
      readonly stride: readonly string[];
      readonly cwe: readonly string[];
    };
    readonly trustBoundary: {
      readonly boundaryIds: readonly string[];
      readonly entryPoints: readonly string[];
      readonly attackerControlled: boolean;
      readonly dataClasses?: readonly string[];
      readonly notes?: readonly string[];
    };
    readonly scopeRefs?: ScopeRefs;
    readonly provenance: {
      readonly origin: "generated";
      readonly generator: string;
      readonly source: string;
      readonly version: string;
    };
    readonly notes?: readonly string[];
  };
}

interface ThreatMapping {
  readonly threatId: string;
  readonly disposition: MappingDisposition;
  readonly reason?: string;
  readonly threat?: {
    readonly threatId: string;
    readonly description: string;
    readonly stride: string;
    readonly cwe: string;
    readonly relatedClaimIds: readonly string[];
    readonly trustBoundaryIds?: readonly string[];
    readonly notes?: readonly string[];
  };
}

interface TargetIdentity {
  readonly repository: string;
  readonly commit: string;
  readonly tree: string;
}

interface TrustBoundary {
  readonly id: string;
  readonly name: string;
  readonly entryPoints: readonly string[];
  readonly attackerControlled: boolean;
  readonly description?: string;
  readonly dataClasses?: readonly string[];
  readonly scopeRefs?: readonly string[];
}

interface ScopeMapping {
  readonly disposition: MappingDisposition;
  readonly reason?: string;
  readonly scope?: {
    readonly profileId: string;
    readonly contextPackIds: readonly string[];
    readonly componentGlobs: readonly string[];
    readonly target: TargetIdentity;
    readonly inScope: readonly string[];
    readonly outOfScope: readonly string[];
    readonly trustBoundaries: readonly TrustBoundary[];
    readonly treeProjection: {
      readonly disposition: "lossy";
      readonly sourceField: "target.tree";
      readonly nativeArtifact: "security-audit-scope/v1";
      readonly omittedField: "target.tree";
      readonly reason: string;
    };
  };
}

interface AeRenderPlan {
  readonly schemaVersion: "cryptocomm-ae-render-plan/v1";
  readonly planId: string;
  readonly ccaRevision: TargetIdentity;
  readonly ccaInputs: Readonly<Record<AeCcaInputRole, ExactBinding>>;
  readonly target: TargetIdentity;
  readonly contextPacks: readonly ContextPackBinding[];
  readonly upstream: {
    readonly repository: "itdojp/ae-framework";
    readonly commit: "c5da6115638fdbfeebbc458b39fa6916db66afb0";
    readonly tree: "0d69865b37a4476a20f0f1f1f42031967d3ec3a7";
    readonly schemas: Readonly<Record<AeUpstreamSchemaRole, SchemaBinding>>;
  };
  readonly renderer: {
    readonly implementationId: "cca-ae-renderer/v1";
    readonly packageName: "@itdojp/cryptocomm-contracts";
    readonly packageVersion: string;
    readonly sourcePath: "packages/contracts/src/ae-renderer.ts";
    readonly sourceSha256: string;
  };
  readonly outputs: readonly OutputSelection[];
  readonly claimMappings: readonly ClaimMapping[];
  readonly threatMappings: readonly ThreatMapping[];
  readonly scopeMapping: ScopeMapping;
  readonly fixtureClassification?: "synthetic-test-only";
}

export interface AeRenderPlanValidationInput {
  readonly planBytes: Uint8Array;
  readonly ccaInputBytes: Readonly<Record<AeCcaInputRole, Uint8Array>>;
  readonly contextPackBytes: ReadonlyMap<string, Uint8Array>;
  readonly upstreamSchemaBytes: Readonly<Record<AeUpstreamSchemaRole, Uint8Array>>;
  readonly rendererSourceBytes: Uint8Array;
}

export interface ValidatedAeRenderPlan {
  readonly planId: string;
}

export interface AeRenderPlanValidationSuccess {
  readonly valid: true;
  readonly validatedPlan: ValidatedAeRenderPlan;
  readonly diagnostics: readonly [];
}

export interface AeRenderPlanValidationFailure {
  readonly valid: false;
  readonly diagnostics: readonly AeRenderDiagnostic[];
}

export type AeRenderPlanValidationResult =
  | AeRenderPlanValidationSuccess
  | AeRenderPlanValidationFailure;

export interface RenderedAeArtifact {
  readonly artifactKind: AeNativeArtifactKind;
  readonly path: string;
  readonly bytes: Uint8Array;
}

export interface AeNativeRenderResult {
  readonly valid: boolean;
  readonly outputs: readonly RenderedAeArtifact[];
  readonly diagnostics: readonly AeRenderDiagnostic[];
}

type NativeValidator = (bytes: Uint8Array) => ContractBytesValidationResult;
interface ValidatedState {
  readonly plan: AeRenderPlan;
  readonly nativeValidators: Readonly<Record<AeNativeArtifactKind, NativeValidator>>;
}

const validatedStates = new WeakMap<ValidatedAeRenderPlan, ValidatedState>();
const planValidator = compileContractBytes(renderPlanSchema);
const ccaSchemaByRole: Readonly<Record<AeCcaInputRole, object>> = {
  propertyCatalog: propertyCatalogSchema,
  attackerCatalog: attackerCatalogSchema,
  threatCatalog: threatCatalogSchema,
  capabilityModuleCatalog: capabilityModuleCatalogSchema,
  resolvedProfile: resolvedProfileSchema,
};
const ccaValidatorByRole: Readonly<Record<AeCcaInputRole, NativeValidator>> = {
  propertyCatalog: compileContractBytes(ccaSchemaByRole.propertyCatalog),
  attackerCatalog: compileContractBytes(ccaSchemaByRole.attackerCatalog),
  threatCatalog: compileContractBytes(ccaSchemaByRole.threatCatalog),
  capabilityModuleCatalog: compileContractBytes(
    ccaSchemaByRole.capabilityModuleCatalog,
  ),
  resolvedProfile: compileContractBytes(ccaSchemaByRole.resolvedProfile),
};
const upstreamSnapshotByRole: Readonly<Record<AeUpstreamSchemaRole, object>> = {
  assuranceProfile: assuranceProfileSchema,
  securityClaim: securityClaimSchema,
  securityThreatModel: securityThreatModelSchema,
  securityAuditScope: securityAuditScopeSchema,
  contextPack: contextPackSchema,
};
const nativeRoleByKind: Readonly<
  Record<AeNativeArtifactKind, Exclude<AeUpstreamSchemaRole, "contextPack">>
> = {
  "assurance-profile/v1": "assuranceProfile",
  "security-claim/v1": "securityClaim",
  "security-threat-model/v1": "securityThreatModel",
  "security-audit-scope/v1": "securityAuditScope",
};

const compare = (left: string, right: string): number => {
  const leftCodePoints = left[Symbol.iterator]();
  const rightCodePoints = right[Symbol.iterator]();
  while (true) {
    const leftNext = leftCodePoints.next();
    const rightNext = rightCodePoints.next();
    if (leftNext.done || rightNext.done) {
      return leftNext.done === rightNext.done ? 0 : leftNext.done ? -1 : 1;
    }
    if (leftNext.value === rightNext.value) continue;
    return (leftNext.value.codePointAt(0) ?? 0) - (rightNext.value.codePointAt(0) ?? 0);
  }
};

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function diagnostic(
  code: string,
  path: string,
  message: string,
  severity: "error" | "information" = "error",
): AeRenderDiagnostic {
  return { code, path, message: message.slice(0, 512), severity };
}

export function normalizeAeRenderDiagnostics(
  diagnostics: readonly AeRenderDiagnostic[],
  overflowSeverity: "error" | "information" = "error",
): readonly AeRenderDiagnostic[] {
  const unique = new Map<string, AeRenderDiagnostic>();
  for (const entry of diagnostics) {
    const key = `${entry.code}\0${entry.path}\0${entry.message}`;
    const existing = unique.get(key);
    if (
      existing === undefined ||
      (existing.severity === "information" && entry.severity === "error")
    ) {
      unique.set(key, entry);
    }
  }
  const sorted = [...unique.values()].sort(
    (left, right) =>
      compare(left.code, right.code) ||
      compare(left.path, right.path) ||
      compare(left.message, right.message),
  );
  if (sorted.length <= maximumAeRenderDiagnostics) return sorted;
  return [
    diagnostic(
      "DIAGNOSTIC_LIMIT_EXCEEDED",
      "",
      `More than ${maximumAeRenderDiagnostics} diagnostics were produced; details were suppressed.`,
      overflowSeverity,
    ),
  ];
}

function schemaDiagnostics(
  result: ContractBytesValidationResult,
  path: string,
  code = "CONTRACT_SCHEMA_INVALID",
): readonly AeRenderDiagnostic[] {
  if (result.valid) return [];
  if (result.stage === "decode") {
    return result.errors.map((entry) =>
      diagnostic(entry.code, `${path}${entry.path}`, entry.message),
    );
  }
  return result.errors.map((entry) =>
    diagnostic(
      code,
      `${path}${entry.instancePath}`,
      `${entry.keyword}: ${entry.message ?? "schema validation failed"}`,
    ),
  );
}

function equalSet(left: readonly string[], right: readonly string[]): boolean {
  const leftSorted = sorted(left);
  const rightSorted = sorted(right);
  return (
    leftSorted.length === rightSorted.length &&
    leftSorted.every((value, index) => value === rightSorted[index])
  );
}

function sorted(values: readonly string[]): string[] {
  return [...values].sort(compare);
}

function duplicateDiagnostics(
  values: readonly string[],
  code: string,
  path: string,
): readonly AeRenderDiagnostic[] {
  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) duplicates.add(value);
    seen.add(value);
  }
  return [...duplicates]
    .sort(compare)
    .map((value) => diagnostic(code, path, `Duplicate value: ${value}.`));
}

function bindingDiagnostics(
  binding: { readonly sha256: string; readonly byteLength: number },
  bytes: Uint8Array,
  path: string,
  prefix: "CCA" | "CONTEXT_PACK" | "UPSTREAM_SCHEMA",
): readonly AeRenderDiagnostic[] {
  const diagnostics: AeRenderDiagnostic[] = [];
  if (binding.byteLength !== bytes.byteLength) {
    diagnostics.push(
      diagnostic(
        `${prefix}_BINDING_LENGTH_MISMATCH`,
        `${path}/byteLength`,
        `Expected ${binding.byteLength} exact bytes but received ${bytes.byteLength}.`,
      ),
    );
  }
  if (binding.sha256 !== sha256(bytes)) {
    diagnostics.push(
      diagnostic(
        `${prefix}_BINDING_DIGEST_MISMATCH`,
        `${path}/sha256`,
        "The declared SHA-256 does not bind the supplied exact bytes.",
      ),
    );
  }
  return diagnostics;
}

function isBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

function recordAt(value: unknown, keys: readonly string[]): unknown {
  let current = value;
  for (const key of keys) {
    if (current === null || typeof current !== "object" || Array.isArray(current)) {
      return undefined;
    }
    const record = current as Record<string, unknown>;
    if (!Object.hasOwn(record, key)) return undefined;
    current = record[key];
  }
  return current;
}

function enumAt(schema: object, keys: readonly string[]): ReadonlySet<string> {
  const value = recordAt(schema, keys);
  return new Set(
    Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [],
  );
}

function pointerSegment(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function targetEqual(left: TargetIdentity, right: TargetIdentity): boolean {
  return (
    left.repository === right.repository &&
    left.commit === right.commit &&
    left.tree === right.tree
  );
}

function decodedCcaInputDiagnostics(
  input: AeRenderPlanValidationInput,
  plan: AeRenderPlan,
): {
  readonly diagnostics: readonly AeRenderDiagnostic[];
  readonly decoded: Partial<{
    propertyCatalog: PropertyCatalog;
    attackerCatalog: AttackerCatalog;
    threatCatalog: ThreatCatalog;
    capabilityModuleCatalog: CapabilityModuleCatalog;
    resolvedProfile: ResolvedProfile;
  }>;
} {
  const diagnostics: AeRenderDiagnostic[] = [];
  const decoded: Record<string, object> = {};
  for (const role of Object.keys(input.ccaInputBytes).sort(compare)) {
    if (!(aeCcaInputRoles as readonly string[]).includes(role)) {
      diagnostics.push(
        diagnostic(
          "CCA_INPUT_ROLE_UNKNOWN",
          `/ccaInputs/${role}`,
          "Supplied CCA input bytes use a role outside the closed v1 input set.",
        ),
      );
    }
  }
  for (const role of aeCcaInputRoles) {
    const bytes: unknown = input.ccaInputBytes[role];
    const path = `/ccaInputs/${role}`;
    if (!isBytes(bytes)) {
      diagnostics.push(
        diagnostic("CCA_INPUT_MISSING", path, `No exact bytes were supplied for ${role}.`),
      );
      continue;
    }
    diagnostics.push(...bindingDiagnostics(plan.ccaInputs[role], bytes, path, "CCA"));
    const validation = ccaValidatorByRole[role](bytes);
    diagnostics.push(...schemaDiagnostics(validation, path, "CCA_INPUT_SCHEMA_INVALID"));
    if (validation.valid) decoded[role] = validation.value;
  }

  if (
    isBytes(input.ccaInputBytes.propertyCatalog) &&
    isBytes(input.ccaInputBytes.attackerCatalog) &&
    isBytes(input.ccaInputBytes.threatCatalog) &&
    isBytes(input.ccaInputBytes.capabilityModuleCatalog)
  ) {
    const validation = validateCapabilityModuleCatalog({
      propertyCatalogBytes: input.ccaInputBytes.propertyCatalog,
      attackerCatalogBytes: input.ccaInputBytes.attackerCatalog,
      threatCatalogBytes: input.ccaInputBytes.threatCatalog,
      moduleCatalogBytes: input.ccaInputBytes.capabilityModuleCatalog,
    });
    if (!validation.valid) {
      diagnostics.push(
        ...validation.diagnostics.map((entry) =>
          diagnostic(
            "CCA_INPUT_SEMANTIC_INVALID",
            `/ccaInputs${entry.path}`,
            `${entry.code}: ${entry.message}`,
          ),
        ),
      );
    }
  }

  const profile = decoded.resolvedProfile as ResolvedProfile | undefined;
  if (
    profile !== undefined &&
    isBytes(input.ccaInputBytes.propertyCatalog) &&
    isBytes(input.ccaInputBytes.attackerCatalog) &&
    isBytes(input.ccaInputBytes.threatCatalog) &&
    isBytes(input.ccaInputBytes.capabilityModuleCatalog) &&
    isBytes(input.ccaInputBytes.resolvedProfile)
  ) {
    const embeddedRequest: ProfileRequest = {
      schemaVersion: "cryptocomm-profile-request/v1",
      profileId: profile.profileId,
      moduleCatalog: profile.inputBindings.moduleCatalog,
      requestedModules: profile.requestedModules,
      safety: profile.safety,
      ...(profile.fixtureClassification === undefined
        ? {}
        : { fixtureClassification: profile.fixtureClassification }),
    };
    const validation = validateResolvedProfile({
      propertyCatalogBytes: input.ccaInputBytes.propertyCatalog,
      attackerCatalogBytes: input.ccaInputBytes.attackerCatalog,
      threatCatalogBytes: input.ccaInputBytes.threatCatalog,
      moduleCatalogBytes: input.ccaInputBytes.capabilityModuleCatalog,
      requestBytes: serialize(embeddedRequest),
      resolvedProfileBytes: input.ccaInputBytes.resolvedProfile,
    });
    if (!validation.valid) {
      diagnostics.push(
        ...validation.diagnostics.map((entry) =>
          diagnostic(
            "CCA_RESOLVED_PROFILE_SEMANTIC_INVALID",
            `/ccaInputs${entry.path}`,
            `${entry.code}: ${entry.message}`,
          ),
        ),
      );
    }
  }

  return {
    diagnostics,
    decoded: decoded as Partial<{
      propertyCatalog: PropertyCatalog;
      attackerCatalog: AttackerCatalog;
      threatCatalog: ThreatCatalog;
      capabilityModuleCatalog: CapabilityModuleCatalog;
      resolvedProfile: ResolvedProfile;
    }>,
  };
}

function upstreamDiagnostics(
  input: AeRenderPlanValidationInput,
  plan: AeRenderPlan,
): {
  readonly diagnostics: readonly AeRenderDiagnostic[];
  readonly schemas: Partial<Record<AeUpstreamSchemaRole, object>>;
  readonly validators: Partial<Record<AeNativeArtifactKind, NativeValidator>>;
} {
  const diagnostics: AeRenderDiagnostic[] = [];
  const schemas: Partial<Record<AeUpstreamSchemaRole, object>> = {};
  const validators: Partial<Record<AeNativeArtifactKind, NativeValidator>> = {};
  for (const role of Object.keys(input.upstreamSchemaBytes).sort(compare)) {
    if (!(aeUpstreamSchemaRoles as readonly string[]).includes(role)) {
      diagnostics.push(
        diagnostic(
          "UPSTREAM_SCHEMA_ROLE_UNKNOWN",
          `/upstream/schemas/${role}`,
          "Supplied upstream schema bytes use a role outside the closed exact pin.",
        ),
      );
    }
  }
  for (const role of aeUpstreamSchemaRoles) {
    const bytes: unknown = input.upstreamSchemaBytes[role];
    const path = `/upstream/schemas/${role}`;
    if (!isBytes(bytes)) {
      diagnostics.push(
        diagnostic(
          "UPSTREAM_SCHEMA_MISSING",
          path,
          `No exact pinned schema bytes were supplied for ${role}.`,
        ),
      );
      continue;
    }
    const binding = plan.upstream.schemas[role];
    const exactDiagnostics = bindingDiagnostics(
      binding,
      bytes,
      path,
      "UPSTREAM_SCHEMA",
    );
    diagnostics.push(...exactDiagnostics);
    const expectedSnapshot = upstreamSnapshotByRole[role];
    const decoded = decodeStrictJsonObject(bytes);
    if (!decoded.valid) {
      diagnostics.push(
        ...decoded.diagnostics.map((entry) =>
          diagnostic(entry.code, `${path}${entry.path}`, entry.message),
        ),
      );
      continue;
    }
    if (exactDiagnostics.length > 0 || JSON.stringify(decoded.value) !== JSON.stringify(expectedSnapshot)) {
      if (exactDiagnostics.length === 0) {
        diagnostics.push(
          diagnostic(
            "UPSTREAM_SCHEMA_SNAPSHOT_MISMATCH",
            path,
            "The supplied schema value differs from the repository snapshot.",
          ),
        );
      }
      continue;
    }
    schemas[role] = decoded.value;
  }

  for (const kind of aeNativeArtifactKinds) {
    const role = nativeRoleByKind[kind];
    const schema = schemas[role];
    if (schema === undefined) continue;
    try {
      validators[kind] = compileContractBytes(schema);
    } catch (error) {
      diagnostics.push(
        diagnostic(
          "UPSTREAM_SCHEMA_COMPILE_FAILED",
          `/upstream/schemas/${role}`,
          `The exact pinned schema could not be compiled: ${error instanceof Error ? error.message : "unknown error"}`,
        ),
      );
    }
  }
  return { diagnostics, schemas, validators };
}

function resolvedBindingDiagnostics(
  plan: AeRenderPlan,
  decoded: ReturnType<typeof decodedCcaInputDiagnostics>["decoded"],
): readonly AeRenderDiagnostic[] {
  const diagnostics: AeRenderDiagnostic[] = [];
  const profile = decoded.resolvedProfile;
  if (profile === undefined) return diagnostics;
  if (profile.state !== "complete") {
    diagnostics.push(
      diagnostic(
        "RESOLVED_PROFILE_INCOMPLETE",
        "/ccaInputs/resolvedProfile",
        "A native render plan cannot promote an incomplete resolved profile.",
      ),
    );
  }
  const roles = [
    ["propertyCatalog", decoded.propertyCatalog],
    ["attackerCatalog", decoded.attackerCatalog],
    ["threatCatalog", decoded.threatCatalog],
    ["moduleCatalog", decoded.capabilityModuleCatalog],
  ] as const;
  for (const [bindingRole, artifact] of roles) {
    if (artifact === undefined) continue;
    const binding = profile.inputBindings[bindingRole];
    const planRole = bindingRole === "moduleCatalog" ? "capabilityModuleCatalog" : bindingRole;
    const exact = plan.ccaInputs[planRole];
    if (
      binding.contractId !== artifact.schemaVersion ||
      binding.catalogId !== artifact.catalogId ||
      binding.catalogVersion !== artifact.catalogVersion ||
      binding.digest.value !== exact.sha256
    ) {
      diagnostics.push(
        diagnostic(
          "RESOLVED_PROFILE_BINDING_MISMATCH",
          `/ccaInputs/resolvedProfile/inputBindings/${bindingRole}`,
          `The resolved profile does not repeat the exact ${planRole} identity and digest.`,
        ),
      );
    }
  }
  return diagnostics;
}

interface ContextIdentifiers {
  readonly objectIds: Set<string>;
  readonly morphismIds: Set<string>;
  readonly diagramIds: Set<string>;
  readonly acceptanceTestIds: Set<string>;
}

function emptyContextIdentifiers(): ContextIdentifiers {
  return {
    objectIds: new Set(),
    morphismIds: new Set(),
    diagramIds: new Set(),
    acceptanceTestIds: new Set(),
  };
}

function contextDiagnostics(
  input: AeRenderPlanValidationInput,
  plan: AeRenderPlan,
  schema: object | undefined,
): {
  readonly diagnostics: readonly AeRenderDiagnostic[];
  readonly identifiers: ContextIdentifiers;
} {
  const diagnostics: AeRenderDiagnostic[] = [];
  const identifiers = emptyContextIdentifiers();
  const allIdentifiers = emptyContextIdentifiers();
  const selectedContextIds = new Set(
    plan.scopeMapping.disposition === "render" && plan.scopeMapping.scope !== undefined
      ? plan.scopeMapping.scope.contextPackIds
      : [],
  );
  diagnostics.push(
    ...duplicateDiagnostics(
      plan.contextPacks.map(({ id }) => id),
      "CONTEXT_PACK_ID_DUPLICATE",
      "/contextPacks",
    ),
    ...duplicateDiagnostics(
      plan.contextPacks.map(({ path }) => path),
      "CONTEXT_PACK_PATH_DUPLICATE",
      "/contextPacks",
    ),
  );
  if (input.contextPackBytes.size > 8) {
    diagnostics.push(
      diagnostic(
        "CONTEXT_PACK_INPUT_LIMIT_EXCEEDED",
        "/contextPacks",
        "At most eight supplied Context Pack byte sequences are accepted by v1.",
      ),
    );
  }
  for (const [index, binding] of plan.contextPacks.entries()) {
    const path = `/contextPacks/${index}`;
    const bytes = input.contextPackBytes.get(binding.id);
    if (bytes === undefined) {
      diagnostics.push(
        diagnostic(
          "CONTEXT_PACK_MISSING",
          path,
          `No exact bytes were supplied for Context Pack ${binding.id}.`,
        ),
      );
      continue;
    }
    diagnostics.push(...bindingDiagnostics(binding, bytes, path, "CONTEXT_PACK"));
    const decoded = decodeStrictJsonObject<Record<string, unknown>>(bytes);
    if (!decoded.valid) {
      diagnostics.push(
        ...decoded.diagnostics.map((entry) =>
          diagnostic(entry.code, `${path}${entry.path}`, entry.message),
        ),
      );
      continue;
    }
    if (schema === undefined) {
      diagnostics.push(
        diagnostic(
          "CONTEXT_PACK_SCHEMA_UNAVAILABLE",
          path,
          "Pinned Context Pack schema bytes were not validly supplied.",
        ),
      );
    } else {
      diagnostics.push(
        ...schemaDiagnostics(
          compileContractBytes(schema)(bytes),
          path,
          "CONTEXT_PACK_SCHEMA_INVALID",
        ),
      );
    }
    const groups = [
      ["objects", allIdentifiers.objectIds, identifiers.objectIds],
      ["morphisms", allIdentifiers.morphismIds, identifiers.morphismIds],
      ["diagrams", allIdentifiers.diagramIds, identifiers.diagramIds],
      [
        "acceptance_tests",
        allIdentifiers.acceptanceTestIds,
        identifiers.acceptanceTestIds,
      ],
    ] as const;
    for (const [key, allTarget, selectedTarget] of groups) {
      const entries = decoded.value[key];
      if (!Array.isArray(entries)) continue;
      for (const [entryIndex, entry] of entries.entries()) {
        const id =
          entry !== null && typeof entry === "object" && !Array.isArray(entry)
            ? (entry as Record<string, unknown>).id
            : undefined;
        if (typeof id !== "string") continue;
        if (allTarget.has(id)) {
          diagnostics.push(
            diagnostic(
              "CONTEXT_PACK_ELEMENT_ID_DUPLICATE",
              `${path}/${key}/${entryIndex}/id`,
              `Duplicate Context Pack element ID: ${id}.`,
            ),
          );
        }
        allTarget.add(id);
        if (selectedContextIds.has(binding.id)) selectedTarget.add(id);
      }
    }
  }
  if (input.contextPackBytes.size <= 8) {
    for (const id of input.contextPackBytes.keys()) {
      if (!plan.contextPacks.some((binding) => binding.id === id)) {
        diagnostics.push(
          diagnostic(
            "CONTEXT_PACK_UNREFERENCED",
            "/contextPacks",
            `Supplied Context Pack bytes are not declared by the plan: ${id}.`,
          ),
        );
      }
    }
  }
  return { diagnostics, identifiers };
}

function outputDiagnostics(plan: AeRenderPlan): readonly AeRenderDiagnostic[] {
  const diagnostics: AeRenderDiagnostic[] = [];
  diagnostics.push(
    ...duplicateDiagnostics(
      plan.outputs.map(({ artifactKind }) => artifactKind),
      "OUTPUT_KIND_DUPLICATE",
      "/outputs",
    ),
    ...duplicateDiagnostics(
      plan.outputs.flatMap(({ outputPath }) =>
        outputPath === undefined ? [] : [outputPath],
      ),
      "OUTPUT_PATH_DUPLICATE",
      "/outputs",
    ),
  );
  const actual = new Set(plan.outputs.map(({ artifactKind }) => artifactKind));
  for (const kind of aeNativeArtifactKinds) {
    if (!actual.has(kind)) {
      diagnostics.push(
        diagnostic(
          "OUTPUT_DISPOSITION_MISSING",
          "/outputs",
          `The plan does not explicitly disposition ${kind}.`,
        ),
      );
    }
  }
  return diagnostics;
}

function scopeDiagnostics(
  plan: AeRenderPlan,
  resolvedProfile: ResolvedProfile | undefined,
  identifiers: ContextIdentifiers,
): {
  readonly diagnostics: readonly AeRenderDiagnostic[];
  readonly boundaries: ReadonlyMap<string, TrustBoundary>;
} {
  const diagnostics: AeRenderDiagnostic[] = [];
  const boundaries = new Map<string, TrustBoundary>();
  if (plan.scopeMapping.disposition !== "render" || plan.scopeMapping.scope === undefined) {
    if (plan.outputs.some(({ disposition }) => disposition === "render")) {
      diagnostics.push(
        diagnostic(
          "SCOPE_MAPPING_REQUIRED",
          "/scopeMapping",
          "Every supported native output requires the explicit rendered scope mapping.",
        ),
      );
    }
    return { diagnostics, boundaries };
  }
  const scope = plan.scopeMapping.scope;
  if (!targetEqual(plan.target, scope.target)) {
    diagnostics.push(
      diagnostic(
        "TARGET_SCOPE_MISMATCH",
        "/scopeMapping/scope/target",
        "The audit-scope target differs from the plan target identity.",
      ),
    );
  }
  if (resolvedProfile !== undefined && scope.profileId !== resolvedProfile.profileId) {
    diagnostics.push(
      diagnostic(
        "PROFILE_ID_MISMATCH",
        "/scopeMapping/scope/profileId",
        "The native profile ID differs from the exact resolved profile ID.",
      ),
    );
  }
  diagnostics.push(
    ...duplicateDiagnostics(
      scope.contextPackIds,
      "CONTEXT_PACK_ID_DUPLICATE",
      "/scopeMapping/scope/contextPackIds",
    ),
    ...duplicateDiagnostics(
      scope.trustBoundaries.map(({ id }) => id),
      "TRUST_BOUNDARY_ID_DUPLICATE",
      "/scopeMapping/scope/trustBoundaries",
    ),
  );
  const declaredContexts = new Set(plan.contextPacks.map(({ id }) => id));
  for (const [index, id] of scope.contextPackIds.entries()) {
    if (!declaredContexts.has(id)) {
      diagnostics.push(
        diagnostic(
          "CONTEXT_PACK_REFERENCE_DANGLING",
          `/scopeMapping/scope/contextPackIds/${index}`,
          `No declared Context Pack has ID ${id}.`,
        ),
      );
    }
  }
  const availableScopeRefs = new Set([
    ...identifiers.objectIds,
    ...identifiers.morphismIds,
    ...identifiers.diagramIds,
    ...identifiers.acceptanceTestIds,
  ]);
  for (const [boundaryIndex, boundary] of scope.trustBoundaries.entries()) {
    boundaries.set(boundary.id, boundary);
    for (const [refIndex, ref] of (boundary.scopeRefs ?? []).entries()) {
      if (!availableScopeRefs.has(ref)) {
        diagnostics.push(
          diagnostic(
            "CONTEXT_SCOPE_REF_DANGLING",
            `/scopeMapping/scope/trustBoundaries/${boundaryIndex}/scopeRefs/${refIndex}`,
            `No scope-selected Context Pack declares ${ref}.`,
          ),
        );
      }
    }
  }
  return { diagnostics, boundaries };
}

function scopeRefDiagnostics(
  refs: ScopeRefs,
  identifiers: ContextIdentifiers,
  path: string,
): readonly AeRenderDiagnostic[] {
  const diagnostics: AeRenderDiagnostic[] = [];
  const groups = [
    ["objectIds", refs.objectIds, identifiers.objectIds],
    ["morphismIds", refs.morphismIds, identifiers.morphismIds],
    ["diagramIds", refs.diagramIds, identifiers.diagramIds],
    ["acceptanceTestIds", refs.acceptanceTestIds, identifiers.acceptanceTestIds],
  ] as const;
  for (const [key, values, available] of groups) {
    for (const [index, id] of (values ?? []).entries()) {
      if (!available.has(id)) {
        diagnostics.push(
          diagnostic(
            "CONTEXT_SCOPE_REF_DANGLING",
            `${path}/${key}/${index}`,
            `No supplied Context Pack declares ${id}.`,
          ),
        );
      }
    }
  }
  return diagnostics;
}

interface NativeEnums {
  readonly lanes: ReadonlySet<string>;
  readonly evidenceKinds: ReadonlySet<string>;
  readonly stride: ReadonlySet<string>;
  readonly claimKinds: ReadonlySet<string>;
  readonly criticalities: ReadonlySet<string>;
  readonly assuranceLevels: ReadonlySet<string>;
}

function nativeEnums(schemas: Partial<Record<AeUpstreamSchemaRole, object>>): NativeEnums {
  const profile = schemas.assuranceProfile ?? {};
  const claim = schemas.securityClaim ?? {};
  const threat = schemas.securityThreatModel ?? {};
  return {
    lanes: enumAt(profile, ["$defs", "claim", "properties", "requiredLanes", "items", "enum"]),
    evidenceKinds: enumAt(profile, ["$defs", "claim", "properties", "requiredEvidenceKinds", "items", "enum"]),
    stride: new Set([
      ...enumAt(claim, ["$defs", "stride", "enum"]),
      ...enumAt(threat, ["$defs", "stride", "enum"]),
    ]),
    claimKinds: enumAt(profile, ["$defs", "claim", "properties", "kind", "enum"]),
    criticalities: enumAt(profile, ["$defs", "claim", "properties", "criticality", "enum"]),
    assuranceLevels: enumAt(profile, ["$defs", "claim", "properties", "targetLevel", "enum"]),
  };
}

function claimDiagnostics(
  plan: AeRenderPlan,
  propertyCatalog: PropertyCatalog | undefined,
  resolvedProfile: ResolvedProfile | undefined,
  boundaries: ReadonlyMap<string, TrustBoundary>,
  identifiers: ContextIdentifiers,
  enums: NativeEnums,
): {
  readonly diagnostics: readonly AeRenderDiagnostic[];
  readonly renderedClaimIds: ReadonlySet<string>;
} {
  const diagnostics: AeRenderDiagnostic[] = [];
  const renderedClaimIds = new Set<string>();
  diagnostics.push(
    ...duplicateDiagnostics(
      plan.claimMappings.map(({ propertyId }) => propertyId),
      "CLAIM_MAPPING_DUPLICATE",
      "/claimMappings",
    ),
  );
  const selected = Object.keys(resolvedProfile?.selections.properties ?? {}).sort(compare);
  const mapped = [...new Set(plan.claimMappings.map(({ propertyId }) => propertyId))].sort(compare);
  if (!equalSet(selected, mapped)) {
    diagnostics.push(
      diagnostic(
        "CLAIM_MAPPING_INCOMPLETE",
        "/claimMappings",
        "Claim mappings must disposition every and only exact resolved-profile property selection.",
      ),
    );
  }
  for (const [index, mapping] of plan.claimMappings.entries()) {
    const path = `/claimMappings/${index}`;
    const property = propertyCatalog?.properties[mapping.propertyId];
    if (property === undefined) {
      diagnostics.push(
        diagnostic(
          "PROPERTY_REFERENCE_DANGLING",
          `${path}/propertyId`,
          `No exact bound property catalog entry has ID ${mapping.propertyId}.`,
        ),
      );
    }
    if (mapping.disposition !== "render" || mapping.claim === undefined) continue;
    const claim = mapping.claim;
    if (claim.claimId !== mapping.propertyId) {
      diagnostics.push(
        diagnostic(
          "CLAIM_PROPERTY_ID_MISMATCH",
          `${path}/claim/claimId`,
          "The native claim ID must equal the exact CCA property ID.",
        ),
      );
    } else {
      renderedClaimIds.add(claim.claimId);
    }
    const expectedSection = `#/properties/${pointerSegment(mapping.propertyId)}`;
    if (
      !claim.sourceRefs.some(
        ({ uri, section }) =>
          uri === plan.ccaInputs.propertyCatalog.path && section === expectedSection,
      )
    ) {
      diagnostics.push(
        diagnostic(
          "CLAIM_SOURCE_REFERENCE_MISSING",
          `${path}/claim/sourceRefs`,
          "A rendered claim must cite the exact property-catalog path and JSON Pointer.",
        ),
      );
    }
    diagnostics.push(
      ...duplicateDiagnostics(
        claim.evidenceMappings.map(({ sourceEvidenceKind }) => sourceEvidenceKind),
        "EVIDENCE_MAPPING_DUPLICATE",
        `${path}/claim/evidenceMappings`,
      ),
      ...duplicateDiagnostics(
        claim.evidenceMappings.map(({ decisionId }) => decisionId),
        "EVIDENCE_DECISION_ID_DUPLICATE",
        `${path}/claim/evidenceMappings`,
      ),
    );
    const requiredSourceEvidence = property?.requiredEvidenceKinds ?? [];
    const mappedEvidence = claim.evidenceMappings.map(({ sourceEvidenceKind }) => sourceEvidenceKind);
    if (!equalSet(requiredSourceEvidence, mappedEvidence)) {
      diagnostics.push(
        diagnostic(
          "EVIDENCE_MAPPING_INCOMPLETE",
          `${path}/claim/evidenceMappings`,
          "Evidence mappings must disposition every and only exact source CCA evidence requirement.",
        ),
      );
    }
    const projectedLanes: string[] = [];
    const projectedKinds: string[] = [];
    for (const [evidenceIndex, evidenceMapping] of claim.evidenceMappings.entries()) {
      if (evidenceMapping.disposition !== "render" || evidenceMapping.rendered === undefined) continue;
      const evidencePath = `${path}/claim/evidenceMappings/${evidenceIndex}/rendered`;
      if (
        (evidenceMapping.sourceEvidenceKind === "operational-procedure" ||
          evidenceMapping.sourceEvidenceKind === "human-review") &&
        (evidenceMapping.rendered.projection !== "lossy" ||
          evidenceMapping.rendered.requiredEvidenceKinds.includes("waiver"))
      ) {
        diagnostics.push(
          diagnostic(
            "UNSUPPORTED_EVIDENCE_PROJECTION",
            evidencePath,
            "Operational-procedure and human-review require an explicit narrower lossy projection; waiver is not such a projection.",
          ),
        );
      }
      for (const [laneIndex, lane] of evidenceMapping.rendered.requiredLanes.entries()) {
        if (!enums.lanes.has(lane)) {
          diagnostics.push(
            diagnostic(
              "NATIVE_ENUM_INVALID",
              `${evidencePath}/requiredLanes/${laneIndex}`,
              `Lane ${lane} is not in the exact pinned assurance-profile schema.`,
            ),
          );
        }
        projectedLanes.push(lane);
      }
      for (const [kindIndex, kind] of evidenceMapping.rendered.requiredEvidenceKinds.entries()) {
        if (!enums.evidenceKinds.has(kind)) {
          diagnostics.push(
            diagnostic(
              "NATIVE_ENUM_INVALID",
              `${evidencePath}/requiredEvidenceKinds/${kindIndex}`,
              `Evidence kind ${kind} is not in the exact pinned assurance-profile schema.`,
            ),
          );
        }
        projectedKinds.push(kind);
      }
    }
    if (!equalSet([...new Set(projectedLanes)], claim.requiredLanes)) {
      diagnostics.push(
        diagnostic(
          "EVIDENCE_LANE_AGGREGATE_MISMATCH",
          `${path}/claim/requiredLanes`,
          "Claim requiredLanes must equal the explicit rendered evidence-mapping union.",
        ),
      );
    }
    if (!equalSet([...new Set(projectedKinds)], claim.requiredEvidenceKinds)) {
      diagnostics.push(
        diagnostic(
          "EVIDENCE_KIND_AGGREGATE_MISMATCH",
          `${path}/claim/requiredEvidenceKinds`,
          "Claim requiredEvidenceKinds must equal the explicit rendered evidence-mapping union.",
        ),
      );
    }
    for (const [laneIndex, lane] of claim.requiredLanes.entries()) {
      if (!enums.lanes.has(lane)) {
        diagnostics.push(
          diagnostic("NATIVE_ENUM_INVALID", `${path}/claim/requiredLanes/${laneIndex}`, `Lane ${lane} is not in the pinned schema.`),
        );
      }
    }
    for (const [kindIndex, kind] of claim.requiredEvidenceKinds.entries()) {
      if (!enums.evidenceKinds.has(kind)) {
        diagnostics.push(
          diagnostic("NATIVE_ENUM_INVALID", `${path}/claim/requiredEvidenceKinds/${kindIndex}`, `Evidence kind ${kind} is not in the pinned schema.`),
        );
      }
    }
    if (!enums.claimKinds.has(claim.kind)) {
      diagnostics.push(diagnostic("NATIVE_ENUM_INVALID", `${path}/claim/kind`, `Claim kind ${claim.kind} is not in the pinned schema.`));
    }
    if (!enums.criticalities.has(claim.criticality)) {
      diagnostics.push(diagnostic("NATIVE_ENUM_INVALID", `${path}/claim/criticality`, `Criticality ${claim.criticality} is not in the pinned schema.`));
    }
    if (!enums.assuranceLevels.has(claim.targetLevel)) {
      diagnostics.push(diagnostic("NATIVE_ENUM_INVALID", `${path}/claim/targetLevel`, `Target level ${claim.targetLevel} is not in the pinned schema.`));
    }
    for (const [tagIndex, tag] of claim.threatTags.stride.entries()) {
      if (!enums.stride.has(tag)) diagnostics.push(diagnostic("NATIVE_ENUM_INVALID", `${path}/claim/threatTags/stride/${tagIndex}`, `STRIDE value ${tag} is not in the pinned schema.`));
    }
    const boundaryId = claim.trustBoundary.boundaryIds[0];
    const boundary = boundaryId === undefined ? undefined : boundaries.get(boundaryId);
    if (boundary === undefined) {
      diagnostics.push(diagnostic("TRUST_BOUNDARY_REFERENCE_DANGLING", `${path}/claim/trustBoundary/boundaryIds`, "The rendered claim references no declared trust boundary."));
    } else if (
      !equalSet(claim.trustBoundary.entryPoints, boundary.entryPoints) ||
      claim.trustBoundary.attackerControlled !== boundary.attackerControlled ||
      !equalSet(claim.trustBoundary.dataClasses ?? [], boundary.dataClasses ?? [])
    ) {
      diagnostics.push(diagnostic("TRUST_BOUNDARY_PROJECTION_MISMATCH", `${path}/claim/trustBoundary`, "The claim trust-boundary projection differs from its explicit scope boundary."));
    }
    if (claim.scopeRefs !== undefined) diagnostics.push(...scopeRefDiagnostics(claim.scopeRefs, identifiers, `${path}/claim/scopeRefs`));
    const expectedProvenanceSource = `${plan.ccaInputs.propertyCatalog.path}${expectedSection}`;
    if (
      claim.provenance.generator !== plan.renderer.implementationId ||
      claim.provenance.version !== plan.renderer.packageVersion ||
      claim.provenance.source !== expectedProvenanceSource
    ) {
      diagnostics.push(diagnostic("CLAIM_PROVENANCE_MISMATCH", `${path}/claim/provenance`, "Native claim provenance must identify the exact renderer and bound source property."));
    }
  }
  return { diagnostics, renderedClaimIds };
}

function threatDiagnostics(
  plan: AeRenderPlan,
  threatCatalog: ThreatCatalog | undefined,
  resolvedProfile: ResolvedProfile | undefined,
  renderedClaimIds: ReadonlySet<string>,
  boundaries: ReadonlyMap<string, TrustBoundary>,
  enums: NativeEnums,
): { readonly diagnostics: readonly AeRenderDiagnostic[]; readonly renderedThreatCount: number } {
  const diagnostics: AeRenderDiagnostic[] = [];
  let renderedThreatCount = 0;
  diagnostics.push(...duplicateDiagnostics(plan.threatMappings.map(({ threatId }) => threatId), "THREAT_MAPPING_DUPLICATE", "/threatMappings"));
  const selected = Object.keys(resolvedProfile?.selections.threats ?? {}).sort(compare);
  const mapped = [...new Set(plan.threatMappings.map(({ threatId }) => threatId))].sort(compare);
  if (!equalSet(selected, mapped)) diagnostics.push(diagnostic("THREAT_MAPPING_INCOMPLETE", "/threatMappings", "Threat mappings must disposition every and only exact resolved-profile threat selection."));
  for (const [index, mapping] of plan.threatMappings.entries()) {
    const path = `/threatMappings/${index}`;
    const source = threatCatalog?.threats[mapping.threatId];
    if (source === undefined) diagnostics.push(diagnostic("THREAT_REFERENCE_DANGLING", `${path}/threatId`, `No exact bound threat catalog entry has ID ${mapping.threatId}.`));
    if (mapping.disposition !== "render" || mapping.threat === undefined) continue;
    renderedThreatCount += 1;
    const threat = mapping.threat;
    if (threat.threatId !== mapping.threatId) diagnostics.push(diagnostic("THREAT_ID_MISMATCH", `${path}/threat/threatId`, "The native threat ID must equal the exact CCA threat ID."));
    if (!enums.stride.has(threat.stride)) diagnostics.push(diagnostic("NATIVE_ENUM_INVALID", `${path}/threat/stride`, `STRIDE value ${threat.stride} is not in the exact pinned schema.`));
    for (const [claimIndex, claimId] of threat.relatedClaimIds.entries()) {
      if (!renderedClaimIds.has(claimId)) diagnostics.push(diagnostic("RELATED_CLAIM_DANGLING", `${path}/threat/relatedClaimIds/${claimIndex}`, `Related claim ${claimId} is not generated.`));
      if (source !== undefined && !source.affectedProperties.includes(claimId)) diagnostics.push(diagnostic("RELATED_CLAIM_SOURCE_MISMATCH", `${path}/threat/relatedClaimIds/${claimIndex}`, `Related claim ${claimId} is not an affected property of the exact source threat.`));
    }
    for (const [boundaryIndex, boundaryId] of (threat.trustBoundaryIds ?? []).entries()) {
      if (!boundaries.has(boundaryId)) diagnostics.push(diagnostic("TRUST_BOUNDARY_REFERENCE_DANGLING", `${path}/threat/trustBoundaryIds/${boundaryIndex}`, `No declared trust boundary has ID ${boundaryId}.`));
    }
  }
  return { diagnostics, renderedThreatCount };
}

function requestedOutput(plan: AeRenderPlan, kind: AeNativeArtifactKind): OutputSelection | undefined {
  return plan.outputs.find((output) => output.artifactKind === kind);
}

function outputReadinessDiagnostics(
  plan: AeRenderPlan,
  renderedClaimCount: number,
  renderedThreatCount: number,
): readonly AeRenderDiagnostic[] {
  const diagnostics: AeRenderDiagnostic[] = [];
  const scopeReady = plan.scopeMapping.disposition === "render" && plan.scopeMapping.scope !== undefined;
  const requirements = [
    ["assurance-profile/v1", scopeReady && plan.contextPacks.length > 0 && renderedClaimCount > 0],
    ["security-claim/v1", scopeReady && renderedClaimCount > 0],
    ["security-threat-model/v1", scopeReady && renderedThreatCount > 0],
    ["security-audit-scope/v1", scopeReady],
  ] as const;
  for (const [kind, ready] of requirements) {
    if (requestedOutput(plan, kind)?.disposition === "render" && !ready) {
      diagnostics.push(diagnostic("OUTPUT_MAPPING_INCOMPLETE", "/outputs", `${kind} is marked render without every required explicit mapping.`));
    }
  }
  return diagnostics;
}

function projectionDiagnostics(plan: AeRenderPlan): readonly AeRenderDiagnostic[] {
  const diagnostics: AeRenderDiagnostic[] = [];
  for (const [index, output] of plan.outputs.entries()) {
    if (output.disposition !== "render") {
      diagnostics.push(
        diagnostic(
          output.disposition === "unsupported"
            ? "OUTPUT_MAPPING_UNSUPPORTED"
            : "OUTPUT_MAPPING_EXCLUDED",
          `/outputs/${index}`,
          `${output.artifactKind} remains ${output.disposition}: ${output.reason ?? "No reason supplied."}`,
          "information",
        ),
      );
    }
  }
  for (const [index, mapping] of plan.claimMappings.entries()) {
    if (mapping.disposition !== "render") {
      diagnostics.push(
        diagnostic(
          mapping.disposition === "unsupported"
            ? "CLAIM_MAPPING_UNSUPPORTED"
            : "CLAIM_MAPPING_EXCLUDED",
          `/claimMappings/${index}`,
          `${mapping.propertyId} remains ${mapping.disposition}: ${mapping.reason ?? "No reason supplied."}`,
          "information",
        ),
      );
      continue;
    }
    for (const [evidenceIndex, evidence] of (mapping.claim?.evidenceMappings ?? []).entries()) {
      if (evidence.disposition !== "render") {
        diagnostics.push(
          diagnostic(
            evidence.disposition === "unsupported"
              ? "EVIDENCE_MAPPING_UNSUPPORTED"
              : "EVIDENCE_MAPPING_EXCLUDED",
            `/claimMappings/${index}/claim/evidenceMappings/${evidenceIndex}`,
            `${evidence.decisionId} retains ${evidence.sourceEvidenceKind} as ${evidence.disposition}: ${evidence.reason ?? "No reason supplied."}`,
            "information",
          ),
        );
      } else if (evidence.rendered?.projection === "lossy") {
        diagnostics.push(
          diagnostic(
            "EVIDENCE_MAPPING_LOSSY",
            `/claimMappings/${index}/claim/evidenceMappings/${evidenceIndex}`,
            `${evidence.decisionId} is an explicit lossy projection of ${evidence.sourceEvidenceKind}: ${evidence.rendered.lossExplanation ?? "Loss remains explicit in the plan."}`,
            "information",
          ),
        );
      }
    }
  }
  for (const [index, mapping] of plan.threatMappings.entries()) {
    if (mapping.disposition !== "render") {
      diagnostics.push(
        diagnostic(
          mapping.disposition === "unsupported"
            ? "THREAT_MAPPING_UNSUPPORTED"
            : "THREAT_MAPPING_EXCLUDED",
          `/threatMappings/${index}`,
          `${mapping.threatId} remains ${mapping.disposition}: ${mapping.reason ?? "No reason supplied."}`,
          "information",
        ),
      );
    } else {
      diagnostics.push(
        diagnostic(
          "THREAT_PROJECTION_LOSSY",
          `/threatMappings/${index}`,
          `${mapping.threatId} projects explicit STRIDE/CWE/claim/boundary fields; structured CCA capabilities, preconditions, assumptions, exclusions, and impact remain in the exact bound source catalog and plan notes.`,
          "information",
        ),
      );
    }
  }
  for (const [index, contextPack] of plan.contextPacks.entries()) {
    diagnostics.push(
      diagnostic(
        "CONTEXT_PACK_REFERENCE_LOSSY",
        `/contextPacks/${index}`,
        `${contextPack.id} projects only repository-relative path ${contextPack.path}; exact digest and byte length remain in the CCA plan and CCA-240 records.`,
        "information",
      ),
    );
  }
  if (plan.scopeMapping.disposition === "render" && plan.scopeMapping.scope !== undefined) {
    diagnostics.push(
      diagnostic(
        "AUDIT_TREE_PROJECTION_LOSSY",
        "/scopeMapping/scope/treeProjection",
        plan.scopeMapping.scope.treeProjection.reason,
        "information",
      ),
    );
  }
  return normalizeAeRenderDiagnostics(diagnostics, "information");
}

export function validateAeRenderPlan(
  input: AeRenderPlanValidationInput,
): AeRenderPlanValidationResult {
  const planResult = planValidator(input.planBytes);
  if (!planResult.valid) {
    return { valid: false, diagnostics: normalizeAeRenderDiagnostics(schemaDiagnostics(planResult, "/plan", "RENDER_PLAN_SCHEMA_INVALID")) };
  }
  const plan = planResult.value as unknown as AeRenderPlan;
  const diagnostics: AeRenderDiagnostic[] = [];
  diagnostics.push(...outputDiagnostics(plan));
  if (!isBytes(input.rendererSourceBytes)) {
    diagnostics.push(
      diagnostic(
        "RENDERER_SOURCE_MISSING",
        "/renderer/sourceSha256",
        "No exact renderer implementation bytes were supplied.",
      ),
    );
  } else if (plan.renderer.sourceSha256 !== sha256(input.rendererSourceBytes)) {
    diagnostics.push(diagnostic("RENDERER_IDENTITY_MISMATCH", "/renderer/sourceSha256", "The renderer source digest does not bind the supplied exact implementation bytes."));
  }
  const cca = decodedCcaInputDiagnostics(input, plan);
  diagnostics.push(...cca.diagnostics, ...resolvedBindingDiagnostics(plan, cca.decoded));
  const upstream = upstreamDiagnostics(input, plan);
  diagnostics.push(...upstream.diagnostics);
  const contexts = contextDiagnostics(input, plan, upstream.schemas.contextPack);
  diagnostics.push(...contexts.diagnostics);
  const scope = scopeDiagnostics(
    plan,
    cca.decoded.resolvedProfile,
    contexts.identifiers,
  );
  diagnostics.push(...scope.diagnostics);
  const claims = claimDiagnostics(plan, cca.decoded.propertyCatalog, cca.decoded.resolvedProfile, scope.boundaries, contexts.identifiers, nativeEnums(upstream.schemas));
  diagnostics.push(...claims.diagnostics);
  const threats = threatDiagnostics(plan, cca.decoded.threatCatalog, cca.decoded.resolvedProfile, claims.renderedClaimIds, scope.boundaries, nativeEnums(upstream.schemas));
  diagnostics.push(...threats.diagnostics);
  diagnostics.push(...outputReadinessDiagnostics(plan, claims.renderedClaimIds.size, threats.renderedThreatCount));
  const stable = normalizeAeRenderDiagnostics(diagnostics);
  if (stable.length > 0) return { valid: false, diagnostics: stable };

  const completeValidators = {} as Record<AeNativeArtifactKind, NativeValidator>;
  for (const kind of aeNativeArtifactKinds) {
    const validator = upstream.validators[kind];
    if (validator === undefined) {
      return { valid: false, diagnostics: [diagnostic("UPSTREAM_SCHEMA_UNAVAILABLE", `/upstream/schemas/${nativeRoleByKind[kind]}`, `No validator is available for ${kind}.`)] };
    }
    completeValidators[kind] = validator;
  }
  const token = Object.freeze({ planId: plan.planId });
  validatedStates.set(token, { plan, nativeValidators: completeValidators });
  return { valid: true, validatedPlan: token, diagnostics: [] };
}

function optionalSet(name: string, values: readonly string[] | undefined): Record<string, readonly string[]> {
  return values === undefined ? {} : { [name]: sorted(values) };
}

function renderAssuranceProfile(plan: AeRenderPlan): object {
  const scope = plan.scopeMapping.scope;
  if (scope === undefined) throw new Error("validated scope is missing");
  return {
    schemaVersion: "assurance-profile/v1",
    profileId: scope.profileId,
    scope: {
      contextPackSources: sorted(plan.contextPacks.filter(({ id }) => scope.contextPackIds.includes(id)).map(({ path }) => path)),
      componentGlobs: sorted(scope.componentGlobs),
    },
    claims: plan.claimMappings
      .filter((mapping): mapping is ClaimMapping & { claim: NonNullable<ClaimMapping["claim"]> } => mapping.disposition === "render" && mapping.claim !== undefined)
      .sort((left, right) => compare(left.propertyId, right.propertyId))
      .map(({ claim }) => ({
        id: claim.claimId,
        statement: claim.statement,
        kind: claim.kind,
        criticality: claim.criticality,
        targetLevel: claim.targetLevel,
        ...(claim.minIndependentSources === undefined ? {} : { minIndependentSources: claim.minIndependentSources }),
        ...(claim.scopeRefs === undefined
          ? {}
          : {
              scopeRefs: {
                ...optionalSet("objectIds", claim.scopeRefs.objectIds),
                ...optionalSet("morphismIds", claim.scopeRefs.morphismIds),
                ...optionalSet("diagramIds", claim.scopeRefs.diagramIds),
                ...optionalSet("acceptanceTestIds", claim.scopeRefs.acceptanceTestIds),
              },
            }),
        requiredLanes: sorted(claim.requiredLanes),
        requiredEvidenceKinds: sorted(claim.requiredEvidenceKinds),
      })),
  };
}

function renderSecurityClaims(plan: AeRenderPlan): object {
  return {
    schemaVersion: "security-claim/v1",
    claims: plan.claimMappings
      .filter((mapping): mapping is ClaimMapping & { claim: NonNullable<ClaimMapping["claim"]> } => mapping.disposition === "render" && mapping.claim !== undefined)
      .sort((left, right) => compare(left.propertyId, right.propertyId))
      .map(({ claim }) => ({
        id: claim.claimId,
        type: claim.type,
        statement: claim.statement,
        sourceRefs: [...claim.sourceRefs]
          .sort(
            (left, right) =>
              compare(left.kind, right.kind) ||
              compare(left.uri, right.uri) ||
              compare(left.section, right.section) ||
              compare(left.description ?? "", right.description ?? ""),
          )
          .map((source) => ({ kind: source.kind, uri: source.uri, section: source.section, ...(source.description === undefined ? {} : { description: source.description }) })),
        criticality: claim.criticality,
        targetLevel: claim.targetLevel,
        threatTags: { stride: sorted(claim.threatTags.stride), cwe: sorted(claim.threatTags.cwe) },
        trustBoundary: {
          boundaryIds: sorted(claim.trustBoundary.boundaryIds),
          entryPoints: sorted(claim.trustBoundary.entryPoints),
          attackerControlled: claim.trustBoundary.attackerControlled,
          ...optionalSet("dataClasses", claim.trustBoundary.dataClasses),
          ...optionalSet("notes", claim.trustBoundary.notes),
        },
        requiredLanes: sorted(claim.requiredLanes),
        provenance: {
          origin: claim.provenance.origin,
          generator: claim.provenance.generator,
          source: claim.provenance.source,
          version: claim.provenance.version,
        },
        ...optionalSet("notes", claim.notes),
      })),
  };
}

function renderThreatModel(plan: AeRenderPlan): object {
  return {
    schemaVersion: "security-threat-model/v1",
    frameworks: ["CWE_TOP_25", "STRIDE"],
    threats: plan.threatMappings
      .filter((mapping): mapping is ThreatMapping & { threat: NonNullable<ThreatMapping["threat"]> } => mapping.disposition === "render" && mapping.threat !== undefined)
      .sort((left, right) => compare(left.threatId, right.threatId))
      .map(({ threat }) => ({
        id: threat.threatId,
        stride: threat.stride,
        cwe: threat.cwe,
        description: threat.description,
        relatedClaimIds: sorted(threat.relatedClaimIds),
        ...optionalSet("trustBoundaryIds", threat.trustBoundaryIds),
        ...optionalSet("notes", threat.notes),
      })),
  };
}

function renderAuditScope(plan: AeRenderPlan): object {
  const scope = plan.scopeMapping.scope;
  if (scope === undefined) throw new Error("validated scope is missing");
  return {
    schemaVersion: "security-audit-scope/v1",
    target: { repository: scope.target.repository, commit: scope.target.commit },
    inScope: sorted(scope.inScope),
    outOfScope: sorted(scope.outOfScope),
    trustBoundaries: [...scope.trustBoundaries]
      .sort((left, right) => compare(left.id, right.id))
      .map((boundary) => ({
        id: boundary.id,
        name: boundary.name,
        entryPoints: sorted(boundary.entryPoints),
        attackerControlled: boundary.attackerControlled,
        ...(boundary.description === undefined ? {} : { description: boundary.description }),
        ...optionalSet("dataClasses", boundary.dataClasses),
        ...optionalSet("scopeRefs", boundary.scopeRefs),
      })),
  };
}

function serialize(value: object): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(value, undefined, 2)}\n`);
}

export function renderAeNativeArtifacts(
  validatedPlan: ValidatedAeRenderPlan,
): AeNativeRenderResult {
  const state = validatedStates.get(validatedPlan);
  if (state === undefined) {
    return {
      valid: false,
      outputs: [],
      diagnostics: [diagnostic("VALIDATED_PLAN_REQUIRED", "", "Rendering accepts only a token returned by successful render-plan validation.")],
    };
  }
  const renderers: Readonly<Record<AeNativeArtifactKind, () => object>> = {
    "assurance-profile/v1": () => renderAssuranceProfile(state.plan),
    "security-claim/v1": () => renderSecurityClaims(state.plan),
    "security-threat-model/v1": () => renderThreatModel(state.plan),
    "security-audit-scope/v1": () => renderAuditScope(state.plan),
  };
  const outputs: RenderedAeArtifact[] = [];
  const renderErrors: AeRenderDiagnostic[] = [];
  for (const kind of aeNativeArtifactKinds) {
    const selection = requestedOutput(state.plan, kind);
    if (selection?.disposition !== "render" || selection.outputPath === undefined) continue;
    const bytes = serialize(renderers[kind]());
    const validation = state.nativeValidators[kind](bytes);
    const schemaErrors = schemaDiagnostics(
      validation,
      `/outputs/${kind}`,
      "NATIVE_SCHEMA_MISMATCH",
    );
    if (schemaErrors.length > 0) renderErrors.push(...schemaErrors);
    else outputs.push({ artifactKind: kind, path: selection.outputPath, bytes });
  }
  const stableErrors = normalizeAeRenderDiagnostics(renderErrors);
  return {
    valid: stableErrors.length === 0,
    outputs,
    diagnostics: normalizeAeRenderDiagnostics([
      ...stableErrors,
      ...projectionDiagnostics(state.plan),
    ]),
  };
}
