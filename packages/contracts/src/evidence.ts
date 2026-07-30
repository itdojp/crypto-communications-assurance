import { createHash } from "node:crypto";

import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";

import bindingSetSchema from "../../../schema/cryptocomm-evidence-binding-set-v1.schema.json" with { type: "json" };
import evidenceProvenanceSchema from "../../../schema/cryptocomm-evidence-provenance-v1.schema.json" with { type: "json" };
import executionResultSchema from "../../../schema/cryptocomm-execution-result-v1.schema.json" with { type: "json" };
import freshnessAssessmentSchema from "../../../schema/cryptocomm-freshness-assessment-v1.schema.json" with { type: "json" };

import {
  decodeStrictJsonObject,
  type StrictJsonDiagnostic,
  type StrictJsonDiagnosticCode,
} from "./strict-json.js";

export const executionStatuses = [
  "pass",
  "fail",
  "skip",
  "unsupported",
  "timeout",
  "tool-error",
  "not-run",
] as const;
export type ExecutionStatus = (typeof executionStatuses)[number];

export const artifactRoles = [
  "substantive-result",
  "partial",
  "diagnostic",
  "log",
] as const;
export type ArtifactRole = (typeof artifactRoles)[number];

export const freshnessStates = [
  "fresh",
  "stale",
  "mismatched",
  "unknown",
  "not-assessed",
] as const;
export type FreshnessState = (typeof freshnessStates)[number];

export const maximumEvidenceInputBindings = 64;
export const maximumEvidenceArtifactReferences = 64;
export const maximumPrivateOpaqueReferences = 64;
export const maximumEvidenceDiagnostics = 256;

export interface EvidenceSha256Digest {
  readonly algorithm: "sha256";
  readonly value: string;
}

export interface EvidenceGitSha1 {
  readonly algorithm: "git-sha1";
  readonly value: string;
}

export interface ExactContentBinding {
  readonly digest: EvidenceSha256Digest;
  readonly byteLength: number;
}

export interface FreshnessBindingFingerprint extends ExactContentBinding {
  readonly bindingId: string;
}

export interface ExactRecordBinding extends ExactContentBinding {
  readonly contractId: string;
  readonly recordId: string;
}

export interface Cca110ManifestSubject {
  readonly kind: "cca-110-manifest";
  readonly manifest: ExactRecordBinding & {
    readonly contractId: "cryptocomm-pack-manifest/v1";
  };
}

export interface GitRevisionSubject {
  readonly kind: "git-revision";
  readonly repositoryId: string;
  readonly commit: EvidenceGitSha1;
  readonly tree: EvidenceGitSha1;
}

export interface ContractArtifactSubject {
  readonly kind: "contract-artifact";
  readonly artifact: ExactRecordBinding;
}

export type EvidenceSubject =
  | Cca110ManifestSubject
  | GitRevisionSubject
  | ContractArtifactSubject;

export interface EvidenceContractIdentity {
  readonly contractId: string;
  readonly recordId: string;
}

export interface ExactInputBinding extends ExactContentBinding {
  readonly inputId: string;
  readonly mediaType: string;
  readonly contract?: EvidenceContractIdentity;
}

export interface SoftwareIdentity {
  readonly implementationId: string;
  readonly version: string;
  readonly sourceRepositoryId: string;
  readonly sourceRevision: EvidenceGitSha1;
}

export interface SoftwareProducer {
  readonly kind: "software";
  readonly implementation: SoftwareIdentity;
}

export interface HumanProducer {
  readonly kind: "human";
  readonly operatorId: string;
}

export type EvidenceProducer = SoftwareProducer | HumanProducer;

export interface IdentifiedTool {
  readonly kind: "identified";
  readonly toolId: string;
  readonly version: string;
  readonly implementation: SoftwareIdentity;
}

export interface NotApplicableTool {
  readonly kind: "not-applicable";
  readonly reason: string;
}

export type EvidenceTool = IdentifiedTool | NotApplicableTool;

export interface RecordedEnvironment {
  readonly kind: "recorded";
  readonly environmentId: string;
  readonly operatingSystem: string;
  readonly architecture: string;
  readonly runtimeVersion?: string;
  readonly immutableImageDigest?: EvidenceSha256Digest;
}

export interface NotRecordedEnvironment {
  readonly kind: "not-recorded";
  readonly reason: string;
}

export type EvidenceEnvironment = RecordedEnvironment | NotRecordedEnvironment;

export interface OperatorScope {
  readonly scopeId: string;
  readonly description: string;
  readonly exclusions: readonly string[];
}

export interface EvidenceSafetyBoundary {
  readonly executable: false;
  readonly networkRequired: false;
  readonly secretsAllowed: false;
}

export interface EvidenceDiagnostic {
  readonly code: string;
  readonly path: string;
  readonly message: string;
}

export interface ExecutionArtifactReference {
  readonly artifactId: string;
  readonly role: ArtifactRole;
}

export interface RetryAdvisory {
  readonly advisoryOnly: true;
  readonly meaningful: boolean;
  readonly reason: string;
}

export interface CheckIdentity {
  readonly checkId: string;
  readonly criteriaId: string;
  readonly criteriaVersion: string;
}

export interface CompletedExecution {
  readonly attempted: true;
  readonly occurred: true;
  readonly completed: true;
  readonly startedAt: string;
  readonly completedAt: string;
}

export interface SkipExecution {
  readonly attempted: false;
  readonly occurred: false;
  readonly completed: false;
  readonly decisionId: string;
  readonly reasonCode: string;
  readonly reason: string;
}

export interface UnsupportedExecution {
  readonly attempted: false;
  readonly occurred: false;
  readonly completed: false;
  readonly supportScope: string;
  readonly reasonCode: string;
  readonly reason: string;
}

export interface TimeoutExecution {
  readonly attempted: true;
  readonly occurred: true;
  readonly completed: false;
  readonly startedAt: string;
  readonly timeLimitMilliseconds: number;
  readonly reasonCode: string;
  readonly reason: string;
}

export interface ToolErrorPreflightExecution {
  readonly attempted: true;
  readonly occurred: false;
  readonly completed: false;
  readonly phase: "preflight";
  readonly reasonCode: string;
  readonly reason: string;
}

export interface ToolErrorOccurredExecution {
  readonly attempted: true;
  readonly occurred: true;
  readonly completed: false;
  readonly phase: "execution" | "post-processing";
  readonly startedAt: string;
  readonly reasonCode: string;
  readonly reason: string;
}

export interface NotRunExecution {
  readonly attempted: false;
  readonly occurred: false;
  readonly completed: false;
  readonly reasonCode: string;
  readonly reason: string;
}

interface ExecutionResultBase {
  readonly schemaVersion: "cryptocomm-execution-result/v1";
  readonly resultId: string;
  readonly check: CheckIdentity;
  readonly subject: EvidenceSubject;
  readonly inputBindings: readonly ExactInputBinding[];
  readonly producer: EvidenceProducer;
  readonly tool: EvidenceTool;
  readonly environment: EvidenceEnvironment;
  readonly scope: OperatorScope;
  readonly artifacts: readonly ExecutionArtifactReference[];
  readonly retryAdvisory: RetryAdvisory;
  readonly diagnostics: readonly EvidenceDiagnostic[];
  readonly fixtureClassification?: "synthetic-test-only";
  readonly safety: EvidenceSafetyBoundary;
}

export interface PassExecutionResult extends ExecutionResultBase {
  readonly status: "pass";
  readonly execution: CompletedExecution;
}
export interface FailExecutionResult extends ExecutionResultBase {
  readonly status: "fail";
  readonly execution: CompletedExecution;
}
export interface SkipExecutionResult extends ExecutionResultBase {
  readonly status: "skip";
  readonly execution: SkipExecution;
}
export interface UnsupportedExecutionResult extends ExecutionResultBase {
  readonly status: "unsupported";
  readonly execution: UnsupportedExecution;
}
export interface TimeoutExecutionResult extends ExecutionResultBase {
  readonly status: "timeout";
  readonly execution: TimeoutExecution;
}
export interface ToolErrorExecutionResult extends ExecutionResultBase {
  readonly status: "tool-error";
  readonly execution: ToolErrorPreflightExecution | ToolErrorOccurredExecution;
}
export interface NotRunExecutionResult extends ExecutionResultBase {
  readonly status: "not-run";
  readonly execution: NotRunExecution;
}

export type ExecutionResult =
  | PassExecutionResult
  | FailExecutionResult
  | SkipExecutionResult
  | UnsupportedExecutionResult
  | TimeoutExecutionResult
  | ToolErrorExecutionResult
  | NotRunExecutionResult;

export interface PublicContentArtifactReference {
  readonly kind: "public-content";
  readonly artifactId: string;
  readonly role: ArtifactRole;
  readonly digest: EvidenceSha256Digest;
  readonly byteLength: number;
  readonly mediaType: string;
}

export interface PrivateOpaqueArtifactReference {
  readonly kind: "private-opaque";
  readonly artifactId: string;
  readonly classification: "private";
  readonly role: ArtifactRole;
  readonly opaqueId: string;
}

export type ProvenanceArtifactReference =
  | PublicContentArtifactReference
  | PrivateOpaqueArtifactReference;

export interface EvidenceProvenance {
  readonly schemaVersion: "cryptocomm-evidence-provenance/v1";
  readonly provenanceId: string;
  readonly executionResult: ExactRecordBinding & {
    readonly contractId: "cryptocomm-execution-result/v1";
  };
  readonly subject: EvidenceSubject;
  readonly inputBindings: readonly ExactInputBinding[];
  readonly producer: EvidenceProducer;
  readonly tool: EvidenceTool;
  readonly environment: EvidenceEnvironment;
  readonly scope: OperatorScope;
  readonly evidenceOrigin: "synthetic" | "real";
  readonly useRestriction: "test-only" | "policy-evaluable";
  readonly artifacts: readonly ProvenanceArtifactReference[];
  readonly diagnostics: readonly EvidenceDiagnostic[];
  readonly fixtureClassification?: "synthetic-test-only";
  readonly safety: EvidenceSafetyBoundary;
}

export interface ComparisonNotSelected {
  readonly selected: false;
  readonly outcome: "not-selected";
}
export interface ComparisonAvailable {
  readonly selected: true;
  readonly availability: "available";
  readonly expected: FreshnessBindingFingerprint;
  readonly observed: FreshnessBindingFingerprint;
  readonly outcome: "match" | "mismatch";
}
export interface ComparisonUnavailable {
  readonly selected: true;
  readonly availability: "unavailable";
  readonly expected: FreshnessBindingFingerprint;
  readonly outcome: "unknown";
}
export type FreshnessComparison =
  | ComparisonNotSelected
  | ComparisonAvailable
  | ComparisonUnavailable;

export type FreshnessDimensionName =
  | "subject"
  | "input"
  | "producer"
  | "tool"
  | "contract"
  | "dependency"
  | "scope"
  | "environment";

export type FreshnessDimensions = Readonly<
  Record<FreshnessDimensionName, FreshnessComparison>
>;

export interface TimeNotSelected {
  readonly selected: false;
  readonly clockTrust: "not-required";
  readonly outcome: "not-selected";
}
export interface TimeSelected {
  readonly selected: true;
  readonly clockTrust: "trusted" | "untrusted" | "unknown";
  readonly validity: "valid" | "expired" | "unknown";
  readonly outcome: "valid" | "expired" | "unknown";
}
export type FreshnessTimeFact = TimeNotSelected | TimeSelected;

export interface LifecycleNotSelected {
  readonly selected: false;
  readonly outcome: "not-selected";
}
export interface LifecycleAvailable {
  readonly selected: true;
  readonly authorityId: string;
  readonly availability: "available";
  readonly applies: boolean;
  readonly outcome: "clear" | "applies";
}
export interface LifecycleUnavailable {
  readonly selected: true;
  readonly authorityId: string;
  readonly availability: "unavailable";
  readonly outcome: "unknown";
}
export type FreshnessLifecycleFact =
  | LifecycleNotSelected
  | LifecycleAvailable
  | LifecycleUnavailable;

export interface FreshnessValidity {
  readonly time: FreshnessTimeFact;
  readonly supersession: FreshnessLifecycleFact;
  readonly revocation: FreshnessLifecycleFact;
  readonly invalidation: FreshnessLifecycleFact;
}

export interface FreshnessAssessment {
  readonly schemaVersion: "cryptocomm-freshness-assessment/v1";
  readonly assessmentId: string;
  readonly provenance: ExactRecordBinding & {
    readonly contractId: "cryptocomm-evidence-provenance/v1";
  };
  readonly subject: EvidenceSubject;
  readonly scope: OperatorScope;
  readonly intent: {
    readonly requested: boolean;
    readonly context?: {
      readonly contextId: string;
      readonly contextVersion: string;
    };
  };
  readonly asOf: string;
  readonly dimensions: FreshnessDimensions;
  readonly validity: FreshnessValidity;
  readonly state: FreshnessState;
  readonly diagnostics: readonly EvidenceDiagnostic[];
  readonly fixtureClassification?: "synthetic-test-only";
  readonly safety: EvidenceSafetyBoundary;
}

export interface EvidenceBindingSet {
  readonly schemaVersion: "cryptocomm-evidence-binding-set/v1";
  readonly bindingSetId: string;
  readonly subject: EvidenceSubject;
  readonly scope: OperatorScope;
  readonly bindings: {
    readonly executionResult: ExactRecordBinding & {
      readonly contractId: "cryptocomm-execution-result/v1";
    };
    readonly evidenceProvenance: ExactRecordBinding & {
      readonly contractId: "cryptocomm-evidence-provenance/v1";
    };
    readonly freshnessAssessment: ExactRecordBinding & {
      readonly contractId: "cryptocomm-freshness-assessment/v1";
    };
  };
  readonly diagnostics: readonly EvidenceDiagnostic[];
  readonly fixtureClassification?: "synthetic-test-only";
  readonly safety: EvidenceSafetyBoundary;
}

export const evidenceDiagnosticCodes = [
  "CONTRACT_SCHEMA_INVALID",
  "INPUT_ID_DUPLICATE",
  "ARTIFACT_ID_DUPLICATE",
  "BINDING_CONTRACT_MISMATCH",
  "BINDING_RECORD_ID_MISMATCH",
  "BINDING_DIGEST_MISMATCH",
  "BINDING_BYTE_LENGTH_MISMATCH",
  "SUBJECT_MISMATCH",
  "INPUT_BINDING_MISMATCH",
  "PRODUCER_MISMATCH",
  "TOOL_MISMATCH",
  "ENVIRONMENT_MISMATCH",
  "SCOPE_MISMATCH",
  "FIXTURE_CLASSIFICATION_MISMATCH",
  "ARTIFACT_REFERENCE_MISMATCH",
  "FRESHNESS_CONTEXT_INCONSISTENT",
  "FRESHNESS_REQUIREMENT_REQUIRED",
  "FRESHNESS_COMPARISON_INCONSISTENT",
  "FRESHNESS_STATE_INCONSISTENT",
  "DIAGNOSTIC_LIMIT_EXCEEDED",
] as const;
export type EvidenceSpecificDiagnosticCode =
  (typeof evidenceDiagnosticCodes)[number];
export type EvidenceDiagnosticCode =
  | EvidenceSpecificDiagnosticCode
  | StrictJsonDiagnosticCode;

const evidenceDiagnosticDescriptions: Readonly<
  Record<EvidenceSpecificDiagnosticCode, string>
> = {
  CONTRACT_SCHEMA_INVALID:
    "A strict-decoded input does not conform to its closed Draft 2020-12 contract.",
  INPUT_ID_DUPLICATE: "An exact input identifier is repeated.",
  ARTIFACT_ID_DUPLICATE: "An artifact identifier is repeated.",
  BINDING_CONTRACT_MISMATCH:
    "An exact-byte binding names a contract other than the supplied artifact contract.",
  BINDING_RECORD_ID_MISMATCH:
    "An exact-byte binding names a record other than the supplied artifact record.",
  BINDING_DIGEST_MISMATCH:
    "An exact-byte binding does not match the SHA-256 of the supplied original bytes.",
  BINDING_BYTE_LENGTH_MISMATCH:
    "An exact-byte binding does not match the supplied original byte length.",
  SUBJECT_MISMATCH:
    "Cross-contract subject identities differ; no subject-form inference is performed.",
  INPUT_BINDING_MISMATCH: "Cross-contract exact input bindings differ.",
  PRODUCER_MISMATCH: "Cross-contract producer identities differ.",
  TOOL_MISMATCH: "Cross-contract tool identities differ.",
  ENVIRONMENT_MISMATCH: "Cross-contract environment identities differ.",
  SCOPE_MISMATCH: "Cross-contract operator-selected scopes differ.",
  FIXTURE_CLASSIFICATION_MISMATCH:
    "Cross-contract fixture classifications differ; a synthetic/test-only fixture marker must propagate through the complete binding chain.",
  ARTIFACT_REFERENCE_MISMATCH:
    "Execution and provenance artifact identifiers or roles differ.",
  FRESHNESS_CONTEXT_INCONSISTENT:
    "Freshness intent/context is inconsistent with a performed assessment.",
  FRESHNESS_REQUIREMENT_REQUIRED:
    "A requested assessment context selects no identity or validity requirement.",
  FRESHNESS_COMPARISON_INCONSISTENT:
    "A freshness dimension outcome does not follow from its explicit caller-supplied facts.",
  FRESHNESS_STATE_INCONSISTENT:
    "The freshness state does not follow the required not-assessed, mismatched, stale, unknown, fresh decision order.",
  DIAGNOSTIC_LIMIT_EXCEEDED:
    "Validation produced more than 256 diagnostics; remaining diagnostics were omitted deterministically.",
};

export interface EvidenceValidationDiagnostic {
  readonly code: EvidenceDiagnosticCode;
  readonly path: string;
  readonly message: string;
}
export interface EvidenceValidationSuccess {
  readonly valid: true;
  readonly diagnostics: readonly [];
}
export interface EvidenceValidationFailure {
  readonly valid: false;
  readonly diagnostics: readonly EvidenceValidationDiagnostic[];
}
export type EvidenceValidationResult =
  | EvidenceValidationSuccess
  | EvidenceValidationFailure;

const compare = (left: string, right: string): number =>
  left < right ? -1 : left > right ? 1 : 0;

const ajv = new Ajv2020({ allErrors: true, strict: true, validateFormats: false });
const schemaValidators = {
  execution: ajv.compile(executionResultSchema as object),
  provenance: ajv.compile(evidenceProvenanceSchema as object),
  freshness: ajv.compile(freshnessAssessmentSchema as object),
  bindingSet: ajv.compile(bindingSetSchema as object),
} as const;

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function exactRecordBinding(
  contractId: string,
  recordId: string,
  bytes: Uint8Array,
): ExactRecordBinding {
  return {
    contractId,
    recordId,
    digest: { algorithm: "sha256", value: sha256(bytes) },
    byteLength: bytes.byteLength,
  };
}

function escapePointer(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function diagnostic(
  code: EvidenceSpecificDiagnosticCode,
  path: string,
): EvidenceValidationDiagnostic {
  return { code, path, message: evidenceDiagnosticDescriptions[code] };
}

function stableDiagnostics(
  entries: readonly EvidenceValidationDiagnostic[],
): readonly EvidenceValidationDiagnostic[] {
  const unique = new Map<string, EvidenceValidationDiagnostic>();
  for (const entry of entries) {
    unique.set(`${entry.code}\0${entry.path}\0${entry.message}`, entry);
  }
  let stable = [...unique.values()].sort(
    (left, right) =>
      compare(left.code, right.code) ||
      compare(left.path, right.path) ||
      compare(left.message, right.message),
  );
  if (stable.length > maximumEvidenceDiagnostics) {
    stable = [
      ...stable.slice(0, maximumEvidenceDiagnostics - 1),
      diagnostic("DIAGNOSTIC_LIMIT_EXCEEDED", ""),
    ].sort(
      (left, right) =>
        compare(left.code, right.code) || compare(left.path, right.path),
    );
  }
  return stable;
}

function validationResult(
  entries: readonly EvidenceValidationDiagnostic[],
): EvidenceValidationResult {
  const diagnostics = stableDiagnostics(entries);
  return diagnostics.length === 0
    ? { valid: true, diagnostics: [] }
    : { valid: false, diagnostics };
}

function prefixedStrictDiagnostics(
  entries: readonly StrictJsonDiagnostic[],
  prefix: string,
): readonly EvidenceValidationDiagnostic[] {
  return entries.map((entry) => ({
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
  return prefix + error.instancePath + (named === undefined ? "" : `/${escapePointer(named)}`);
}

function schemaDiagnostics(
  validator: ValidateFunction,
  value: object,
  prefix: string,
): readonly EvidenceValidationDiagnostic[] {
  if (validator(value)) return [];
  return (validator.errors ?? []).map((error) => ({
    code: "CONTRACT_SCHEMA_INVALID",
    path: schemaErrorPath(prefix, error),
    message: `${evidenceDiagnosticDescriptions.CONTRACT_SCHEMA_INVALID} Keyword: ${error.keyword}.`,
  }));
}

interface DecodedArtifact<T extends object> {
  readonly value?: T;
  readonly diagnostics: readonly EvidenceValidationDiagnostic[];
}

function decodeArtifact<T extends object>(
  bytes: Uint8Array,
  prefix: string,
): DecodedArtifact<T> {
  const decoded = decodeStrictJsonObject<T>(bytes);
  return decoded.valid
    ? { value: decoded.value, diagnostics: [] }
    : { diagnostics: prefixedStrictDiagnostics(decoded.diagnostics, prefix) };
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value
      .map((entry) => canonicalValue(entry))
      .sort((left, right) => compare(JSON.stringify(left), JSON.stringify(right)));
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => compare(left, right))
        .map(([key, entry]) => [key, canonicalValue(entry)]),
    );
  }
  return value;
}

function valuesEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(canonicalValue(left)) === JSON.stringify(canonicalValue(right));
}

export function serializeEvidenceContract(value: object): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(canonicalValue(value), undefined, 2)}\n`);
}

export const serializeExecutionResult = (value: ExecutionResult): Uint8Array =>
  serializeEvidenceContract(value);
export const serializeEvidenceProvenance = (
  value: EvidenceProvenance,
): Uint8Array => serializeEvidenceContract(value);
export const serializeFreshnessAssessment = (
  value: FreshnessAssessment,
): Uint8Array => serializeEvidenceContract(value);
export const serializeEvidenceBindingSet = (
  value: EvidenceBindingSet,
): Uint8Array => serializeEvidenceContract(value);

function duplicateIdDiagnostics(
  values: readonly { readonly id: string; readonly path: string }[],
  code: "INPUT_ID_DUPLICATE" | "ARTIFACT_ID_DUPLICATE",
): readonly EvidenceValidationDiagnostic[] {
  const seen = new Set<string>();
  const diagnostics: EvidenceValidationDiagnostic[] = [];
  for (const value of values) {
    if (seen.has(value.id)) diagnostics.push(diagnostic(code, value.path));
    seen.add(value.id);
  }
  return diagnostics;
}

function executionSemantics(
  value: ExecutionResult,
  prefix: string,
): readonly EvidenceValidationDiagnostic[] {
  return [
    ...duplicateIdDiagnostics(
      value.inputBindings.map((entry, index) => ({
        id: entry.inputId,
        path: `${prefix}/inputBindings/${index}/inputId`,
      })),
      "INPUT_ID_DUPLICATE",
    ),
    ...duplicateIdDiagnostics(
      value.artifacts.map((entry, index) => ({
        id: entry.artifactId,
        path: `${prefix}/artifacts/${index}/artifactId`,
      })),
      "ARTIFACT_ID_DUPLICATE",
    ),
  ];
}

function provenanceSemantics(
  value: EvidenceProvenance,
  prefix: string,
): readonly EvidenceValidationDiagnostic[] {
  return [
    ...duplicateIdDiagnostics(
      value.inputBindings.map((entry, index) => ({
        id: entry.inputId,
        path: `${prefix}/inputBindings/${index}/inputId`,
      })),
      "INPUT_ID_DUPLICATE",
    ),
    ...duplicateIdDiagnostics(
      value.artifacts.map((entry, index) => ({
        id: entry.artifactId,
        path: `${prefix}/artifacts/${index}/artifactId`,
      })),
      "ARTIFACT_ID_DUPLICATE",
    ),
  ];
}

function selectedRequirementCount(value: FreshnessAssessment): number {
  return (
    Object.values(value.dimensions).filter((entry) => entry.selected).length +
    Object.values(value.validity).filter((entry) => entry.selected).length
  );
}

function expectedComparisonOutcome(value: FreshnessComparison): FreshnessComparison["outcome"] {
  if (!value.selected) return "not-selected";
  if (value.availability === "unavailable") return "unknown";
  return valuesEqual(value.expected, value.observed) ? "match" : "mismatch";
}

function expectedTimeOutcome(value: FreshnessTimeFact): FreshnessTimeFact["outcome"] {
  if (!value.selected) return "not-selected";
  if (value.clockTrust !== "trusted") return "unknown";
  return value.validity;
}

function expectedLifecycleOutcome(
  value: FreshnessLifecycleFact,
): FreshnessLifecycleFact["outcome"] {
  if (!value.selected) return "not-selected";
  if (value.availability === "unavailable") return "unknown";
  return value.applies ? "applies" : "clear";
}

function expectedFreshnessState(value: FreshnessAssessment): FreshnessState | undefined {
  if (!value.intent.requested || value.intent.context === undefined) return "not-assessed";
  if (selectedRequirementCount(value) === 0) return undefined;
  if (Object.values(value.dimensions).some((entry) => entry.outcome === "mismatch")) {
    return "mismatched";
  }
  if (
    value.validity.time.outcome === "expired" ||
    value.validity.supersession.outcome === "applies" ||
    value.validity.revocation.outcome === "applies" ||
    value.validity.invalidation.outcome === "applies"
  ) {
    return "stale";
  }
  if (
    Object.values(value.dimensions).some((entry) => entry.outcome === "unknown") ||
    Object.values(value.validity).some((entry) => entry.outcome === "unknown")
  ) {
    return "unknown";
  }
  return "fresh";
}

function freshnessSemantics(
  value: FreshnessAssessment,
  prefix: string,
): readonly EvidenceValidationDiagnostic[] {
  const diagnostics: EvidenceValidationDiagnostic[] = [];
  const active = value.intent.requested && value.intent.context !== undefined;
  if (!value.intent.requested && value.intent.context !== undefined) {
    diagnostics.push(diagnostic("FRESHNESS_CONTEXT_INCONSISTENT", `${prefix}/intent/context`));
  }
  if (!active) {
    if (
      Object.values(value.dimensions).some((entry) => entry.selected) ||
      Object.values(value.validity).some((entry) => entry.selected)
    ) {
      diagnostics.push(diagnostic("FRESHNESS_CONTEXT_INCONSISTENT", `${prefix}/intent`));
    }
  } else if (selectedRequirementCount(value) === 0) {
    diagnostics.push(diagnostic("FRESHNESS_REQUIREMENT_REQUIRED", `${prefix}/dimensions`));
  }

  for (const [name, comparison] of Object.entries(value.dimensions)) {
    if (comparison.outcome !== expectedComparisonOutcome(comparison)) {
      diagnostics.push(
        diagnostic("FRESHNESS_COMPARISON_INCONSISTENT", `${prefix}/dimensions/${name}/outcome`),
      );
    }
  }
  if (value.validity.time.outcome !== expectedTimeOutcome(value.validity.time)) {
    diagnostics.push(
      diagnostic("FRESHNESS_COMPARISON_INCONSISTENT", `${prefix}/validity/time/outcome`),
    );
  }
  for (const name of ["supersession", "revocation", "invalidation"] as const) {
    const lifecycle = value.validity[name];
    if (lifecycle.outcome !== expectedLifecycleOutcome(lifecycle)) {
      diagnostics.push(
        diagnostic("FRESHNESS_COMPARISON_INCONSISTENT", `${prefix}/validity/${name}/outcome`),
      );
    }
  }
  const expected = expectedFreshnessState(value);
  if (expected !== undefined && value.state !== expected) {
    diagnostics.push(diagnostic("FRESHNESS_STATE_INCONSISTENT", `${prefix}/state`));
  }
  return diagnostics;
}

function validateOne<T extends object>(
  bytes: Uint8Array,
  prefix: string,
  validator: ValidateFunction,
  semantics: (value: T, prefix: string) => readonly EvidenceValidationDiagnostic[],
): EvidenceValidationResult {
  const decoded = decodeArtifact<T>(bytes, prefix);
  if (decoded.value === undefined) return validationResult(decoded.diagnostics);
  const schema = schemaDiagnostics(validator, decoded.value, prefix);
  if (schema.length > 0) return validationResult(schema);
  return validationResult(semantics(decoded.value, prefix));
}

export const validateExecutionResult = (bytes: Uint8Array): EvidenceValidationResult =>
  validateOne<ExecutionResult>(bytes, "/executionResult", schemaValidators.execution, executionSemantics);

export const validateEvidenceProvenance = (
  bytes: Uint8Array,
): EvidenceValidationResult =>
  validateOne<EvidenceProvenance>(bytes, "/evidenceProvenance", schemaValidators.provenance, provenanceSemantics);

export const validateFreshnessAssessment = (
  bytes: Uint8Array,
): EvidenceValidationResult =>
  validateOne<FreshnessAssessment>(bytes, "/freshnessAssessment", schemaValidators.freshness, freshnessSemantics);

export const validateEvidenceBindingSetContract = (
  bytes: Uint8Array,
): EvidenceValidationResult =>
  validateOne<EvidenceBindingSet>(bytes, "/bindingSet", schemaValidators.bindingSet, () => []);

export type ComparisonRequest =
  | { readonly selected: false }
  | {
      readonly selected: true;
      readonly availability: "available";
      readonly expected: FreshnessBindingFingerprint;
      readonly observed: FreshnessBindingFingerprint;
    }
  | {
      readonly selected: true;
      readonly availability: "unavailable";
      readonly expected: FreshnessBindingFingerprint;
    };

export type TimeFactRequest =
  | { readonly selected: false }
  | {
      readonly selected: true;
      readonly clockTrust: "trusted" | "untrusted" | "unknown";
      readonly validity: "valid" | "expired" | "unknown";
    };

export type LifecycleFactRequest =
  | { readonly selected: false }
  | {
      readonly selected: true;
      readonly authorityId: string;
      readonly availability: "available";
      readonly applies: boolean;
    }
  | {
      readonly selected: true;
      readonly authorityId: string;
      readonly availability: "unavailable";
    };

export interface FreshnessAssessmentRequest {
  readonly assessmentId: string;
  readonly provenance: FreshnessAssessment["provenance"];
  readonly subject: EvidenceSubject;
  readonly scope: OperatorScope;
  readonly intent: FreshnessAssessment["intent"];
  readonly asOf: string;
  readonly dimensions: Readonly<Record<FreshnessDimensionName, ComparisonRequest>>;
  readonly validity: {
    readonly time: TimeFactRequest;
    readonly supersession: LifecycleFactRequest;
    readonly revocation: LifecycleFactRequest;
    readonly invalidation: LifecycleFactRequest;
  };
  readonly fixtureClassification?: "synthetic-test-only";
  readonly safety: EvidenceSafetyBoundary;
}

export interface FreshnessAssessmentSuccess {
  readonly valid: true;
  readonly assessment: FreshnessAssessment;
  readonly bytes: Uint8Array;
  readonly diagnostics: readonly [];
}
export interface FreshnessAssessmentFailure {
  readonly valid: false;
  readonly diagnostics: readonly EvidenceValidationDiagnostic[];
}
export type FreshnessAssessmentResult =
  | FreshnessAssessmentSuccess
  | FreshnessAssessmentFailure;

function comparisonFromRequest(
  request: ComparisonRequest,
  active: boolean,
): FreshnessComparison {
  if (!active || !request.selected) return { selected: false, outcome: "not-selected" };
  if (request.availability === "unavailable") {
    return {
      selected: true,
      availability: "unavailable",
      expected: request.expected,
      outcome: "unknown",
    };
  }
  return {
    selected: true,
    availability: "available",
    expected: request.expected,
    observed: request.observed,
    outcome: valuesEqual(request.expected, request.observed) ? "match" : "mismatch",
  };
}

function timeFromRequest(request: TimeFactRequest, active: boolean): FreshnessTimeFact {
  if (!active || !request.selected) {
    return { selected: false, clockTrust: "not-required", outcome: "not-selected" };
  }
  return {
    selected: true,
    clockTrust: request.clockTrust,
    validity: request.validity,
    outcome: request.clockTrust === "trusted" ? request.validity : "unknown",
  };
}

function lifecycleFromRequest(
  request: LifecycleFactRequest,
  active: boolean,
): FreshnessLifecycleFact {
  if (!active || !request.selected) return { selected: false, outcome: "not-selected" };
  if (request.availability === "unavailable") {
    return {
      selected: true,
      authorityId: request.authorityId,
      availability: "unavailable",
      outcome: "unknown",
    };
  }
  return {
    selected: true,
    authorityId: request.authorityId,
    availability: "available",
    applies: request.applies,
    outcome: request.applies ? "applies" : "clear",
  };
}

export function assessFreshness(
  request: FreshnessAssessmentRequest,
): FreshnessAssessmentResult {
  const active = request.intent.requested && request.intent.context !== undefined;
  const dimensions = Object.fromEntries(
    (Object.keys(request.dimensions) as FreshnessDimensionName[])
      .sort(compare)
      .map((name) => [name, comparisonFromRequest(request.dimensions[name], active)]),
  ) as unknown as FreshnessDimensions;
  const validity: FreshnessValidity = {
    time: timeFromRequest(request.validity.time, active),
    supersession: lifecycleFromRequest(request.validity.supersession, active),
    revocation: lifecycleFromRequest(request.validity.revocation, active),
    invalidation: lifecycleFromRequest(request.validity.invalidation, active),
  };
  const provisional: FreshnessAssessment = {
    schemaVersion: "cryptocomm-freshness-assessment/v1",
    assessmentId: request.assessmentId,
    provenance: request.provenance,
    subject: request.subject,
    scope: request.scope,
    intent: request.intent,
    asOf: request.asOf,
    dimensions,
    validity,
    state: "not-assessed",
    diagnostics: [],
    ...(request.fixtureClassification === undefined
      ? {}
      : { fixtureClassification: request.fixtureClassification }),
    safety: request.safety,
  };
  const expected = expectedFreshnessState(provisional);
  if (expected === undefined) {
    return {
      valid: false,
      diagnostics: [diagnostic("FRESHNESS_REQUIREMENT_REQUIRED", "/dimensions")],
    };
  }
  const assessment: FreshnessAssessment = { ...provisional, state: expected };
  const bytes = serializeFreshnessAssessment(assessment);
  const validation = validateFreshnessAssessment(bytes);
  if (!validation.valid) return validation;
  return { valid: true, assessment, bytes, diagnostics: [] };
}

export interface EvidenceBindingSetValidationInput {
  readonly executionResultBytes: Uint8Array;
  readonly evidenceProvenanceBytes: Uint8Array;
  readonly freshnessAssessmentBytes: Uint8Array;
  readonly bindingSetBytes: Uint8Array;
}

function bindingDiagnostics(
  binding: ExactRecordBinding,
  expectedContractId: string,
  expectedRecordId: string,
  bytes: Uint8Array,
  path: string,
): readonly EvidenceValidationDiagnostic[] {
  const diagnostics: EvidenceValidationDiagnostic[] = [];
  if (binding.contractId !== expectedContractId) {
    diagnostics.push(diagnostic("BINDING_CONTRACT_MISMATCH", `${path}/contractId`));
  }
  if (binding.recordId !== expectedRecordId) {
    diagnostics.push(diagnostic("BINDING_RECORD_ID_MISMATCH", `${path}/recordId`));
  }
  if (binding.digest.algorithm !== "sha256" || binding.digest.value !== sha256(bytes)) {
    diagnostics.push(diagnostic("BINDING_DIGEST_MISMATCH", `${path}/digest`));
  }
  if (binding.byteLength !== bytes.byteLength) {
    diagnostics.push(diagnostic("BINDING_BYTE_LENGTH_MISMATCH", `${path}/byteLength`));
  }
  return diagnostics;
}

function artifactIdentities(
  artifacts: readonly { readonly artifactId: string; readonly role: ArtifactRole }[],
): readonly { readonly artifactId: string; readonly role: ArtifactRole }[] {
  return artifacts
    .map(({ artifactId, role }) => ({ artifactId, role }))
    .sort((left, right) => compare(left.artifactId, right.artifactId) || compare(left.role, right.role));
}

export function validateEvidenceBindingSet(
  input: EvidenceBindingSetValidationInput,
): EvidenceValidationResult {
  const execution = decodeArtifact<ExecutionResult>(input.executionResultBytes, "/executionResult");
  const provenance = decodeArtifact<EvidenceProvenance>(input.evidenceProvenanceBytes, "/evidenceProvenance");
  const freshness = decodeArtifact<FreshnessAssessment>(input.freshnessAssessmentBytes, "/freshnessAssessment");
  const bindingSet = decodeArtifact<EvidenceBindingSet>(input.bindingSetBytes, "/bindingSet");
  const decodeDiagnostics = [
    ...execution.diagnostics,
    ...provenance.diagnostics,
    ...freshness.diagnostics,
    ...bindingSet.diagnostics,
  ];
  if (
    execution.value === undefined ||
    provenance.value === undefined ||
    freshness.value === undefined ||
    bindingSet.value === undefined
  ) {
    return validationResult(decodeDiagnostics);
  }

  const schema = [
    ...schemaDiagnostics(schemaValidators.execution, execution.value, "/executionResult"),
    ...schemaDiagnostics(schemaValidators.provenance, provenance.value, "/evidenceProvenance"),
    ...schemaDiagnostics(schemaValidators.freshness, freshness.value, "/freshnessAssessment"),
    ...schemaDiagnostics(schemaValidators.bindingSet, bindingSet.value, "/bindingSet"),
  ];
  if (schema.length > 0) return validationResult(schema);

  const diagnostics: EvidenceValidationDiagnostic[] = [
    ...executionSemantics(execution.value, "/executionResult"),
    ...provenanceSemantics(provenance.value, "/evidenceProvenance"),
    ...freshnessSemantics(freshness.value, "/freshnessAssessment"),
    ...bindingDiagnostics(
      provenance.value.executionResult,
      execution.value.schemaVersion,
      execution.value.resultId,
      input.executionResultBytes,
      "/evidenceProvenance/executionResult",
    ),
    ...bindingDiagnostics(
      freshness.value.provenance,
      provenance.value.schemaVersion,
      provenance.value.provenanceId,
      input.evidenceProvenanceBytes,
      "/freshnessAssessment/provenance",
    ),
    ...bindingDiagnostics(
      bindingSet.value.bindings.executionResult,
      execution.value.schemaVersion,
      execution.value.resultId,
      input.executionResultBytes,
      "/bindingSet/bindings/executionResult",
    ),
    ...bindingDiagnostics(
      bindingSet.value.bindings.evidenceProvenance,
      provenance.value.schemaVersion,
      provenance.value.provenanceId,
      input.evidenceProvenanceBytes,
      "/bindingSet/bindings/evidenceProvenance",
    ),
    ...bindingDiagnostics(
      bindingSet.value.bindings.freshnessAssessment,
      freshness.value.schemaVersion,
      freshness.value.assessmentId,
      input.freshnessAssessmentBytes,
      "/bindingSet/bindings/freshnessAssessment",
    ),
  ];

  for (const [left, right, code, path] of [
    [execution.value.subject, provenance.value.subject, "SUBJECT_MISMATCH", "/evidenceProvenance/subject"],
    [execution.value.subject, freshness.value.subject, "SUBJECT_MISMATCH", "/freshnessAssessment/subject"],
    [execution.value.subject, bindingSet.value.subject, "SUBJECT_MISMATCH", "/bindingSet/subject"],
    [execution.value.inputBindings, provenance.value.inputBindings, "INPUT_BINDING_MISMATCH", "/evidenceProvenance/inputBindings"],
    [execution.value.producer, provenance.value.producer, "PRODUCER_MISMATCH", "/evidenceProvenance/producer"],
    [execution.value.tool, provenance.value.tool, "TOOL_MISMATCH", "/evidenceProvenance/tool"],
    [execution.value.environment, provenance.value.environment, "ENVIRONMENT_MISMATCH", "/evidenceProvenance/environment"],
    [execution.value.scope, provenance.value.scope, "SCOPE_MISMATCH", "/evidenceProvenance/scope"],
    [execution.value.scope, freshness.value.scope, "SCOPE_MISMATCH", "/freshnessAssessment/scope"],
    [execution.value.scope, bindingSet.value.scope, "SCOPE_MISMATCH", "/bindingSet/scope"],
    [execution.value.fixtureClassification, provenance.value.fixtureClassification, "FIXTURE_CLASSIFICATION_MISMATCH", "/evidenceProvenance/fixtureClassification"],
    [execution.value.fixtureClassification, freshness.value.fixtureClassification, "FIXTURE_CLASSIFICATION_MISMATCH", "/freshnessAssessment/fixtureClassification"],
    [execution.value.fixtureClassification, bindingSet.value.fixtureClassification, "FIXTURE_CLASSIFICATION_MISMATCH", "/bindingSet/fixtureClassification"],
    [artifactIdentities(execution.value.artifacts), artifactIdentities(provenance.value.artifacts), "ARTIFACT_REFERENCE_MISMATCH", "/evidenceProvenance/artifacts"],
  ] as const) {
    if (!valuesEqual(left, right)) {
      diagnostics.push(diagnostic(code, path));
    }
  }
  return validationResult(diagnostics);
}
