import { createHash } from "node:crypto";

import {
  decodeStrictJsonObject,
  strictJsonDiagnosticCodes,
  strictJsonDiagnosticDescriptions,
  type StrictJsonDiagnostic,
} from "./strict-json.js";

export interface Sha256Digest {
  readonly algorithm: "sha256";
  readonly value: string;
}

export interface GitSha1 {
  readonly algorithm: "git-sha1";
  readonly value: string;
}

export interface SourceIdentity {
  readonly repositoryId: string;
  readonly revision: GitSha1;
  readonly tree: GitSha1;
}

export interface ImplementationIdentity {
  readonly implementationId: string;
  readonly version: string;
  readonly sourceRepositoryId: string;
  readonly sourceRevision: GitSha1;
}

export interface ContractIdentity {
  readonly contractId: string;
  readonly version: string;
}

export interface ManifestContractIdentity {
  readonly contractId: string;
}

export interface SafetyBoundary {
  readonly executable: false;
  readonly networkRequired: false;
  readonly secretsAllowed: false;
}

export type FixtureClassification = "synthetic-test-only";

export type ManifestArtifactType =
  | "contract-schema"
  | "contract-instance"
  | "catalog"
  | "profile"
  | "evidence-requirement"
  | "bridge-context"
  | "bridge-evidence"
  | "documentation"
  | "synthetic-fixture";

interface ManifestArtifactDeclarationBase {
  readonly digest: Sha256Digest;
  readonly mediaType: string;
}

export interface ManifestContractArtifactDeclaration
  extends ManifestArtifactDeclarationBase {
  readonly artifactType: "contract-schema" | "contract-instance";
  readonly contract: ManifestContractIdentity;
}

export interface ManifestNonContractArtifactDeclaration
  extends ManifestArtifactDeclarationBase {
  readonly artifactType: Exclude<
    ManifestArtifactType,
    "contract-schema" | "contract-instance"
  >;
  readonly contract?: ManifestContractIdentity;
}

export type ManifestArtifactDeclaration =
  | ManifestContractArtifactDeclaration
  | ManifestNonContractArtifactDeclaration;

export interface CompatibilitySubject {
  readonly packId: string;
  readonly packVersion: string;
  readonly manifestDigest: Sha256Digest;
  readonly manifestSource: SourceIdentity;
}

export interface CompatibilityTarget {
  readonly implementation: ImplementationIdentity;
  readonly contract: ContractIdentity;
}

export interface PackManifest {
  readonly schemaVersion: "cryptocomm-pack-manifest/v1";
  readonly packId: string;
  readonly packVersion: string;
  readonly source: SourceIdentity;
  readonly producer: ImplementationIdentity;
  readonly artifacts: Readonly<Record<string, ManifestArtifactDeclaration>>;
  readonly safety: SafetyBoundary;
  readonly fixtureClassification?: FixtureClassification;
}

export interface CompatibilityRecordReference {
  readonly digest: Sha256Digest;
  readonly subject: CompatibilitySubject;
  readonly target: CompatibilityTarget;
}

export interface PackLock {
  readonly schemaVersion: "cryptocomm-pack-lock/v1";
  readonly packId: string;
  readonly packVersion: string;
  readonly manifest: {
    readonly digest: Sha256Digest;
    readonly source: SourceIdentity;
  };
  readonly resolver: ImplementationIdentity;
  readonly compatibilityRecords?: Readonly<Record<string, CompatibilityRecordReference>>;
  readonly safety: SafetyBoundary;
  readonly fixtureClassification?: FixtureClassification;
}

export type CompatibilityState = "unknown" | "compatible" | "incompatible" | "unsupported";

export type CompatibilityEvidenceType =
  | "synthetic-test-result"
  | "public-test-result"
  | "public-analysis-report";

export interface CompatibilityEvidenceReference {
  readonly digest: Sha256Digest;
  readonly mediaType: string;
  readonly evidenceType: CompatibilityEvidenceType;
}

export interface UnsupportedCompatibilityReason {
  readonly reason: string;
  readonly scope: string;
}

interface CompatibilityRecordBase {
  readonly schemaVersion: "cryptocomm-compatibility-record/v1";
  readonly recordId: string;
  readonly subject: CompatibilitySubject;
  readonly target: CompatibilityTarget;
  readonly safety: SafetyBoundary;
  readonly fixtureClassification?: FixtureClassification;
}

export interface UnknownCompatibilityRecord extends CompatibilityRecordBase {
  readonly state: "unknown";
  readonly evidence?: never;
  readonly unsupported?: never;
}

export interface AssessedCompatibilityRecord extends CompatibilityRecordBase {
  readonly state: "compatible" | "incompatible";
  readonly evidence: Readonly<Record<string, CompatibilityEvidenceReference>>;
  readonly unsupported?: never;
}

export interface UnsupportedCompatibilityRecord extends CompatibilityRecordBase {
  readonly state: "unsupported";
  readonly evidence?: Readonly<Record<string, CompatibilityEvidenceReference>>;
  readonly unsupported: UnsupportedCompatibilityReason;
}

export type CompatibilityRecord =
  | UnknownCompatibilityRecord
  | AssessedCompatibilityRecord
  | UnsupportedCompatibilityRecord;

export interface PackResolutionInput {
  readonly manifestBytes: Uint8Array;
  readonly lockBytes: Uint8Array;
  readonly compatibilityRecordBytes: Readonly<Record<string, Uint8Array>>;
}

export const semanticDiagnosticCodes = [
  ...strictJsonDiagnosticCodes,
  "MANIFEST_DIGEST_MISMATCH",
  "PACK_ID_MISMATCH",
  "PACK_VERSION_MISMATCH",
  "SOURCE_IDENTITY_MISMATCH",
  "IMPLEMENTATION_IDENTITY_INVALID",
  "COMPATIBILITY_RECORD_LIMIT_EXCEEDED",
  "COMPATIBILITY_RECORD_MISSING",
  "COMPATIBILITY_RECORD_UNREFERENCED",
  "COMPATIBILITY_RECORD_ID_MISMATCH",
  "COMPATIBILITY_RECORD_DIGEST_MISMATCH",
  "COMPATIBILITY_SUBJECT_MISMATCH",
  "COMPATIBILITY_TARGET_MISMATCH",
  "COMPATIBILITY_PAIR_DUPLICATE",
  "COMPATIBILITY_EVIDENCE_REQUIRED",
  "LEGACY_STATUS_MIGRATION_FORBIDDEN",
] as const;

export type SemanticDiagnosticCode = (typeof semanticDiagnosticCodes)[number];

export const semanticDiagnosticDescriptions: Readonly<Record<SemanticDiagnosticCode, string>> = {
  ...strictJsonDiagnosticDescriptions,
  MANIFEST_DIGEST_MISMATCH: "The lock does not bind the exact supplied manifest bytes.",
  PACK_ID_MISMATCH: "The pack identifier differs across bound artifacts.",
  PACK_VERSION_MISMATCH: "The pack version differs across bound artifacts.",
  SOURCE_IDENTITY_MISMATCH: "The repository, revision, or source tree identity differs.",
  IMPLEMENTATION_IDENTITY_INVALID:
    "A producer, resolver, or target implementation identity is incomplete or not exact.",
  COMPATIBILITY_RECORD_LIMIT_EXCEEDED:
    "More than 256 compatibility-record byte entries were supplied; validation fails with one bounded aggregate diagnostic.",
  COMPATIBILITY_RECORD_MISSING: "A lock reference has no supplied compatibility record.",
  COMPATIBILITY_RECORD_UNREFERENCED:
    "A supplied compatibility record is not declared by the lock.",
  COMPATIBILITY_RECORD_ID_MISMATCH:
    "A lock reference key differs from the supplied compatibility record identifier.",
  COMPATIBILITY_RECORD_DIGEST_MISMATCH:
    "A lock reference does not bind the exact supplied compatibility-record bytes.",
  COMPATIBILITY_SUBJECT_MISMATCH:
    "A compatibility subject differs from the exact manifest identity.",
  COMPATIBILITY_TARGET_MISMATCH:
    "A compatibility target differs between the lock reference and record.",
  COMPATIBILITY_PAIR_DUPLICATE:
    "A lock references more than one compatibility record for the same exact subject and target pair.",
  COMPATIBILITY_EVIDENCE_REQUIRED:
    "Compatible and incompatible states require at least one content-addressed evidence reference.",
  LEGACY_STATUS_MIGRATION_FORBIDDEN:
    "The only accepted legacy mapping is planned to unknown; every other legacy/new-state combination fails closed.",
};

export interface SemanticDiagnostic {
  readonly code: SemanticDiagnosticCode;
  readonly path: string;
  readonly message: string;
}

export interface SemanticValidationSuccess {
  readonly valid: true;
  readonly diagnostics: readonly [];
}

export interface SemanticValidationFailure {
  readonly valid: false;
  readonly diagnostics: readonly SemanticDiagnostic[];
}

export type SemanticValidationResult = SemanticValidationSuccess | SemanticValidationFailure;

const repositoryIdPattern =
  /^[a-z][a-z0-9.-]{0,31}:[A-Za-z0-9][A-Za-z0-9._-]{0,127}(?:\/[A-Za-z0-9][A-Za-z0-9._-]{0,127})+$/;
const implementationIdPattern = /^[a-z][a-z0-9.-]*(?:\/[a-z0-9][a-z0-9._-]*)+$/;
const gitSha1Pattern = /^[0-9a-f]{40}$/;

function isAsciiDigit(code: number): boolean {
  return code >= 0x30 && code <= 0x39;
}

function isSemverIdentifierCharacter(code: number): boolean {
  return (
    isAsciiDigit(code) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    code === 0x2d
  );
}

function identifierCharactersValid(value: string): boolean {
  if (value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (!isSemverIdentifierCharacter(value.charCodeAt(index))) return false;
  }
  return true;
}

function numericIdentifierValid(value: string): boolean {
  if (value.length === 0 || (value.length > 1 && value.startsWith("0"))) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (!isAsciiDigit(value.charCodeAt(index))) return false;
  }
  return true;
}

function prereleaseIdentifierValid(value: string): boolean {
  if (!identifierCharactersValid(value)) return false;
  let numeric = true;
  for (let index = 0; index < value.length; index += 1) {
    if (!isAsciiDigit(value.charCodeAt(index))) {
      numeric = false;
      break;
    }
  }
  return !numeric || numericIdentifierValid(value);
}

function semanticVersionValid(value: string): boolean {
  if (value.length === 0 || value.length > 64) return false;

  const buildSeparator = value.indexOf("+");
  if (buildSeparator !== value.lastIndexOf("+")) return false;
  const coreAndPrerelease =
    buildSeparator === -1 ? value : value.slice(0, buildSeparator);
  if (buildSeparator !== -1) {
    const build = value.slice(buildSeparator + 1);
    if (!build.split(".").every(identifierCharactersValid)) return false;
  }

  const prereleaseSeparator = coreAndPrerelease.indexOf("-");
  const core =
    prereleaseSeparator === -1
      ? coreAndPrerelease
      : coreAndPrerelease.slice(0, prereleaseSeparator);
  if (prereleaseSeparator !== -1) {
    const prerelease = coreAndPrerelease.slice(prereleaseSeparator + 1);
    if (!prerelease.split(".").every(prereleaseIdentifierValid)) return false;
  }

  const coreIdentifiers = core.split(".");
  return coreIdentifiers.length === 3 && coreIdentifiers.every(numericIdentifierValid);
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

const maximumCompatibilityRecordCount = 256;

function boundedOwnKeys(
  value: Readonly<Record<string, unknown>>,
  maximum: number,
): { readonly keys: readonly string[]; readonly exceeded: boolean } {
  const keys: string[] = [];
  for (const key in value) {
    if (!Object.hasOwn(value, key)) continue;
    if (keys.length === maximum) return { keys, exceeded: true };
    keys.push(key);
  }
  return { keys, exceeded: false };
}

function prefixedStrictDiagnostics(
  diagnostics: readonly StrictJsonDiagnostic[],
  prefix: string,
): readonly SemanticDiagnostic[] {
  return diagnostics.map((entry) => ({
    code: entry.code,
    path: prefix + entry.path,
    message: entry.message,
  }));
}

function sourceIdentityEqual(left: SourceIdentity, right: SourceIdentity): boolean {
  return (
    left.repositoryId === right.repositoryId &&
    left.revision.algorithm === right.revision.algorithm &&
    left.revision.value === right.revision.value &&
    left.tree.algorithm === right.tree.algorithm &&
    left.tree.value === right.tree.value
  );
}

function implementationIdentityEqual(
  left: ImplementationIdentity,
  right: ImplementationIdentity,
): boolean {
  return (
    left.implementationId === right.implementationId &&
    left.version === right.version &&
    left.sourceRepositoryId === right.sourceRepositoryId &&
    left.sourceRevision.algorithm === right.sourceRevision.algorithm &&
    left.sourceRevision.value === right.sourceRevision.value
  );
}

function implementationIdentityValid(identity: ImplementationIdentity): boolean {
  return (
    implementationIdPattern.test(identity.implementationId) &&
    semanticVersionValid(identity.version) &&
    repositoryIdPattern.test(identity.sourceRepositoryId) &&
    identity.sourceRevision.algorithm === "git-sha1" &&
    gitSha1Pattern.test(identity.sourceRevision.value)
  );
}

function digestEqual(left: Sha256Digest, right: Sha256Digest): boolean {
  return left.algorithm === right.algorithm && left.value === right.value;
}

function subjectEqual(left: CompatibilitySubject, right: CompatibilitySubject): boolean {
  return (
    left.packId === right.packId &&
    left.packVersion === right.packVersion &&
    digestEqual(left.manifestDigest, right.manifestDigest) &&
    sourceIdentityEqual(left.manifestSource, right.manifestSource)
  );
}

function targetEqual(left: CompatibilityTarget, right: CompatibilityTarget): boolean {
  return (
    implementationIdentityEqual(left.implementation, right.implementation) &&
    left.contract.contractId === right.contract.contractId &&
    left.contract.version === right.contract.version
  );
}

function diagnostic(code: SemanticDiagnosticCode, path: string): SemanticDiagnostic {
  return { code, path, message: semanticDiagnosticDescriptions[code] };
}

function result(diagnostics: readonly SemanticDiagnostic[]): SemanticValidationResult {
  const unique = new Map<string, SemanticDiagnostic>();
  for (const entry of diagnostics) {
    unique.set(entry.code + "\u0000" + entry.path, entry);
  }
  const compare = (left: string, right: string): number =>
    left < right ? -1 : left > right ? 1 : 0;
  const stable = [...unique.values()].sort(
    (left, right) => compare(left.code, right.code) || compare(left.path, right.path),
  );
  return stable.length === 0
    ? { valid: true, diagnostics: [] }
    : { valid: false, diagnostics: stable };
}

function expectedSubject(
  manifest: PackManifest,
  manifestBytes: Uint8Array,
): CompatibilitySubject {
  return {
    packId: manifest.packId,
    packVersion: manifest.packVersion,
    manifestDigest: {
      algorithm: "sha256",
      value: sha256(manifestBytes),
    },
    manifestSource: manifest.source,
  };
}

export function validateManifestLockBinding(
  manifestBytes: Uint8Array,
  lockBytes: Uint8Array,
): SemanticValidationResult {
  const diagnostics: SemanticDiagnostic[] = [];
  const manifest = decodeStrictJsonObject<PackManifest>(manifestBytes);
  const lock = decodeStrictJsonObject<PackLock>(lockBytes);

  if (!manifest.valid) {
    diagnostics.push(...prefixedStrictDiagnostics(manifest.diagnostics, "/manifest"));
  }
  if (!lock.valid) {
    diagnostics.push(...prefixedStrictDiagnostics(lock.diagnostics, "/lock"));
  }
  if (!manifest.valid || !lock.valid) {
    return result(diagnostics);
  }

  return validateManifestLockBindingParsed(manifest.value, manifestBytes, lock.value);
}

function validateManifestLockBindingParsed(
  manifest: PackManifest,
  manifestBytes: Uint8Array,
  lock: PackLock,
): SemanticValidationResult {
  const diagnostics: SemanticDiagnostic[] = [];
  const actualManifestDigest = sha256(manifestBytes);

  if (
    lock.manifest.digest.algorithm !== "sha256" ||
    lock.manifest.digest.value !== actualManifestDigest
  ) {
    diagnostics.push(diagnostic("MANIFEST_DIGEST_MISMATCH", "/manifest/digest"));
  }
  if (lock.packId !== manifest.packId) {
    diagnostics.push(diagnostic("PACK_ID_MISMATCH", "/packId"));
  }
  if (lock.packVersion !== manifest.packVersion) {
    diagnostics.push(diagnostic("PACK_VERSION_MISMATCH", "/packVersion"));
  }
  if (!sourceIdentityEqual(lock.manifest.source, manifest.source)) {
    diagnostics.push(diagnostic("SOURCE_IDENTITY_MISMATCH", "/manifest/source"));
  }
  if (!implementationIdentityValid(manifest.producer)) {
    diagnostics.push(diagnostic("IMPLEMENTATION_IDENTITY_INVALID", "/producer"));
  }
  if (!implementationIdentityValid(lock.resolver)) {
    diagnostics.push(diagnostic("IMPLEMENTATION_IDENTITY_INVALID", "/resolver"));
  }

  return result(diagnostics);
}

export function validateCompatibilityRecordBinding(
  manifestBytes: Uint8Array,
  recordBytes: Uint8Array,
): SemanticValidationResult {
  const diagnostics: SemanticDiagnostic[] = [];
  const manifest = decodeStrictJsonObject<PackManifest>(manifestBytes);
  const record = decodeStrictJsonObject<CompatibilityRecord>(recordBytes);

  if (!manifest.valid) {
    diagnostics.push(...prefixedStrictDiagnostics(manifest.diagnostics, "/manifest"));
  }
  if (!record.valid) {
    diagnostics.push(...prefixedStrictDiagnostics(record.diagnostics, "/record"));
  }
  if (!manifest.valid || !record.valid) {
    return result(diagnostics);
  }

  return validateCompatibilityRecordBindingParsed(
    manifest.value,
    manifestBytes,
    record.value,
  );
}

function validateCompatibilityRecordBindingParsed(
  manifest: PackManifest,
  manifestBytes: Uint8Array,
  record: CompatibilityRecord,
): SemanticValidationResult {
  const diagnostics: SemanticDiagnostic[] = [];

  if (!subjectEqual(record.subject, expectedSubject(manifest, manifestBytes))) {
    diagnostics.push(diagnostic("COMPATIBILITY_SUBJECT_MISMATCH", "/subject"));
  }
  if (!implementationIdentityValid(record.target.implementation)) {
    diagnostics.push(
      diagnostic("IMPLEMENTATION_IDENTITY_INVALID", "/target/implementation"),
    );
  }
  if (
    (record.state === "compatible" || record.state === "incompatible") &&
    Object.keys(record.evidence ?? {}).length === 0
  ) {
    diagnostics.push(diagnostic("COMPATIBILITY_EVIDENCE_REQUIRED", "/evidence"));
  }

  return result(diagnostics);
}

function validateUniqueCompatibilityPairs(
  references: Readonly<Record<string, CompatibilityRecordReference>>,
  recordIds: readonly string[],
): readonly SemanticDiagnostic[] {
  const diagnostics: SemanticDiagnostic[] = [];
  const seen: Array<{
    readonly recordId: string;
    readonly reference: CompatibilityRecordReference;
  }> = [];

  for (const recordId of recordIds) {
    const reference = references[recordId];
    if (reference === undefined) continue;
    const duplicate = seen.find(
      (entry) =>
        subjectEqual(entry.reference.subject, reference.subject) &&
        targetEqual(entry.reference.target, reference.target),
    );
    if (duplicate !== undefined) {
      diagnostics.push(
        diagnostic(
          "COMPATIBILITY_PAIR_DUPLICATE",
          "/lock/compatibilityRecords/" + recordId,
        ),
      );
      continue;
    }
    seen.push({ recordId, reference });
  }

  return diagnostics;
}

export function validatePackResolution(input: PackResolutionInput): SemanticValidationResult {
  const diagnostics: SemanticDiagnostic[] = [];
  const manifest = decodeStrictJsonObject<PackManifest>(input.manifestBytes);
  const lock = decodeStrictJsonObject<PackLock>(input.lockBytes);

  if (!manifest.valid) {
    diagnostics.push(...prefixedStrictDiagnostics(manifest.diagnostics, "/manifest"));
  }
  if (!lock.valid) {
    diagnostics.push(...prefixedStrictDiagnostics(lock.diagnostics, "/lock"));
    return result(diagnostics);
  }
  if (manifest.valid) {
    diagnostics.push(
      ...validateManifestLockBindingParsed(
        manifest.value,
        input.manifestBytes,
        lock.value,
      ).diagnostics,
    );
  }

  const references = lock.value.compatibilityRecords ?? {};
  const referenceKeyScan = boundedOwnKeys(references, maximumCompatibilityRecordCount);
  if (referenceKeyScan.exceeded) {
    diagnostics.push(
      diagnostic(
        "COMPATIBILITY_RECORD_LIMIT_EXCEEDED",
        "/lock/compatibilityRecords",
      ),
    );
    return result(diagnostics);
  }
  const referenceIds = [...referenceKeyScan.keys].sort();
  diagnostics.push(...validateUniqueCompatibilityPairs(references, referenceIds));

  const suppliedKeyScan = boundedOwnKeys(
    input.compatibilityRecordBytes,
    maximumCompatibilityRecordCount,
  );
  if (suppliedKeyScan.exceeded) {
    diagnostics.push(
      diagnostic("COMPATIBILITY_RECORD_LIMIT_EXCEEDED", "/compatibilityRecordBytes"),
    );
  } else {
    for (const recordId of [...suppliedKeyScan.keys].sort()) {
      if (references[recordId] === undefined) {
        diagnostics.push(
          diagnostic(
            "COMPATIBILITY_RECORD_UNREFERENCED",
            "/compatibilityRecordBytes/" + recordId,
          ),
        );
      }
    }
  }

  for (const recordId of referenceIds) {
    const reference = references[recordId];
    if (reference === undefined) continue;
    const suppliedBytes = Object.hasOwn(input.compatibilityRecordBytes, recordId)
      ? input.compatibilityRecordBytes[recordId]
      : undefined;
    if (suppliedBytes === undefined) {
      diagnostics.push(
        diagnostic(
          "COMPATIBILITY_RECORD_MISSING",
          "/lock/compatibilityRecords/" + recordId,
        ),
      );
      continue;
    }

    const record = decodeStrictJsonObject<CompatibilityRecord>(suppliedBytes);
    if (!record.valid) {
      diagnostics.push(
        ...prefixedStrictDiagnostics(
          record.diagnostics,
          "/lock/compatibilityRecords/" + recordId,
        ),
      );
      continue;
    }

    if (
      reference.digest.algorithm !== "sha256" ||
      reference.digest.value !== sha256(suppliedBytes)
    ) {
      diagnostics.push(
        diagnostic(
          "COMPATIBILITY_RECORD_DIGEST_MISMATCH",
          "/lock/compatibilityRecords/" + recordId + "/digest",
        ),
      );
    }

    if (record.value.recordId !== recordId) {
      diagnostics.push(
        diagnostic(
          "COMPATIBILITY_RECORD_ID_MISMATCH",
          "/lock/compatibilityRecords/" + recordId,
        ),
      );
    }
    if (!subjectEqual(reference.subject, record.value.subject)) {
      diagnostics.push(
        diagnostic(
          "COMPATIBILITY_SUBJECT_MISMATCH",
          "/lock/compatibilityRecords/" + recordId + "/subject",
        ),
      );
    }
    if (!targetEqual(reference.target, record.value.target)) {
      diagnostics.push(
        diagnostic(
          "COMPATIBILITY_TARGET_MISMATCH",
          "/lock/compatibilityRecords/" + recordId + "/target",
        ),
      );
    }
    if (manifest.valid) {
      diagnostics.push(
        ...validateCompatibilityRecordBindingParsed(
          manifest.value,
          input.manifestBytes,
          record.value,
        ).diagnostics.map((entry) => ({
          ...entry,
          path: "/lock/compatibilityRecords/" + recordId + entry.path,
        })),
      );
    }
  }

  return result(diagnostics);
}

export function validateLegacyCompatibilityMigration(
  legacyStatus: "planned" | "compatible" | "unsupported",
  migratedState: CompatibilityState,
): SemanticValidationResult {
  return legacyStatus === "planned" && migratedState === "unknown"
    ? result([])
    : result([
        diagnostic("LEGACY_STATUS_MIGRATION_FORBIDDEN", "/compatibility/state"),
      ]);
}
