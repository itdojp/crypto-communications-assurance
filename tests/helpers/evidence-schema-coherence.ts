import { isDeepStrictEqual } from "node:util";

/** The deliberately shared CCA-240 definitions, not each contract's local defs. */
export const sharedEvidenceDefinitionNames = [
  "boundedId",
  "recordId",
  "contractId",
  "version",
  "repositoryId",
  "gitSha1",
  "sha256Digest",
  "mediaType",
  "timestamp",
  "reasonCode",
  "boundedText",
  "authorityId",
  "exactBinding",
  "exactContentBinding",
  "bindingFingerprint",
  "contractIdentity",
  "manifestSubject",
  "gitSubject",
  "contractArtifactSubject",
  "subject",
  "inputBinding",
  "inputBindings",
  "softwareIdentity",
  "softwareProducer",
  "humanProducer",
  "producer",
  "identifiedTool",
  "notApplicableTool",
  "tool",
  "recordedEnvironment",
  "notRecordedEnvironment",
  "environment",
  "scope",
  "safety",
  "diagnostic",
  "diagnostics",
] as const;

export interface EvidenceSchemaSnapshot {
  readonly name: string;
  readonly schema: Readonly<Record<string, unknown>>;
}

export interface EvidenceDefinitionDrift {
  readonly schema: string;
  readonly definition: string;
  readonly kind: "missing-definitions" | "missing-definition" | "different-definition";
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Test-only comparison of strict-decoded repository schemas. This is neither
 * schema validation nor a general-purpose public/untrusted-object API.
 * Object key order is irrelevant; array order and every value remain significant.
 */
export function evidenceDefinitionDrift(
  snapshots: readonly EvidenceSchemaSnapshot[],
): readonly EvidenceDefinitionDrift[] {
  const failures: EvidenceDefinitionDrift[] = [];
  const valid: Array<{
    readonly name: string;
    readonly definitions: Readonly<Record<string, unknown>>;
  }> = [];

  for (const { name, schema } of snapshots) {
    const definitions = schema.$defs;
    if (!Object.hasOwn(schema, "$defs") || !isRecord(definitions)) {
      failures.push({ schema: name, definition: "$defs", kind: "missing-definitions" });
    } else {
      valid.push({ name, definitions });
    }
  }

  // Select a stable comparison baseline, not an authority that proves correctness.
  valid.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  for (const definition of sharedEvidenceDefinitionNames) {
    const reference = valid.find(({ definitions }) => Object.hasOwn(definitions, definition));
    for (const { name, definitions } of valid) {
      if (!Object.hasOwn(definitions, definition)) {
        failures.push({ schema: name, definition, kind: "missing-definition" });
      } else if (
        reference !== undefined &&
        !isDeepStrictEqual(definitions[definition], reference.definitions[definition])
      ) {
        failures.push({ schema: name, definition, kind: "different-definition" });
      }
    }
  }
  return failures;
}
