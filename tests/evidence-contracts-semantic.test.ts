import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { describe, expect, it, vi } from "vitest";

import {
  assessFreshness,
  decodeStrictJsonObject,
  serializeEvidenceContract,
  validateEvidenceBindingSet,
  validateEvidenceProvenance,
  validateExecutionResult,
  validateFreshnessAssessment,
  type EvidenceBindingSet,
  type EvidenceDiagnosticCode,
  type EvidenceProvenance,
  type ExecutionResult,
  type FreshnessAssessment,
  type FreshnessAssessmentRequest,
  type FreshnessDimensionName,
  type LifecycleFactRequest,
} from "../packages/contracts/src/index.js";

const loadBytes = (relativePath: string): Promise<Buffer> =>
  readFile(new URL(relativePath, import.meta.url));
const loadStrict = async <T extends object>(relativePath: string): Promise<T> => {
  const decoded = decodeStrictJsonObject<T>(await loadBytes(relativePath));
  if (!decoded.valid) throw new Error(`${relativePath}: strict decode failed`);
  return decoded.value;
};
const codes = (result: {
  readonly diagnostics: readonly { readonly code: EvidenceDiagnosticCode }[];
}): readonly EvidenceDiagnosticCode[] => result.diagnostics.map(({ code }) => code);
const exactRecordBinding = (
  contractId: string,
  recordId: string,
  bytes: Uint8Array,
) => ({
  contractId,
  recordId,
  digest: {
    algorithm: "sha256" as const,
    value: createHash("sha256").update(bytes).digest("hex"),
  },
  byteLength: bytes.byteLength,
});

const baseBindingInput = async () => ({
  executionResultBytes: await loadBytes("../fixtures/valid/cca-240/execution-pass-v1.json"),
  evidenceProvenanceBytes: await loadBytes(
    "../fixtures/valid/cca-240/provenance-public-synthetic-test-only-v1.json",
  ),
  freshnessAssessmentBytes: await loadBytes(
    "../fixtures/valid/cca-240/freshness-fresh-v1.json",
  ),
  bindingSetBytes: await loadBytes(
    "../fixtures/valid/cca-240/evidence-binding-set-complete-v1.json",
  ),
});

function requestFromAssessment(value: FreshnessAssessment): FreshnessAssessmentRequest {
  const dimensions = Object.fromEntries(
    Object.entries(value.dimensions).map(([name, entry]) => {
      if (!entry.selected) return [name, { selected: false }];
      if (entry.availability === "unavailable") {
        return [name, { selected: true, availability: "unavailable", expected: entry.expected }];
      }
      return [
        name,
        {
          selected: true,
          availability: "available",
          expected: entry.expected,
          observed: entry.observed,
        },
      ];
    }),
  ) as unknown as Readonly<Record<FreshnessDimensionName, FreshnessAssessmentRequest["dimensions"][FreshnessDimensionName]>>;
  const lifecycle = (entry: FreshnessAssessment["validity"]["revocation"]): LifecycleFactRequest => {
    if (!entry.selected) return { selected: false };
    if (entry.availability === "unavailable") {
      return {
        selected: true,
        authorityId: entry.authorityId,
        availability: "unavailable",
      };
    }
    return {
      selected: true,
      authorityId: entry.authorityId,
      availability: "available",
      applies: entry.applies,
    };
  };
  const time = value.validity.time.selected
    ? {
        selected: true as const,
        clockTrust: value.validity.time.clockTrust,
        validity: value.validity.time.validity,
      }
    : { selected: false as const };
  return {
    assessmentId: value.assessmentId,
    provenance: value.provenance,
    subject: value.subject,
    scope: value.scope,
    intent: value.intent,
    asOf: value.asOf,
    dimensions,
    validity: {
      time,
      supersession: lifecycle(value.validity.supersession),
      revocation: lifecycle(value.validity.revocation),
      invalidation: lifecycle(value.validity.invalidation),
    },
    ...(value.fixtureClassification === undefined
      ? {}
      : { fixtureClassification: value.fixtureClassification }),
    safety: value.safety,
  };
}

describe("CCA-240 semantic validation and deterministic assessment", () => {
  it("validates every positive result, provenance, and freshness fixture semantically", async () => {
    for (const file of [
      "execution-pass-v1.json",
      "execution-fail-v1.json",
      "execution-skip-v1.json",
      "execution-unsupported-v1.json",
      "execution-timeout-v1.json",
      "execution-tool-error-preflight-v1.json",
      "execution-tool-error-execution-v1.json",
      "execution-tool-error-post-processing-v1.json",
      "execution-not-run-v1.json",
      "execution-pass-manifest-subject-v1.json",
      "execution-not-run-human-producer-v1.json",
    ]) {
      expect(validateExecutionResult(await loadBytes(`../fixtures/valid/cca-240/${file}`)), file).toEqual({ valid: true, diagnostics: [] });
    }
    for (const file of [
      "provenance-public-synthetic-test-only-v1.json",
      "provenance-private-synthetic-test-only-v1.json",
      "provenance-human-no-tool-no-environment-v1.json",
    ]) {
      expect(validateEvidenceProvenance(await loadBytes(`../fixtures/valid/cca-240/${file}`)), file).toEqual({ valid: true, diagnostics: [] });
    }
    for (const state of ["fresh", "stale", "mismatched", "unknown", "not-assessed"]) {
      expect(validateFreshnessAssessment(await loadBytes(`../fixtures/valid/cca-240/freshness-${state}-v1.json`)), state).toEqual({ valid: true, diagnostics: [] });
    }
  });

  it("validates the complete exact-byte composition root", async () => {
    expect(validateEvidenceBindingSet(await baseBindingInput())).toEqual({ valid: true, diagnostics: [] });
  });

  it("propagates synthetic/test-only fixture classification through the exact binding chain", async () => {
    const executionResultBytes = await loadBytes(
      "../fixtures/valid/cca-240/execution-pass-v1.json",
    );
    const markedProvenance = await loadStrict<EvidenceProvenance>(
      "../fixtures/valid/cca-240/provenance-public-synthetic-test-only-v1.json",
    );
    const {
      fixtureClassification: provenanceFixtureClassification,
      ...unmarkedProvenance
    } = markedProvenance;
    expect(provenanceFixtureClassification).toBe("synthetic-test-only");
    const provenance: EvidenceProvenance = {
      ...unmarkedProvenance,
      evidenceOrigin: "real",
      useRestriction: "policy-evaluable",
    };
    const evidenceProvenanceBytes = serializeEvidenceContract(provenance);
    expect(validateEvidenceProvenance(evidenceProvenanceBytes)).toEqual({
      valid: true,
      diagnostics: [],
    });

    const freshness = await loadStrict<FreshnessAssessment>(
      "../fixtures/valid/cca-240/freshness-fresh-v1.json",
    );
    const freshnessAssessmentBytes = serializeEvidenceContract({
      ...freshness,
      provenance: exactRecordBinding(
        provenance.schemaVersion,
        provenance.provenanceId,
        evidenceProvenanceBytes,
      ),
    });
    const bindingSet = await loadStrict<EvidenceBindingSet>(
      "../fixtures/valid/cca-240/evidence-binding-set-complete-v1.json",
    );
    const bindingSetBytes = serializeEvidenceContract({
      ...bindingSet,
      bindings: {
        executionResult: exactRecordBinding(
          "cryptocomm-execution-result/v1",
          "result.synthetic.pass",
          executionResultBytes,
        ),
        evidenceProvenance: exactRecordBinding(
          provenance.schemaVersion,
          provenance.provenanceId,
          evidenceProvenanceBytes,
        ),
        freshnessAssessment: exactRecordBinding(
          freshness.schemaVersion,
          freshness.assessmentId,
          freshnessAssessmentBytes,
        ),
      },
    });

    const result = validateEvidenceBindingSet({
      executionResultBytes,
      evidenceProvenanceBytes,
      freshnessAssessmentBytes,
      bindingSetBytes,
    });
    expect(result.valid).toBe(false);
    expect(result.diagnostics).toEqual([
      expect.objectContaining({
        code: "FIXTURE_CLASSIFICATION_MISMATCH",
        path: "/evidenceProvenance/fixtureClassification",
      }),
    ]);

    const validInput = await baseBindingInput();
    const {
      fixtureClassification: _freshnessFixtureClassification,
      ...unmarkedFreshness
    } = freshness;
    expect(_freshnessFixtureClassification).toBe("synthetic-test-only");
    const unmarkedFreshnessBytes = serializeEvidenceContract(unmarkedFreshness);
    const bindingForUnmarkedFreshness = serializeEvidenceContract({
      ...bindingSet,
      bindings: {
        ...bindingSet.bindings,
        freshnessAssessment: exactRecordBinding(
          freshness.schemaVersion,
          freshness.assessmentId,
          unmarkedFreshnessBytes,
        ),
      },
    });
    expect(
      validateEvidenceBindingSet({
        ...validInput,
        freshnessAssessmentBytes: unmarkedFreshnessBytes,
        bindingSetBytes: bindingForUnmarkedFreshness,
      }).diagnostics,
    ).toEqual([
      expect.objectContaining({
        code: "FIXTURE_CLASSIFICATION_MISMATCH",
        path: "/freshnessAssessment/fixtureClassification",
      }),
    ]);

    const {
      fixtureClassification: _bindingFixtureClassification,
      ...unmarkedBindingSet
    } = bindingSet;
    expect(_bindingFixtureClassification).toBe("synthetic-test-only");
    expect(
      validateEvidenceBindingSet({
        ...validInput,
        bindingSetBytes: serializeEvidenceContract(unmarkedBindingSet),
      }).diagnostics,
    ).toEqual([
      expect.objectContaining({
        code: "FIXTURE_CLASSIFICATION_MISMATCH",
        path: "/bindingSet/fixtureClassification",
      }),
    ]);
  });

  it.each([
    ["provenance-subject-mismatch.json", "SUBJECT_MISMATCH"],
    ["provenance-input-mismatch.json", "INPUT_BINDING_MISMATCH"],
    ["provenance-producer-mismatch.json", "PRODUCER_MISMATCH"],
    ["provenance-tool-mismatch.json", "TOOL_MISMATCH"],
    ["provenance-environment-mismatch.json", "ENVIRONMENT_MISMATCH"],
    ["provenance-scope-mismatch.json", "SCOPE_MISMATCH"],
    ["provenance-contract-mismatch.json", "CONTRACT_SCHEMA_INVALID"],
  ] as const)("rejects cross-contract mismatch %s", async (file, expected) => {
    const input = await baseBindingInput();
    const result = validateEvidenceBindingSet({
      ...input,
      evidenceProvenanceBytes: await loadBytes(`../fixtures/invalid/cca-240/${file}`),
    });
    expect(result.valid).toBe(false);
    expect(codes(result)).toContain(expected);
  });

  it.each([
    ["binding-set-digest-mismatch.json", "BINDING_DIGEST_MISMATCH"],
    ["binding-set-subject-mismatch.json", "SUBJECT_MISMATCH"],
    ["binding-set-scope-mismatch.json", "SCOPE_MISMATCH"],
    ["binding-set-missing-freshness.json", "CONTRACT_SCHEMA_INVALID"],
  ] as const)("rejects binding-root mismatch %s", async (file, expected) => {
    const input = await baseBindingInput();
    const result = validateEvidenceBindingSet({
      ...input,
      bindingSetBytes: await loadBytes(`../fixtures/invalid/cca-240/${file}`),
    });
    expect(result.valid).toBe(false);
    expect(codes(result)).toContain(expected);
  });

  it.each([
    "freshness-decision-order-mismatch-as-stale.json",
    "freshness-stale-reported-fresh.json",
    "freshness-unknown-reported-fresh.json",
    "freshness-untrusted-clock-reported-fresh.json",
    "freshness-dependency-mismatch-reported-fresh.json",
  ])("rejects a freshness state that contradicts explicit facts: %s", async (file) => {
    const result = validateFreshnessAssessment(
      await loadBytes(`../fixtures/invalid/cca-240/${file}`),
    );
    expect(result.valid).toBe(false);
    expect(codes(result)).toContain("FRESHNESS_STATE_INCONSISTENT");
  });

  it("applies all five states and the approved decision order from caller facts", async () => {
    for (const state of ["fresh", "stale", "mismatched", "unknown", "not-assessed"] as const) {
      const fixture = await loadStrict<FreshnessAssessment>(
        `../fixtures/valid/cca-240/freshness-${state}-v1.json`,
      );
      const result = assessFreshness(requestFromAssessment(fixture));
      expect(result.valid, state).toBe(true);
      if (!result.valid) continue;
      expect(result.assessment.state).toBe(state);
      expect(Buffer.from(result.bytes)).toEqual(
        await loadBytes(`../fixtures/valid/cca-240/freshness-${state}-v1.json`),
      );
    }
  });

  it("makes mismatch outrank revocation and stale outrank unavailable facts", async () => {
    const mismatch = await loadStrict<FreshnessAssessment>(
      "../fixtures/valid/cca-240/freshness-mismatched-v1.json",
    );
    expect(assessFreshness(requestFromAssessment(mismatch))).toMatchObject({
      valid: true,
      assessment: { state: "mismatched" },
    });
    const stale = await loadStrict<FreshnessAssessment>(
      "../fixtures/valid/cca-240/freshness-stale-v1.json",
    );
    const request = requestFromAssessment(stale);
    const withUnknown = {
      ...request,
      dimensions: {
        ...request.dimensions,
        tool: {
          selected: true as const,
          availability: "unavailable" as const,
          expected: { bindingId: "binding.synthetic.d", digest: { algorithm: "sha256" as const, value: "d".repeat(64) }, byteLength: 64 },
        },
      },
    };
    expect(assessFreshness(withUnknown)).toMatchObject({
      valid: true,
      assessment: { state: "stale" },
    });
  });

  it("does not require clock trust when time validity is not selected", async () => {
    const fresh = await loadStrict<FreshnessAssessment>(
      "../fixtures/valid/cca-240/freshness-fresh-v1.json",
    );
    const request = requestFromAssessment(fresh);
    const result = assessFreshness({
      ...request,
      validity: { ...request.validity, time: { selected: false } },
    });
    expect(result).toMatchObject({ valid: true, assessment: { state: "fresh" } });
  });

  it("returns not-assessed when request or context is absent and never reads wall clock", async () => {
    const fixture = await loadStrict<FreshnessAssessment>(
      "../fixtures/valid/cca-240/freshness-fresh-v1.json",
    );
    const now = vi.spyOn(Date, "now").mockImplementation(() => {
      throw new Error("wall clock access is forbidden");
    });
    try {
      const result = assessFreshness({
        ...requestFromAssessment(fixture),
        intent: { requested: true },
      });
      expect(result).toMatchObject({
        valid: true,
        assessment: { state: "not-assessed" },
      });
    } finally {
      now.mockRestore();
    }
  });

  it("rejects an active context that selects no requirements", async () => {
    const fixture = await loadStrict<FreshnessAssessment>(
      "../fixtures/valid/cca-240/freshness-not-assessed-v1.json",
    );
    const request = requestFromAssessment(fixture);
    const result = assessFreshness({
      ...request,
      intent: {
        requested: true,
        context: { contextId: "context.synthetic.empty", contextVersion: "1.0.0" },
      },
    });
    expect(result.valid).toBe(false);
    expect(codes(result)).toContain("FRESHNESS_REQUIREMENT_REQUIRED");
  });

  it("serializes identical semantic inputs to identical sorted bytes", async () => {
    const value = await loadStrict<ExecutionResult>(
      "../fixtures/valid/cca-240/execution-pass-v1.json",
    );
    const permuted: ExecutionResult = {
      ...value,
      scope: { ...value.scope, exclusions: [...value.scope.exclusions].reverse() },
      inputBindings: [...value.inputBindings].reverse(),
      artifacts: [...value.artifacts].reverse(),
    };
    expect(Buffer.from(serializeEvidenceContract(value))).toEqual(
      Buffer.from(serializeEvidenceContract(permuted)),
    );
    expect(Buffer.from(serializeEvidenceContract(value))).toEqual(
      await loadBytes("../fixtures/valid/cca-240/execution-pass-v1.json"),
    );
  });

  it("serializes diagnostics by code, path, and message", async () => {
    const value = await loadStrict<ExecutionResult>(
      "../fixtures/valid/cca-240/execution-pass-v1.json",
    );
    const diagnostics = [
      { code: "B_CODE", path: "/a", message: "a" },
      { code: "A_CODE", path: "/z", message: "a" },
      { code: "A_CODE", path: "/a", message: "z" },
      { code: "A_CODE", path: "/a", message: "a" },
    ];
    const expected = [
      { code: "A_CODE", path: "/a", message: "a" },
      { code: "A_CODE", path: "/a", message: "z" },
      { code: "A_CODE", path: "/z", message: "a" },
      { code: "B_CODE", path: "/a", message: "a" },
    ];
    const bytes = serializeEvidenceContract({ ...value, diagnostics });
    const decoded = decodeStrictJsonObject<ExecutionResult>(bytes);
    expect(decoded.valid).toBe(true);
    if (!decoded.valid) return;
    expect(decoded.value.diagnostics).toEqual(expected);
    expect(Buffer.from(bytes)).toEqual(
      Buffer.from(
        serializeEvidenceContract({ ...value, diagnostics: [...diagnostics].reverse() }),
      ),
    );
    expect(validateExecutionResult(bytes)).toEqual({ valid: true, diagnostics: [] });
  });

  it("rejects a completed execution that precedes its start", async () => {
    const value = await loadStrict<ExecutionResult>(
      "../fixtures/valid/cca-240/execution-pass-v1.json",
    );
    if (value.status !== "pass") throw new Error("expected pass fixture");

    const reversed = serializeEvidenceContract({
      ...value,
      execution: {
        ...value.execution,
        startedAt: "2026-07-30T12:00:00Z",
        completedAt: "2026-07-30T11:59:59.999999999Z",
      },
    });
    expect(codes(validateExecutionResult(reversed))).toContain(
      "EXECUTION_TIME_ORDER_INVALID",
    );

    const fractionalCompletion = serializeEvidenceContract({
      ...value,
      execution: {
        ...value.execution,
        startedAt: "2026-07-30T12:00:00Z",
        completedAt: "2026-07-30T12:00:00.1Z",
      },
    });
    expect(validateExecutionResult(fractionalCompletion)).toEqual({
      valid: true,
      diagnostics: [],
    });

    const reversedFraction = serializeEvidenceContract({
      ...value,
      execution: {
        ...value.execution,
        startedAt: "2026-07-30T12:00:00.1Z",
        completedAt: "2026-07-30T12:00:00.09Z",
      },
    });
    expect(codes(validateExecutionResult(reversedFraction))).toContain(
      "EXECUTION_TIME_ORDER_INVALID",
    );
  });

  it("digests exact external bytes without canonicalizing them", async () => {
    const input = await baseBindingInput();
    const parsed = await loadStrict<ExecutionResult>(
      "../fixtures/valid/cca-240/execution-pass-v1.json",
    );
    const { safety, ...withoutSafety } = parsed;
    const reorderedBytes = new TextEncoder().encode(
      `${JSON.stringify({ safety, ...withoutSafety }, undefined, 2)}\n`,
    );
    expect(Buffer.from(reorderedBytes)).not.toEqual(Buffer.from(input.executionResultBytes));
    const result = validateEvidenceBindingSet({ ...input, executionResultBytes: reorderedBytes });
    expect(result.valid).toBe(false);
    expect(codes(result)).toContain("BINDING_DIGEST_MISMATCH");
  });

  it("contains no implicit time, network, mutable revision, or external authority read", async () => {
    const source = await readFile(
      new URL("../packages/contracts/src/evidence.ts", import.meta.url),
      "utf8",
    );
    expect(source).not.toMatch(/Date\.now|new Date\s*\(|fetch\s*\(|https?:\/\//);
    expect(source).not.toMatch(/child_process|readFileSync|process\.env/);
  });

  it("keeps binding set free of aggregate decision authority", async () => {
    const value = await loadStrict<EvidenceBindingSet>(
      "../fixtures/valid/cca-240/evidence-binding-set-complete-v1.json",
    );
    expect(JSON.stringify(value)).not.toMatch(
      /aggregateStatus|claimSatisfaction|evidenceSufficiency|winner|precedence|humanApproval|certification|releaseStatus/,
    );
  });

  it("preserves opaque-human, not-applicable-tool, and not-recorded-environment forms without approval", async () => {
    const value = await loadStrict<EvidenceProvenance>(
      "../fixtures/valid/cca-240/provenance-human-no-tool-no-environment-v1.json",
    );
    expect(value.producer).toEqual({
      kind: "human",
      operatorId: "operator.SyntheticOpaque001",
    });
    expect(value.tool.kind).toBe("not-applicable");
    expect(value.environment.kind).toBe("not-recorded");
    expect(JSON.stringify(value)).not.toMatch(/approval|approved|certification|releaseStatus/);
  });

  it("keeps private opaque records free of plaintext digest and private metadata", async () => {
    const value = await loadStrict<EvidenceProvenance>(
      "../fixtures/valid/cca-240/provenance-private-synthetic-test-only-v1.json",
    );
    const privateArtifact = value.artifacts.find(({ kind }) => kind === "private-opaque");
    expect(privateArtifact).toEqual({
      kind: "private-opaque",
      artifactId: "artifact.synthetic.partial",
      classification: "private",
      role: "partial",
      opaqueId: "opaque.SyntheticPrivateReference001",
    });
  });
});
