import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  decodeStrictJsonObject,
  serializeEvidenceContract,
  validateEvidenceBindingSet,
  validateEvidenceBindingSetContract,
  validateEvidenceProvenance,
  validateExecutionResult,
  validateFreshnessAssessment,
} from "../packages/contracts/src/index.js";
import { readRepositoryFile } from "./helpers/cca-210.js";

type JsonRecord = Record<string, unknown>;
const recordRoot = "fixtures/valid/cca-210/records/";
const digest = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

async function loadRecord(name: string): Promise<{ value: JsonRecord; bytes: Buffer }> {
  const bytes = await readRepositoryFile(`${recordRoot}${name}`);
  const decoded = decodeStrictJsonObject<JsonRecord>(bytes);
  if (!decoded.valid) throw new Error(`${name} did not strict-decode`);
  return { value: structuredClone(decoded.value), bytes };
}

const inputPaths: Readonly<Record<string, string>> = {
  "input.cca210.render-plan": "fixtures/valid/cca-210/ae-render-plan-v1.json",
  "input.cca210.cca.property-catalog": "pack/catalogs/v1/property-catalog.json",
  "input.cca210.cca.attacker-catalog": "pack/catalogs/v1/attacker-catalog.json",
  "input.cca210.cca.threat-catalog": "pack/catalogs/v1/threat-catalog.json",
  "input.cca210.cca.module-catalog": "pack/modules/v1/capability-module-catalog.json",
  "input.cca210.cca.resolved-profile": "fixtures/valid/cca-210/resolved-profile-v1.json",
  "input.cca210.context.context-pack": "fixtures/valid/cca-210/context-pack-v1.json",
  "input.cca210.upstream.assurance-profile-schema":
    "integrations/ae-framework/pins/c5da6115638fdbfeebbc458b39fa6916db66afb0/schema/assurance-profile.schema.json",
  "input.cca210.upstream.security-claim-schema":
    "integrations/ae-framework/pins/c5da6115638fdbfeebbc458b39fa6916db66afb0/schema/security-claim-v1.schema.json",
  "input.cca210.upstream.security-threat-model-schema":
    "integrations/ae-framework/pins/c5da6115638fdbfeebbc458b39fa6916db66afb0/schema/security-threat-model-v1.schema.json",
  "input.cca210.upstream.security-audit-scope-schema":
    "integrations/ae-framework/pins/c5da6115638fdbfeebbc458b39fa6916db66afb0/schema/security-audit-scope-v1.schema.json",
  "input.cca210.upstream.context-pack-schema":
    "integrations/ae-framework/pins/c5da6115638fdbfeebbc458b39fa6916db66afb0/schema/context-pack-v1.schema.json",
  "input.cca210.renderer-source": "packages/contracts/src/ae-renderer.ts",
};

const artifactPaths: Readonly<Record<string, string>> = {
  "artifact.cca210.assurance-profile":
    "fixtures/valid/cca-210/rendered/assurance-profile-v1.json",
  "artifact.cca210.security-claim":
    "fixtures/valid/cca-210/rendered/security-claim-v1.json",
  "artifact.cca210.security-threat-model":
    "fixtures/valid/cca-210/rendered/security-threat-model-v1.json",
  "artifact.cca210.security-audit-scope":
    "fixtures/valid/cca-210/rendered/security-audit-scope-v1.json",
};

describe("CCA-210 representative CCA-240 render records", () => {
  it("strict-decodes, schema-validates, and semantically validates all four records", async () => {
    const cases = [
      ["execution-result-v1.json", validateExecutionResult],
      ["evidence-provenance-v1.json", validateEvidenceProvenance],
      ["freshness-assessment-v1.json", validateFreshnessAssessment],
      ["evidence-binding-set-v1.json", validateEvidenceBindingSetContract],
    ] as const;
    for (const [name, validate] of cases) {
      expect(validate((await loadRecord(name)).bytes), name).toEqual({
        valid: true,
        diagnostics: [],
      });
    }
  });

  it("validates the exact execution/provenance/freshness binding composition", async () => {
    const [execution, provenance, freshness, bindingSet] = await Promise.all([
      loadRecord("execution-result-v1.json"),
      loadRecord("evidence-provenance-v1.json"),
      loadRecord("freshness-assessment-v1.json"),
      loadRecord("evidence-binding-set-v1.json"),
    ]);
    expect(
      validateEvidenceBindingSet({
        executionResultBytes: execution.bytes,
        evidenceProvenanceBytes: provenance.bytes,
        freshnessAssessmentBytes: freshness.bytes,
        bindingSetBytes: bindingSet.bytes,
      }),
    ).toEqual({ valid: true, diagnostics: [] });
  });

  it("binds the exact plan, CCA inputs, upstream schemas, Context Pack, and renderer source", async () => {
    const { value } = await loadRecord("execution-result-v1.json");
    const bindings = value.inputBindings as {
      inputId: string;
      digest: { value: string };
      byteLength: number;
    }[];
    expect(bindings).toHaveLength(13);
    expect(bindings.map(({ inputId }) => inputId).sort()).toEqual(
      Object.keys(inputPaths).sort(),
    );
    for (const binding of bindings) {
      const path = inputPaths[binding.inputId];
      if (path === undefined) throw new Error(`unknown input ${binding.inputId}`);
      const bytes = await readRepositoryFile(path);
      expect(binding.byteLength, path).toBe(bytes.byteLength);
      expect(binding.digest.value, path).toBe(digest(bytes));
    }
  });

  it("binds all four exact generated native artifact bytes as substantive results", async () => {
    const { value } = await loadRecord("evidence-provenance-v1.json");
    const artifacts = value.artifacts as {
      artifactId: string;
      role: string;
      kind: string;
      digest: { value: string };
      byteLength: number;
    }[];
    expect(artifacts).toHaveLength(4);
    expect(artifacts.map(({ artifactId }) => artifactId).sort()).toEqual(
      Object.keys(artifactPaths).sort(),
    );
    for (const artifact of artifacts) {
      const path = artifactPaths[artifact.artifactId];
      if (path === undefined) throw new Error(`unknown artifact ${artifact.artifactId}`);
      const bytes = await readRepositoryFile(path);
      expect(artifact).toMatchObject({
        kind: "public-content",
        role: "substantive-result",
        byteLength: bytes.byteLength,
        digest: { value: digest(bytes) },
      });
    }
  });

  it("keeps pass, synthetic/test-only, and freshness not-assessed literal and separate", async () => {
    const [execution, provenance, freshness] = await Promise.all([
      loadRecord("execution-result-v1.json"),
      loadRecord("evidence-provenance-v1.json"),
      loadRecord("freshness-assessment-v1.json"),
    ]);
    expect(execution.value.status).toBe("pass");
    expect(
      (execution.value.diagnostics as { code: string }[]).map(({ code }) => code),
    ).toEqual([
      "AUDIT_TREE_PROJECTION_LOSSY",
      "CONTEXT_PACK_REFERENCE_LOSSY",
      "EVIDENCE_MAPPING_UNSUPPORTED",
      "EVIDENCE_MAPPING_UNSUPPORTED",
      "THREAT_PROJECTION_LOSSY",
      "THREAT_PROJECTION_LOSSY",
      "THREAT_PROJECTION_LOSSY",
    ]);
    expect(provenance.value).toMatchObject({
      evidenceOrigin: "synthetic",
      useRestriction: "test-only",
      fixtureClassification: "synthetic-test-only",
    });
    expect(freshness.value).toMatchObject({
      state: "not-assessed",
      fixtureClassification: "synthetic-test-only",
    });
    for (const value of [execution.value, provenance.value, freshness.value]) {
      for (const field of [
        "claimSatisfied",
        "humanApproved",
        "certified",
        "releaseStatus",
      ]) {
        expect(Object.hasOwn(value, field)).toBe(false);
      }
    }
  });

  it("rejects CCA-240 claim-satisfaction promotion", async () => {
    const execution = await loadRecord("execution-result-v1.json");
    execution.value.claimSatisfied = true;
    expect(validateExecutionResult(serializeEvidenceContract(execution.value)).valid).toBe(
      false,
    );
  });

  it("rejects synthetic evidence promotion to policy-evaluable", async () => {
    const provenance = await loadRecord("evidence-provenance-v1.json");
    provenance.value.useRestriction = "policy-evaluable";
    const result = validateEvidenceProvenance(
      serializeEvidenceContract(provenance.value),
    );
    expect(result.valid).toBe(false);
  });

  it("rejects fixture origin/classification mismatch", async () => {
    const provenance = await loadRecord("evidence-provenance-v1.json");
    provenance.value.evidenceOrigin = "real";
    const result = validateEvidenceProvenance(
      serializeEvidenceContract(provenance.value),
    );
    expect(result.valid).toBe(false);
  });

  it("rejects promotion from not-assessed to fresh without selected facts", async () => {
    const freshness = await loadRecord("freshness-assessment-v1.json");
    freshness.value.state = "fresh";
    expect(
      validateFreshnessAssessment(serializeEvidenceContract(freshness.value)).valid,
    ).toBe(false);
  });

  it("rejects an exact binding-set digest mismatch", async () => {
    const [execution, provenance, freshness, bindingSet] = await Promise.all([
      loadRecord("execution-result-v1.json"),
      loadRecord("evidence-provenance-v1.json"),
      loadRecord("freshness-assessment-v1.json"),
      loadRecord("evidence-binding-set-v1.json"),
    ]);
    (((bindingSet.value.bindings as JsonRecord).executionResult as JsonRecord)
      .digest as JsonRecord).value = "0".repeat(64);
    expect(
      validateEvidenceBindingSet({
        executionResultBytes: execution.bytes,
        evidenceProvenanceBytes: provenance.bytes,
        freshnessAssessmentBytes: freshness.bytes,
        bindingSetBytes: serializeEvidenceContract(bindingSet.value),
      }).valid,
    ).toBe(false);
  });
});
