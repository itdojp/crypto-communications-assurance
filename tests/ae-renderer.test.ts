import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  aeNativeArtifactKinds,
  compileContractBytes,
  decodeStrictJsonObject,
  renderAeNativeArtifacts,
  validateAeRenderPlan,
} from "../packages/contracts/src/index.js";
import {
  loadCca210Plan,
  loadCca210ValidationInput,
  readRepositoryFile,
  serializePlan,
} from "./helpers/cca-210.js";

const digest = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

describe("CCA-210 pure render-plan validation and rendering", () => {
  it("validates the exact synthetic plan and renders only four native artifacts", async () => {
    const validation = validateAeRenderPlan(await loadCca210ValidationInput());
    expect(validation).toMatchObject({ valid: true, diagnostics: [] });
    if (!validation.valid) return;

    const rendered = renderAeNativeArtifacts(validation.validatedPlan);
    expect(rendered.valid).toBe(true);
    expect(rendered.diagnostics).toEqual([]);
    expect(rendered.outputs.map(({ artifactKind }) => artifactKind)).toEqual(
      aeNativeArtifactKinds,
    );
    expect(rendered.outputs).toHaveLength(4);
  });

  it("matches every committed golden native artifact byte-for-byte", async () => {
    const validation = validateAeRenderPlan(await loadCca210ValidationInput());
    if (!validation.valid) throw new Error(JSON.stringify(validation.diagnostics));
    const rendered = renderAeNativeArtifacts(validation.validatedPlan);
    expect(rendered.valid).toBe(true);
    for (const output of rendered.outputs) {
      expect(Buffer.from(output.bytes), output.path).toEqual(
        await readRepositoryFile(output.path),
      );
    }
  });

  it("strict-decodes and validates all four generated kinds against exact pinned schemas", async () => {
    const input = await loadCca210ValidationInput();
    const validation = validateAeRenderPlan(input);
    if (!validation.valid) throw new Error(JSON.stringify(validation.diagnostics));
    const rendered = renderAeNativeArtifacts(validation.validatedPlan);
    const roles = {
      "assurance-profile/v1": "assuranceProfile",
      "security-claim/v1": "securityClaim",
      "security-threat-model/v1": "securityThreatModel",
      "security-audit-scope/v1": "securityAuditScope",
    } as const;
    for (const output of rendered.outputs) {
      const decodedSchema = decodeStrictJsonObject(
        input.upstreamSchemaBytes[roles[output.artifactKind]],
      );
      expect(decodedSchema.valid).toBe(true);
      if (!decodedSchema.valid) continue;
      expect(compileContractBytes(decodedSchema.value)(output.bytes), output.artifactKind).toMatchObject({
        valid: true,
        stage: "validated",
      });
    }
  });

  it("preserves exact property and threat identifiers without emitting timestamps or summaries", async () => {
    const validation = validateAeRenderPlan(await loadCca210ValidationInput());
    if (!validation.valid) throw new Error(JSON.stringify(validation.diagnostics));
    const outputs = renderAeNativeArtifacts(validation.validatedPlan).outputs;
    const values = new Map(
      outputs.map(({ artifactKind, bytes }) => {
        const decoded = decodeStrictJsonObject<Record<string, unknown>>(bytes);
        if (!decoded.valid) throw new Error(artifactKind);
        return [artifactKind, decoded.value] as const;
      }),
    );
    const profileIds = (values.get("assurance-profile/v1")?.claims as { id: string }[]).map(({ id }) => id);
    const claimIds = (values.get("security-claim/v1")?.claims as { id: string }[]).map(({ id }) => id);
    expect(profileIds).toEqual(claimIds);
    expect(profileIds).toEqual([
      "property.confidentiality.key-material",
      "property.confidentiality.message",
      "property.integrity.message",
      "property.integrity.state",
    ]);
    expect(
      (values.get("security-threat-model/v1")?.threats as { id: string }[]).map(({ id }) => id),
    ).toEqual([
      "threat.confidentiality.passive-message-disclosure",
      "threat.confidentiality.secret-material-extraction",
      "threat.integrity.in-transit-modification",
    ]);
    for (const value of values.values()) {
      expect(Object.hasOwn(value, "generatedAt")).toBe(false);
      expect(Object.hasOwn(value, "summary")).toBe(false);
    }
    const auditTarget = values.get("security-audit-scope/v1")?.target as Record<string, unknown>;
    expect(auditTarget.commit).toBe("1111111111111111111111111111111111111111");
    expect(Object.hasOwn(auditTarget, "tree")).toBe(false);
  });

  it("produces identical native bytes under set-like and mapping input permutations", async () => {
    const input = await loadCca210ValidationInput();
    const baselineValidation = validateAeRenderPlan(input);
    if (!baselineValidation.valid) throw new Error(JSON.stringify(baselineValidation.diagnostics));
    const baseline = renderAeNativeArtifacts(baselineValidation.validatedPlan).outputs.map(({ bytes }) => digest(bytes));
    const plan = await loadCca210Plan();
    for (const key of ["outputs", "claimMappings", "threatMappings", "contextPacks"] as const) {
      (plan[key] as unknown[]).reverse();
    }
    const scope = (plan.scopeMapping as { scope: Record<string, unknown> }).scope;
    for (const key of ["componentGlobs", "inScope", "outOfScope", "trustBoundaries"] as const) {
      (scope[key] as unknown[]).reverse();
    }
    for (const mapping of plan.claimMappings as { claim?: Record<string, unknown> }[]) {
      const claim = mapping.claim;
      if (claim === undefined) continue;
      for (const key of ["requiredLanes", "requiredEvidenceKinds", "sourceRefs", "evidenceMappings"] as const) {
        (claim[key] as unknown[]).reverse();
      }
      ((claim.threatTags as Record<string, unknown>).stride as unknown[]).reverse();
      ((claim.threatTags as Record<string, unknown>).cwe as unknown[]).reverse();
    }
    const permuted = validateAeRenderPlan({ ...input, planBytes: serializePlan(plan) });
    expect(permuted.valid).toBe(true);
    if (!permuted.valid) return;
    expect(renderAeNativeArtifacts(permuted.validatedPlan).outputs.map(({ bytes }) => digest(bytes))).toEqual(baseline);
  });
});
