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
    expect(rendered.diagnostics).toHaveLength(7);
    expect(rendered.diagnostics.every(({ severity }) => severity === "information")).toBe(
      true,
    );
    expect(rendered.diagnostics.map(({ code }) => code)).toEqual([
      "AUDIT_TREE_PROJECTION_LOSSY",
      "CONTEXT_PACK_REFERENCE_LOSSY",
      "EVIDENCE_MAPPING_UNSUPPORTED",
      "EVIDENCE_MAPPING_UNSUPPORTED",
      "THREAT_PROJECTION_LOSSY",
      "THREAT_PROJECTION_LOSSY",
      "THREAT_PROJECTION_LOSSY",
    ]);
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
    const profileClaims = values.get("assurance-profile/v1")?.claims;
    const securityClaims = values.get("security-claim/v1")?.claims;
    expect(Array.isArray(profileClaims)).toBe(true);
    expect(Array.isArray(securityClaims)).toBe(true);
    if (!Array.isArray(profileClaims) || !Array.isArray(securityClaims)) {
      throw new Error("generated claim arrays are missing");
    }
    const profileIds = (profileClaims as { id: string }[]).map(({ id }) => id);
    const claimIds = (securityClaims as { id: string }[]).map(({ id }) => id);
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
    const auditTargetValue = values.get("security-audit-scope/v1")?.target;
    expect(auditTargetValue).toBeDefined();
    if (
      auditTargetValue === undefined ||
      auditTargetValue === null ||
      typeof auditTargetValue !== "object"
    ) {
      throw new Error("generated audit target is missing");
    }
    const auditTarget = auditTargetValue as Record<string, unknown>;
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

  it("sorts otherwise-identical source references by description code points", async () => {
    const input = await loadCca210ValidationInput();
    const plan = await loadCca210Plan();
    const firstClaim = (plan.claimMappings as {
      claim?: { sourceRefs: Record<string, unknown>[] };
    }[])[0]?.claim;
    if (firstClaim === undefined) throw new Error("fixture claim missing");
    const original = firstClaim.sourceRefs[0];
    if (original === undefined) throw new Error("fixture source reference missing");
    original.description = "\u{10000} supplementary-plane description.";
    firstClaim.sourceRefs.push({
      ...original,
      description: "\uE000 private-use description.",
    });
    const forward = validateAeRenderPlan({ ...input, planBytes: serializePlan(plan) });
    expect(forward.valid).toBe(true);
    if (!forward.valid) return;
    const forwardBytes = renderAeNativeArtifacts(forward.validatedPlan).outputs.find(
      ({ artifactKind }) => artifactKind === "security-claim/v1",
    )?.bytes;

    firstClaim.sourceRefs.reverse();
    const reverse = validateAeRenderPlan({ ...input, planBytes: serializePlan(plan) });
    expect(reverse.valid).toBe(true);
    if (!reverse.valid) return;
    const reverseBytes = renderAeNativeArtifacts(reverse.validatedPlan).outputs.find(
      ({ artifactKind }) => artifactKind === "security-claim/v1",
    )?.bytes;
    expect(forwardBytes).toBeDefined();
    expect(reverseBytes).toBeDefined();
    if (forwardBytes === undefined || reverseBytes === undefined) {
      throw new Error("security-claim output missing");
    }
    expect(Buffer.from(reverseBytes)).toEqual(Buffer.from(forwardBytes));
    const decoded = decodeStrictJsonObject<Record<string, unknown>>(forwardBytes);
    expect(decoded.valid).toBe(true);
    if (!decoded.valid) return;
    const renderedClaims = decoded.value.claims as {
      sourceRefs: { description?: string }[];
    }[];
    expect(renderedClaims[0]?.sourceRefs.map(({ description }) => description)).toEqual([
      "\uE000 private-use description.",
      "\u{10000} supplementary-plane description.",
    ]);
  });
});
