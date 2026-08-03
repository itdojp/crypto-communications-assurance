import { describe, expect, it } from "vitest";

import {
  compileContractBytes,
  decodeStrictJsonObject,
  renderAeNativeArtifacts,
  validateAeRenderPlan,
  type AeRenderPlanValidationInput,
} from "../packages/contracts/src/index.js";
import {
  loadCca210Plan,
  loadCca210ValidationInput,
  serializePlan,
} from "./helpers/cca-210.js";

type JsonRecord = Record<string, unknown>;

const codes = (result: ReturnType<typeof validateAeRenderPlan>): readonly string[] =>
  result.valid ? [] : result.diagnostics.map(({ code }) => code);

async function validateMutation(
  mutate: (plan: JsonRecord) => void,
  mutateInput?: (input: AeRenderPlanValidationInput) => AeRenderPlanValidationInput,
) {
  const [plan, originalInput] = await Promise.all([
    loadCca210Plan(),
    loadCca210ValidationInput(),
  ]);
  mutate(plan);
  const input = { ...originalInput, planBytes: serializePlan(plan) };
  return validateAeRenderPlan(mutateInput?.(input) ?? input);
}

const claims = (plan: JsonRecord): JsonRecord[] => plan.claimMappings as JsonRecord[];
const claim = (plan: JsonRecord, index = 0): JsonRecord =>
  claims(plan)[index]?.claim as JsonRecord;
const threats = (plan: JsonRecord): JsonRecord[] => plan.threatMappings as JsonRecord[];
const threat = (plan: JsonRecord, index = 0): JsonRecord =>
  threats(plan)[index]?.threat as JsonRecord;

describe("CCA-210 fail-closed negative boundaries", () => {
  it("rejects a CCA exact-byte digest mismatch", async () => {
    const result = await validateMutation((plan) => {
      ((plan.ccaInputs as JsonRecord).propertyCatalog as JsonRecord).sha256 = "0".repeat(64);
    });
    expect(codes(result)).toContain("CCA_BINDING_DIGEST_MISMATCH");
  });

  it("rejects a CCA exact-byte length mismatch", async () => {
    const result = await validateMutation((plan) => {
      ((plan.ccaInputs as JsonRecord).attackerCatalog as JsonRecord).byteLength = 2;
    });
    expect(codes(result)).toContain("CCA_BINDING_LENGTH_MISMATCH");
  });

  it("rejects an upstream schema byte/digest mismatch", async () => {
    const result = await validateMutation(
      () => undefined,
      (input) => ({
        ...input,
        upstreamSchemaBytes: {
          ...input.upstreamSchemaBytes,
          securityClaim: Buffer.concat([
            Buffer.from(input.upstreamSchemaBytes.securityClaim),
            Buffer.from(" "),
          ]),
        },
      }),
    );
    expect(codes(result)).toContain("UPSTREAM_SCHEMA_BINDING_DIGEST_MISMATCH");
  });

  it.each(["commit", "tree"])("rejects a wrong exact upstream %s", async (field) => {
    const result = await validateMutation((plan) => {
      (plan.upstream as JsonRecord)[field] = "f".repeat(40);
    });
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it("rejects a missing Context Pack", async () => {
    const result = await validateMutation(
      () => undefined,
      (input) => ({ ...input, contextPackBytes: new Map() }),
    );
    expect(codes(result)).toContain("CONTEXT_PACK_MISSING");
  });

  it.each(["../secret.json", "/etc/passwd", "fixtures/../secret.json", "C:\\secret.json"])(
    "rejects an unsafe Context Pack path: %s",
    async (path) => {
      const result = await validateMutation((plan) => {
        (plan.contextPacks as JsonRecord[])[0]!.path = path;
      });
      expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
    },
  );

  it("rejects a Context Pack digest mismatch", async () => {
    const result = await validateMutation((plan) => {
      (plan.contextPacks as JsonRecord[])[0]!.sha256 = "0".repeat(64);
    });
    expect(codes(result)).toContain("CONTEXT_PACK_BINDING_DIGEST_MISMATCH");
  });

  it.each(["statement", "type", "kind", "criticality", "targetLevel"])(
    "rejects a rendered claim missing explicit %s",
    async (field) => {
      const result = await validateMutation((plan) => {
        delete claim(plan)[field];
      });
      expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
    },
  );

  it.each(["requiredLanes", "requiredEvidenceKinds"])(
    "rejects a rendered evidence mapping missing %s",
    async (field) => {
      const result = await validateMutation((plan) => {
        const mapping = (claim(plan).evidenceMappings as JsonRecord[])[0]!;
        delete (mapping.rendered as JsonRecord)[field];
      });
      expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
    },
  );

  it.each([
    ["requiredLanes", "invented-lane"],
    ["requiredEvidenceKinds", "invented-evidence-kind"],
  ])("rejects an invalid native %s enum", async (field, value) => {
    const result = await validateMutation((plan) => {
      claim(plan)[field] = [value];
    });
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it.each(["operational-procedure", "human-review"])(
    "rejects a silently projected %s requirement",
    async (sourceEvidenceKind) => {
      const result = await validateMutation((plan) => {
        const mapping = (claim(plan).evidenceMappings as JsonRecord[]).find(
          (candidate) => candidate.sourceEvidenceKind === "human-review",
        );
        if (mapping === undefined) throw new Error("fixture mapping missing");
        mapping.sourceEvidenceKind = sourceEvidenceKind;
        mapping.disposition = "render";
        delete mapping.reason;
        mapping.rendered = {
          projection: "direct",
          requiredLanes: ["behavior"],
          requiredEvidenceKinds: ["waiver"],
        };
        claim(plan).requiredLanes = ["adversarial", "behavior", "spec"];
        claim(plan).requiredEvidenceKinds = [
          "conformance",
          "differential",
          "fuzz",
          "schema",
          "waiver",
        ];
      });
      expect(codes(result)).toContain("UNSUPPORTED_EVIDENCE_PROJECTION");
    },
  );

  it.each(["stride", "cwe"])("rejects a threat missing explicit %s", async (field) => {
    const result = await validateMutation((plan) => {
      delete threat(plan)[field];
    });
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it.each(["inferredStride", "inferredCwe"])(
    "rejects an inferred taxonomy attempt field %s",
    async (field) => {
      const result = await validateMutation((plan) => {
        threat(plan)[field] = true;
      });
      expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
    },
  );

  it("rejects a dangling related claim", async () => {
    const result = await validateMutation((plan) => {
      threat(plan).relatedClaimIds = ["property.integrity.not-rendered"];
    });
    expect(codes(result)).toContain("RELATED_CLAIM_DANGLING");
  });

  it("rejects a property/claim identity mismatch", async () => {
    const result = await validateMutation((plan) => {
      claim(plan).claimId = "property.integrity.state";
    });
    expect(codes(result)).toContain("CLAIM_PROPERTY_ID_MISMATCH");
  });

  it("rejects a threat identity mismatch", async () => {
    const result = await validateMutation((plan) => {
      threat(plan).threatId = "threat.integrity.in-transit-modification";
    });
    expect(codes(result)).toContain("THREAT_ID_MISMATCH");
  });

  it("rejects a rendered claim without the exact property JSON Pointer", async () => {
    const result = await validateMutation((plan) => {
      (claim(plan).sourceRefs as JsonRecord[])[0]!.section = "#/properties/other";
    });
    expect(codes(result)).toContain("CLAIM_SOURCE_REFERENCE_MISSING");
  });

  it.each(["entryPoints", "attackerControlled"])(
    "rejects a claim trust boundary missing %s",
    async (field) => {
      const result = await validateMutation((plan) => {
        delete (claim(plan).trustBoundary as JsonRecord)[field];
      });
      expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
    },
  );

  it("rejects a dangling trust-boundary reference", async () => {
    const result = await validateMutation((plan) => {
      (claim(plan).trustBoundary as JsonRecord).boundaryIds = ["boundary.synthetic.missing"];
    });
    expect(codes(result)).toContain("TRUST_BOUNDARY_REFERENCE_DANGLING");
  });

  it("rejects a scope missing an in-scope target", async () => {
    const result = await validateMutation((plan) => {
      const scope = (plan.scopeMapping as JsonRecord).scope as JsonRecord;
      delete scope.inScope;
    });
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it.each(["main", "refs/tags/v1.0.0", "1234567"])(
    "rejects mutable or abbreviated target identity %s",
    async (revision) => {
      const result = await validateMutation((plan) => {
        (plan.target as JsonRecord).commit = revision;
      });
      expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
    },
  );

  it("rejects a target tree omitted from the render plan", async () => {
    const result = await validateMutation((plan) => {
      delete (plan.target as JsonRecord).tree;
    });
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it("rejects omission of the explicit audit-tree loss record", async () => {
    const result = await validateMutation((plan) => {
      const scope = (plan.scopeMapping as JsonRecord).scope as JsonRecord;
      delete scope.treeProjection;
    });
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it("rejects disabling the no-symlink assumption", async () => {
    const result = await validateMutation((plan) => {
      (plan.safety as JsonRecord).rejectSymlinks = false;
    });
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it("rejects an unsupported mapping that silently retains rendered content", async () => {
    const result = await validateMutation((plan) => {
      claims(plan)[0]!.disposition = "unsupported";
      claims(plan)[0]!.reason = "Synthetic unsupported mapping.";
    });
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it("rejects current-time/generatedAt insertion into the plan", async () => {
    const result = await validateMutation((plan) => {
      plan.generatedAt = "2026-01-01T00:00:00Z";
    });
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it.each([
    "context-pack/v1",
    "claim-evidence-manifest/v1",
    "policy-decision/v1",
    "approval/v1",
    "claim-satisfaction/v1",
    "release/v1",
  ])("rejects prohibited output kind %s", async (artifactKind) => {
    const result = await validateMutation((plan) => {
      (plan.outputs as JsonRecord[])[0]!.artifactKind = artifactKind;
    });
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it("rejects an undeclared authority field", async () => {
    const result = await validateMutation((plan) => {
      plan.humanApproved = true;
    });
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it("rejects mapping-count overflow", async () => {
    const result = await validateMutation((plan) => {
      plan.claimMappings = Array.from({ length: 65 }, () => structuredClone(claims(plan)[0]));
    });
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it("bounds the caller-supplied Context Pack byte map", async () => {
    const result = await validateMutation(
      () => undefined,
      (input) => ({
        ...input,
        contextPackBytes: new Map(
          Array.from({ length: 9 }, (_, index) => [
            `context.synthetic.extra-${index}`,
            Buffer.from("{}\n"),
          ]),
        ),
      }),
    );
    expect(codes(result)).toContain("CONTEXT_PACK_INPUT_LIMIT_EXCEEDED");
  });

  it("returns stable code/path/message-sorted diagnostics", async () => {
    const mutate = (plan: JsonRecord): void => {
      (plan.outputs as JsonRecord[])[1]!.artifactKind = (plan.outputs as JsonRecord[])[0]!.artifactKind;
      ((plan.scopeMapping as JsonRecord).scope as JsonRecord).target = {
        repository: "itdojp/different-synthetic-target",
        commit: "4".repeat(40),
        tree: "5".repeat(40),
      };
    };
    const first = await validateMutation(mutate);
    const second = await validateMutation(mutate);
    expect(first).toEqual(second);
    if (first.valid) throw new Error("negative plan unexpectedly validated");
    const keys = first.diagnostics.map(({ code, path, message }) =>
      `${code}\0${path}\0${message}`,
    );
    expect(keys).toEqual([...keys].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0)));
  });

  it("rejects duplicate claim mappings", async () => {
    const result = await validateMutation((plan) => {
      claims(plan)[1]!.propertyId = claims(plan)[0]!.propertyId;
      (claims(plan)[1]!.claim as JsonRecord).claimId = claims(plan)[0]!.propertyId;
    });
    expect(codes(result)).toContain("CLAIM_MAPPING_DUPLICATE");
  });

  it("rejects duplicate output kinds", async () => {
    const result = await validateMutation((plan) => {
      (plan.outputs as JsonRecord[])[1]!.artifactKind = (plan.outputs as JsonRecord[])[0]!.artifactKind;
    });
    expect(codes(result)).toContain("OUTPUT_KIND_DUPLICATE");
  });

  it("rejects renderer source identity drift", async () => {
    const result = await validateMutation((plan) => {
      (plan.renderer as JsonRecord).sourceSha256 = "0".repeat(64);
    });
    expect(codes(result)).toContain("RENDERER_IDENTITY_MISMATCH");
  });

  it("rejects direct rendering without a validated token", () => {
    const rendered = renderAeNativeArtifacts({ planId: "forged" });
    expect(rendered.valid).toBe(false);
    expect(rendered.outputs).toEqual([]);
    expect(rendered.diagnostics.map(({ code }) => code)).toEqual([
      "VALIDATED_PLAN_REQUIRED",
    ]);
  });

  it("demonstrates a native schema mismatch is rejected", async () => {
    const input = await loadCca210ValidationInput();
    const validation = validateAeRenderPlan(input);
    if (!validation.valid) throw new Error(JSON.stringify(validation.diagnostics));
    const output = renderAeNativeArtifacts(validation.validatedPlan).outputs[0];
    if (output === undefined) throw new Error("missing native output");
    const decoded = decodeStrictJsonObject<JsonRecord>(output.bytes);
    if (!decoded.valid) throw new Error("generated bytes did not strict-decode");
    decoded.value.approved = true;
    const schema = decodeStrictJsonObject(input.upstreamSchemaBytes.assuranceProfile);
    if (!schema.valid) throw new Error("pinned schema did not strict-decode");
    expect(compileContractBytes(schema.value)(serializePlan(decoded.value))).toMatchObject({
      valid: false,
      stage: "schema",
    });
  });
});
