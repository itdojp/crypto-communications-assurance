import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  aeCcaInputRoles,
  aeUpstreamSchemaRoles,
  compileContractBytes,
  decodeStrictJsonObject,
  maximumAeRenderDiagnostics,
  normalizeAeRenderDiagnostics,
  renderAeNativeArtifacts,
  resolveProfile,
  validateAeRenderPlan,
  type AeRenderPlanValidationInput,
} from "../packages/contracts/src/index.js";
import {
  loadCca210Plan,
  loadCca210ValidationInput,
  readRepositoryFile,
  serializePlan,
} from "./helpers/cca-210.js";

type JsonRecord = Record<string, unknown>;

const digest = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

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
  it.each([null, undefined, "invalid", 1, false, [], new Map()])(
    "rejects a malformed top-level validation input without throwing: %p",
    (candidate) => {
      const result = validateAeRenderPlan(
        candidate as unknown as AeRenderPlanValidationInput,
      );
      expect(codes(result)).toEqual(["VALIDATION_INPUT_INVALID"]);
    },
  );

  it.each([null, undefined, "invalid", 1, false, {}, new Map()])(
    "rejects malformed planBytes without throwing: %p",
    async (planBytes) => {
      const input = await loadCca210ValidationInput();
      const result = validateAeRenderPlan({
        ...input,
        planBytes: planBytes as unknown as Uint8Array,
      });
      expect(codes(result)).toContain("RENDER_PLAN_BYTES_INVALID");
    },
  );

  it.each([null, undefined, "invalid", 1, false, [], new Map()])(
    "rejects a malformed CCA input container without throwing: %p",
    async (ccaInputBytes) => {
      const input = await loadCca210ValidationInput();
      const result = validateAeRenderPlan({
        ...input,
        ccaInputBytes: ccaInputBytes as unknown as AeRenderPlanValidationInput["ccaInputBytes"],
      });
      expect(codes(result)).toContain("CCA_INPUT_CONTAINER_INVALID");
    },
  );

  it.each(aeCcaInputRoles)("rejects a missing CCA input role: %s", async (role) => {
    const input = await loadCca210ValidationInput();
    const ccaInputBytes = { ...input.ccaInputBytes } as Record<string, Uint8Array>;
    delete ccaInputBytes[role];
    const result = validateAeRenderPlan({
      ...input,
      ccaInputBytes: ccaInputBytes as AeRenderPlanValidationInput["ccaInputBytes"],
    });
    expect(codes(result)).toContain("CCA_INPUT_MISSING");
  });

  it.each(aeCcaInputRoles)(
    "rejects a non-Uint8Array CCA input value: %s",
    async (role) => {
      const input = await loadCca210ValidationInput();
      const ccaInputBytes: Record<string, unknown> = { ...input.ccaInputBytes };
      ccaInputBytes[role] = null;
      const result = validateAeRenderPlan({
        ...input,
        ccaInputBytes: ccaInputBytes as AeRenderPlanValidationInput["ccaInputBytes"],
      });
      expect(codes(result)).toContain("CCA_INPUT_BYTES_INVALID");
    },
  );

  it("rejects an extra CCA input role", async () => {
    const input = await loadCca210ValidationInput();
    const result = validateAeRenderPlan({
      ...input,
      ccaInputBytes: {
        ...input.ccaInputBytes,
        unreviewedRole: Buffer.from("{}\n"),
      } as AeRenderPlanValidationInput["ccaInputBytes"],
    });
    expect(codes(result)).toContain("CCA_INPUT_ROLE_UNKNOWN");
  });

  it.each([null, undefined, "invalid", 1, false, [], {}])(
    "rejects a malformed Context Pack container without throwing: %p",
    async (contextPackBytes) => {
      const input = await loadCca210ValidationInput();
      const result = validateAeRenderPlan({
        ...input,
        contextPackBytes: contextPackBytes as unknown as ReadonlyMap<string, Uint8Array>,
      });
      expect(codes(result)).toContain("CONTEXT_PACK_CONTAINER_INVALID");
    },
  );

  it("rejects a Context Pack Map subclass with overridden accessors without throwing", async () => {
    class ThrowingContextPackMap extends Map<string, Uint8Array> {
      override get size(): number {
        throw new Error("size override should not be invoked");
      }

      override entries(): MapIterator<[string, Uint8Array]> {
        throw new Error("entries override should not be invoked");
      }
    }

    const input = await loadCca210ValidationInput();
    const contextPackBytes = new ThrowingContextPackMap(input.contextPackBytes);
    const result = validateAeRenderPlan({
      ...input,
      contextPackBytes,
    });
    expect(codes(result)).toContain("CONTEXT_PACK_CONTAINER_INVALID");
  });

  it("rejects a non-string Context Pack key", async () => {
    const input = await loadCca210ValidationInput();
    const result = validateAeRenderPlan({
      ...input,
      contextPackBytes: new Map([[1, Buffer.from("{}\n")]]) as unknown as ReadonlyMap<
        string,
        Uint8Array
      >,
    });
    expect(codes(result)).toContain("CONTEXT_PACK_KEY_INVALID");
  });

  it("rejects a non-Uint8Array Context Pack value", async () => {
    const input = await loadCca210ValidationInput();
    const result = validateAeRenderPlan({
      ...input,
      contextPackBytes: new Map([
        ["context.synthetic.cca-210", null],
      ]) as unknown as ReadonlyMap<string, Uint8Array>,
    });
    expect(codes(result)).toContain("CONTEXT_PACK_BYTES_INVALID");
  });

  it("rejects an extra Context Pack ID", async () => {
    const input = await loadCca210ValidationInput();
    const result = validateAeRenderPlan({
      ...input,
      contextPackBytes: new Map(input.contextPackBytes).set(
        "context.synthetic.unreviewed",
        Buffer.from("{}\n"),
      ),
    });
    expect(codes(result)).toContain("CONTEXT_PACK_UNREFERENCED");
  });

  it.each([null, undefined, "invalid", 1, false, [], new Map()])(
    "rejects a malformed upstream-schema container without throwing: %p",
    async (upstreamSchemaBytes) => {
      const input = await loadCca210ValidationInput();
      const result = validateAeRenderPlan({
        ...input,
        upstreamSchemaBytes: upstreamSchemaBytes as unknown as AeRenderPlanValidationInput["upstreamSchemaBytes"],
      });
      expect(codes(result)).toContain("UPSTREAM_SCHEMA_CONTAINER_INVALID");
    },
  );

  it.each(aeUpstreamSchemaRoles)(
    "rejects a missing upstream-schema role: %s",
    async (role) => {
      const input = await loadCca210ValidationInput();
      const upstreamSchemaBytes = {
        ...input.upstreamSchemaBytes,
      } as Record<string, Uint8Array>;
      delete upstreamSchemaBytes[role];
      const result = validateAeRenderPlan({
        ...input,
        upstreamSchemaBytes: upstreamSchemaBytes as AeRenderPlanValidationInput["upstreamSchemaBytes"],
      });
      expect(codes(result)).toContain("UPSTREAM_SCHEMA_MISSING");
    },
  );

  it.each(aeUpstreamSchemaRoles)(
    "rejects a non-Uint8Array upstream-schema value: %s",
    async (role) => {
      const input = await loadCca210ValidationInput();
      const upstreamSchemaBytes: Record<string, unknown> = {
        ...input.upstreamSchemaBytes,
      };
      upstreamSchemaBytes[role] = null;
      const result = validateAeRenderPlan({
        ...input,
        upstreamSchemaBytes: upstreamSchemaBytes as AeRenderPlanValidationInput["upstreamSchemaBytes"],
      });
      expect(codes(result)).toContain("UPSTREAM_SCHEMA_BYTES_INVALID");
    },
  );

  it("rejects an extra upstream-schema role", async () => {
    const input = await loadCca210ValidationInput();
    const result = validateAeRenderPlan({
      ...input,
      upstreamSchemaBytes: {
        ...input.upstreamSchemaBytes,
        unreviewedRole: Buffer.from("{}\n"),
      } as AeRenderPlanValidationInput["upstreamSchemaBytes"],
    });
    expect(codes(result)).toContain("UPSTREAM_SCHEMA_ROLE_UNKNOWN");
  });

  it("does not mutate caller-owned containers or bytes during runtime-shape rejection", async () => {
    const input = await loadCca210ValidationInput();
    const before = {
      plan: digest(input.planBytes),
      ccaRoles: Object.keys(input.ccaInputBytes).sort(),
      ccaDigests: Object.values(input.ccaInputBytes).map(digest),
      contextEntries: [...input.contextPackBytes.entries()].map(([id, bytes]) => [
        id,
        digest(bytes),
      ]),
      upstreamRoles: Object.keys(input.upstreamSchemaBytes).sort(),
      upstreamDigests: Object.values(input.upstreamSchemaBytes).map(digest),
      renderer: digest(input.rendererSourceBytes),
    };
    const result = validateAeRenderPlan({
      ...input,
      rendererSourceBytes: null as unknown as Uint8Array,
    });
    expect(codes(result)).toContain("RENDERER_SOURCE_MISSING");
    expect({
      plan: digest(input.planBytes),
      ccaRoles: Object.keys(input.ccaInputBytes).sort(),
      ccaDigests: Object.values(input.ccaInputBytes).map(digest),
      contextEntries: [...input.contextPackBytes.entries()].map(([id, bytes]) => [
        id,
        digest(bytes),
      ]),
      upstreamRoles: Object.keys(input.upstreamSchemaBytes).sort(),
      upstreamDigests: Object.values(input.upstreamSchemaBytes).map(digest),
      renderer: digest(input.rendererSourceBytes),
    }).toEqual(before);
  });

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

  it("rejects a schema-valid resolved profile inconsistent with its embedded request facts", async () => {
    const [plan, input] = await Promise.all([
      loadCca210Plan(),
      loadCca210ValidationInput(),
    ]);
    const decoded = decodeStrictJsonObject<JsonRecord>(
      input.ccaInputBytes.resolvedProfile,
    );
    if (!decoded.valid) throw new Error("resolved profile fixture did not decode");
    const selections = decoded.value.selections as JsonRecord;
    const properties = selections.properties as JsonRecord;
    delete properties["property.integrity.state"];
    const profileBytes = serializePlan(decoded.value);
    const binding = (plan.ccaInputs as JsonRecord).resolvedProfile as JsonRecord;
    binding.sha256 = digest(profileBytes);
    binding.byteLength = profileBytes.byteLength;
    plan.claimMappings = claims(plan).filter(
      (mapping) => mapping.propertyId !== "property.integrity.state",
    );

    const result = validateAeRenderPlan({
      ...input,
      planBytes: serializePlan(plan),
      ccaInputBytes: { ...input.ccaInputBytes, resolvedProfile: profileBytes },
    });
    expect(codes(result)).toContain("CCA_RESOLVED_PROFILE_SEMANTIC_INVALID");
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

  it("rejects a renderer package version different from the package manifest", async () => {
    const result = await validateMutation((plan) => {
      (plan.renderer as JsonRecord).packageVersion = "0.0.1";
    });
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it("retains synthetic classification from exact authoritative inputs", async () => {
    const result = await validateMutation((plan) => {
      delete plan.fixtureClassification;
    });
    expect(codes(result)).toContain("FIXTURE_CLASSIFICATION_MISMATCH");
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

  it("rejects disabling pinned-schema validation for a Context Pack", async () => {
    const result = await validateMutation((plan) => {
      (plan.contextPacks as JsonRecord[])[0]!.validateWithPinnedSchema = false;
    });
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it("rejects a claim scope reference found only in an unselected Context Pack", async () => {
    const [plan, input] = await Promise.all([
      loadCca210Plan(),
      loadCca210ValidationInput(),
    ]);
    const originalBytes = input.contextPackBytes.values().next().value as
      | Uint8Array
      | undefined;
    if (originalBytes === undefined) throw new Error("Context Pack fixture missing");
    const decoded = decodeStrictJsonObject<JsonRecord>(originalBytes);
    if (!decoded.valid) throw new Error("Context Pack fixture did not decode");
    const unselectedObjectId = "component.synthetic.unselected-receiver";
    const objects = decoded.value.objects as JsonRecord[];
    if (objects[0] === undefined) throw new Error("Context Pack object missing");
    objects[0].id = unselectedObjectId;
    objects[1]!.id = "component.synthetic.unselected-sender";
    (decoded.value.morphisms as JsonRecord[])[0]!.id =
      "morphism.synthetic.unselected-transfer";
    (decoded.value.diagrams as JsonRecord[])[0]!.id =
      "diagram.synthetic.unselected-flow";
    (decoded.value.acceptance_tests as JsonRecord[])[0]!.id =
      "acceptance.synthetic.unselected-render";
    const unselectedBytes = serializePlan(decoded.value);
    (plan.contextPacks as JsonRecord[]).push({
      id: "context.synthetic.cca-210-unselected",
      path: "fixtures/valid/cca-210/unselected-context-pack-v1.json",
      contractId: "context-pack/v1",
      sha256: digest(unselectedBytes),
      byteLength: unselectedBytes.byteLength,
      validateWithPinnedSchema: true,
    });
    const scopeRefs = claim(plan).scopeRefs as JsonRecord;
    scopeRefs.objectIds = [unselectedObjectId];

    const result = validateAeRenderPlan({
      ...input,
      planBytes: serializePlan(plan),
      contextPackBytes: new Map(input.contextPackBytes).set(
        "context.synthetic.cca-210-unselected",
        unselectedBytes,
      ),
    });
    expect(codes(result)).toContain("CONTEXT_SCOPE_REF_DANGLING");
  });

  it("rejects a dangling trust-boundary reference outside selected Context Packs", async () => {
    const result = await validateMutation((plan) => {
      const scope = (plan.scopeMapping as JsonRecord).scope as JsonRecord;
      const boundary = (scope.trustBoundaries as JsonRecord[])[0]!;
      boundary.scopeRefs = ["component.synthetic.not-selected"];
    });
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "CONTEXT_SCOPE_REF_DANGLING",
          path: "/scopeMapping/scope/trustBoundaries/0/scopeRefs/0",
        }),
      ]),
    );
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

  it("rejects omission of a rendered affected-property relationship", async () => {
    const [plan, input, requestBytes] = await Promise.all([
      loadCca210Plan(),
      loadCca210ValidationInput(),
      readRepositoryFile("fixtures/valid/cca-210/profile-request-v1.json"),
    ]);
    const threatCatalog = decodeStrictJsonObject<JsonRecord>(
      input.ccaInputBytes.threatCatalog,
    );
    const moduleCatalog = decodeStrictJsonObject<JsonRecord>(
      input.ccaInputBytes.capabilityModuleCatalog,
    );
    const request = decodeStrictJsonObject<JsonRecord>(requestBytes);
    if (!threatCatalog.valid || !moduleCatalog.valid || !request.valid) {
      throw new Error("CCA-210 profile inputs did not strict-decode");
    }

    const sourceThreat = (threatCatalog.value.threats as JsonRecord)[
      "threat.confidentiality.passive-message-disclosure"
    ] as JsonRecord;
    sourceThreat.affectedProperties = [
      "property.confidentiality.key-material",
      "property.confidentiality.message",
    ];
    const changedThreatBytes = serializePlan(threatCatalog.value);
    const changedThreatDigest = digest(changedThreatBytes);
    (((moduleCatalog.value.catalogBindings as JsonRecord).threatCatalog as JsonRecord)
      .digest as JsonRecord).value = changedThreatDigest;
    const changedModuleBytes = serializePlan(moduleCatalog.value);
    const changedModuleDigest = digest(changedModuleBytes);
    (((request.value.moduleCatalog as JsonRecord).digest as JsonRecord).value) =
      changedModuleDigest;
    const changedRequestBytes = serializePlan(request.value);
    const resolution = resolveProfile({
      propertyCatalogBytes: input.ccaInputBytes.propertyCatalog,
      attackerCatalogBytes: input.ccaInputBytes.attackerCatalog,
      threatCatalogBytes: changedThreatBytes,
      moduleCatalogBytes: changedModuleBytes,
      requestBytes: changedRequestBytes,
    });
    if (!resolution.valid) throw new Error(JSON.stringify(resolution.diagnostics));

    const changedInputs = {
      threatCatalog: changedThreatBytes,
      capabilityModuleCatalog: changedModuleBytes,
      resolvedProfile: resolution.bytes,
    } as const;
    for (const [role, bytes] of Object.entries(changedInputs)) {
      const binding = (plan.ccaInputs as JsonRecord)[role] as JsonRecord;
      binding.sha256 = digest(bytes);
      binding.byteLength = bytes.byteLength;
    }

    const result = validateAeRenderPlan({
      ...input,
      planBytes: serializePlan(plan),
      ccaInputBytes: { ...input.ccaInputBytes, ...changedInputs },
    });
    expect(codes(result)).toContain("RELATED_CLAIM_MAPPING_INCOMPLETE");
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

  it("rejects a rendered threat model without a generated claim surface", async () => {
    const result = await validateMutation((plan) => {
      for (const output of plan.outputs as JsonRecord[]) {
        if (
          output.artifactKind === "assurance-profile/v1" ||
          output.artifactKind === "security-claim/v1"
        ) {
          output.disposition = "unsupported";
          output.reason = "Synthetic fixture intentionally omits claim surfaces.";
          delete output.outputPath;
        }
      }
    });
    expect(codes(result)).toContain("OUTPUT_MAPPING_INCOMPLETE");
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

  it("summarizes informational diagnostic overflow without changing severity", () => {
    const diagnostics = Array.from(
      { length: maximumAeRenderDiagnostics + 1 },
      (_, index) => ({
        code: "SYNTHETIC_PROJECTION_LOSS",
        path: `/synthetic/${index}`,
        message: `Synthetic informational projection loss ${index}.`,
        severity: "information" as const,
      }),
    );
    expect(normalizeAeRenderDiagnostics(diagnostics, "information")).toEqual([
      {
        code: "DIAGNOSTIC_LIMIT_EXCEEDED",
        path: "",
        message: `More than ${maximumAeRenderDiagnostics} diagnostics were produced; details were suppressed.`,
        severity: "information",
      },
    ]);
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

  it("rejects caller-consistent arbitrary renderer identity bytes", async () => {
    const arbitrarySourceBytes = Buffer.from("arbitrary renderer source\n");
    const result = await validateMutation(
      (plan) => {
        (plan.renderer as JsonRecord).sourceSha256 = digest(arbitrarySourceBytes);
      },
      (input) => ({ ...input, rendererSourceBytes: arbitrarySourceBytes }),
    );
    expect(codes(result)).toContain("RENDER_PLAN_SCHEMA_INVALID");
  });

  it("rejects supplied renderer source bytes that drift from the fixed identity", async () => {
    const result = await validateMutation(
      () => undefined,
      (input) => ({
        ...input,
        rendererSourceBytes: Buffer.concat([
          Buffer.from(input.rendererSourceBytes),
          Buffer.from(" "),
        ]),
      }),
    );
    expect(codes(result)).toContain("RENDERER_IDENTITY_MISMATCH");
  });

  it.each([null, undefined, "invalid", 1, false, {}, new Map()])(
    "rejects malformed renderer source bytes without throwing: %p",
    async (rendererSourceBytes) => {
      const input = await loadCca210ValidationInput();
      const result = validateAeRenderPlan({
        ...input,
        rendererSourceBytes: rendererSourceBytes as unknown as Uint8Array,
      });
      expect(codes(result)).toContain("RENDERER_SOURCE_MISSING");
    },
  );

  it.each([{ planId: "forged" }, null, undefined, "forged", 1, false, [], new Map()])(
    "rejects direct rendering without a validated object token: %j",
    (token) => {
      const rendered = renderAeNativeArtifacts(
        token as unknown as Parameters<typeof renderAeNativeArtifacts>[0],
      );
      expect(rendered.valid).toBe(false);
      expect(rendered.outputs).toEqual([]);
      expect(rendered.diagnostics.map(({ code }) => code)).toEqual([
        "VALIDATED_PLAN_REQUIRED",
      ]);
    },
  );

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
