import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import {
  decodeStrictJsonObject,
  resolveProfile,
  validateCapabilityModuleCatalog,
  validateResolvedProfile,
  type ProfileDiagnosticCode,
  type ProfileResolutionInput,
  type ProfileResolutionResult,
} from "../packages/contracts/src/index.js";

const loadBytes = (relativePath: string): Promise<Buffer> =>
  readFile(new URL(relativePath, import.meta.url));

const syntheticCatalogInput = async () => ({
  propertyCatalogBytes: await loadBytes("../fixtures/valid/property-catalog-v1.json"),
  attackerCatalogBytes: await loadBytes("../fixtures/valid/attacker-catalog-v1.json"),
  threatCatalogBytes: await loadBytes("../fixtures/valid/threat-catalog-v1.json"),
  moduleCatalogBytes: await loadBytes(
    "../fixtures/valid/capability-module-catalog-v1.json",
  ),
});

const authoritativeCatalogInput = async () => ({
  propertyCatalogBytes: await loadBytes("../pack/catalogs/v1/property-catalog.json"),
  attackerCatalogBytes: await loadBytes("../pack/catalogs/v1/attacker-catalog.json"),
  threatCatalogBytes: await loadBytes("../pack/catalogs/v1/threat-catalog.json"),
  moduleCatalogBytes: await loadBytes(
    "../pack/modules/v1/capability-module-catalog.json",
  ),
});

const resolveFixture = async (requestFile: string): Promise<ProfileResolutionResult> =>
  resolveProfile({
    ...(await syntheticCatalogInput()),
    requestBytes: await loadBytes(requestFile),
  });

const codes = (
  result: { readonly diagnostics: readonly { readonly code: ProfileDiagnosticCode }[] },
): readonly ProfileDiagnosticCode[] => result.diagnostics.map((entry) => entry.code);

const requireSuccess = (result: ProfileResolutionResult) => {
  expect(result.valid).toBe(true);
  if (!result.valid) throw new Error(JSON.stringify(result.diagnostics));
  return result;
};

describe("CCA-130 deterministic profile resolution", () => {
  it("accepts both exact-byte-bound module catalogs", async () => {
    expect(validateCapabilityModuleCatalog(await authoritativeCatalogInput())).toEqual({
      valid: true,
      diagnostics: [],
    });
    expect(validateCapabilityModuleCatalog(await syntheticCatalogInput())).toEqual({
      valid: true,
      diagnostics: [],
    });
  });

  it("resolves a complete request to the exact golden bytes", async () => {
    const result = requireSuccess(
      await resolveFixture("../fixtures/valid/profile-request-complete-v1.json"),
    );
    expect(result.profile.state).toBe("complete");
    expect(Buffer.from(result.bytes)).toEqual(
      await loadBytes("../fixtures/valid/resolved-profile-complete-v1.json"),
    );
    expect(Object.values(result.profile.modules).every(({ state }) => state === "resolved"))
      .toBe(true);
  });

  it("expands transitive module dependencies", async () => {
    const result = requireSuccess(
      await resolveFixture("../fixtures/valid/profile-request-dependency-v1.json"),
    );
    expect(Object.keys(result.profile.modules)).toEqual([
      "module.synthetic.base",
      "module.synthetic.dependent",
    ]);
    expect(result.profile.modules["module.synthetic.base"]).toMatchObject({
      state: "resolved",
      requested: false,
      requiredBy: ["module.synthetic.dependent"],
    });
    expect(Object.keys(result.profile.selections.attackers)).toEqual([]);
  });

  it("preserves a syntactically valid absent module as unknown", async () => {
    const result = requireSuccess(
      await resolveFixture("../fixtures/valid/profile-request-unknown-v1.json"),
    );
    expect(result.profile).toMatchObject({
      state: "incomplete",
      modules: {
        "module.synthetic.absent": {
          id: "module.synthetic.absent",
          state: "unknown",
          requested: true,
          requiredBy: [],
        },
      },
    });
  });

  it("preserves an unsupported module, reason, scope, assumption, and exclusion", async () => {
    const result = requireSuccess(
      await resolveFixture("../fixtures/valid/profile-request-unsupported-v1.json"),
    );
    expect(result.profile.state).toBe("incomplete");
    expect(result.profile.modules["module.synthetic.unsupported"]).toMatchObject({
      state: "unsupported",
      reason: "The synthetic fixture deliberately represents unavailable scope.",
      scope: "synthetic unsupported resolution scenario",
    });
    expect(result.profile.assumptions).toEqual([
      expect.objectContaining({ sourceModuleId: "module.synthetic.unsupported" }),
    ]);
    expect(result.profile.exclusions).toEqual([
      expect.objectContaining({ sourceModuleId: "module.synthetic.unsupported" }),
    ]);
  });

  it("keeps both conflict sides and propagates unresolvable dependencies without a winner", async () => {
    const result = requireSuccess(
      await resolveFixture("../fixtures/valid/profile-request-conflict-v1.json"),
    );
    expect(result.profile.state).toBe("incomplete");
    expect(result.profile.modules["module.synthetic.conflict-a"]).toMatchObject({
      state: "unresolvable",
      conflictsWith: ["module.synthetic.conflict-b"],
    });
    expect(result.profile.modules["module.synthetic.conflict-b"]).toMatchObject({
      state: "unresolvable",
      conflictsWith: ["module.synthetic.conflict-a"],
    });
    expect(
      result.profile.modules["module.synthetic.depends-conflict-a"],
    ).toMatchObject({
      state: "unresolvable",
      unresolvedDependencies: ["module.synthetic.conflict-a"],
    });
    expect(Object.keys(result.profile.selections.properties)).toEqual([]);
  });

  it("normalizes request order to byte-identical output", async () => {
    const [left, right] = await Promise.all([
      resolveFixture("../fixtures/valid/profile-request-order-a-v1.json"),
      resolveFixture("../fixtures/valid/profile-request-order-b-v1.json"),
    ]);
    const leftSuccess = requireSuccess(left);
    const rightSuccess = requireSuccess(right);
    expect(Buffer.from(leftSuccess.bytes)).toEqual(Buffer.from(rightSuccess.bytes));
    expect(leftSuccess.profile.requestedModules).toEqual([
      "module.synthetic.contributor",
      "module.synthetic.dependent",
    ]);
  });

  it("records every contributing source module and reason without inferring attackers from threats", async () => {
    const result = requireSuccess(
      await resolveFixture("../fixtures/valid/profile-request-complete-v1.json"),
    );
    expect(result.profile.selections.capabilities["capability.network.observe"])
      .toEqual({
        id: "capability.network.observe",
        sources: [
          {
            sourceModuleId: "module.synthetic.contributor",
            inclusionReasons: ["attacker-capability"],
          },
          {
            sourceModuleId: "module.synthetic.dependent",
            inclusionReasons: ["threat-capability"],
          },
        ],
      });
    expect(result.profile.selections.attackers).toHaveProperty(
      "attacker.synthetic-bounded-model",
    );

    const dependencyOnly = requireSuccess(
      await resolveFixture("../fixtures/valid/profile-request-dependency-v1.json"),
    );
    expect(Object.keys(dependencyOnly.profile.selections.attackers)).toEqual([]);
  });

  it("expands property dependencies and retains their exact source-module reason", async () => {
    const input: ProfileResolutionInput = {
      ...(await authoritativeCatalogInput()),
      requestBytes: await loadBytes(
        "../fixtures/valid/profile-request-authoritative-dependency-v1.json",
      ),
    };
    const result = requireSuccess(resolveProfile(input));
    expect(
      result.profile.selections.properties["property.binding.context-epoch"]?.sources,
    ).toEqual(
      expect.arrayContaining([
        {
          sourceModuleId: "module.keys.derivation-separation",
          inclusionReasons: ["property-dependency"],
        },
      ]),
    );
    expect(
      result.profile.selections.properties["property.integrity.state"],
    ).toBeDefined();
  });

  it.each([
    ["key/ID mismatch", "module-catalog-key-id-mismatch.json", "MODULE_KEY_ID_MISMATCH"],
    ["dangling property", "module-catalog-dangling-property.json", "PROPERTY_SELECTION_DANGLING"],
    ["dangling capability", "module-catalog-dangling-capability.json", "CAPABILITY_SELECTION_DANGLING"],
    ["dangling attacker", "module-catalog-dangling-attacker.json", "ATTACKER_SELECTION_DANGLING"],
    ["dangling threat", "module-catalog-dangling-threat.json", "THREAT_SELECTION_DANGLING"],
    ["self dependency", "module-catalog-self-dependency.json", "MODULE_SELF_DEPENDENCY"],
    ["dangling dependency", "module-catalog-dangling-dependency.json", "MODULE_DEPENDENCY_DANGLING"],
    ["dependency cycle", "module-catalog-dependency-cycle.json", "MODULE_DEPENDENCY_CYCLE"],
    ["noncanonical conflict", "module-catalog-conflict-noncanonical.json", "CONFLICT_NON_CANONICAL"],
    ["reversed duplicate conflict", "module-catalog-conflict-reversed-duplicate.json", "CONFLICT_DUPLICATE"],
    ["dangling conflict", "module-catalog-conflict-dangling.json", "CONFLICT_MODULE_DANGLING"],
    ["intrinsic conflict", "module-catalog-intrinsic-conflict.json", "MODULE_INTRINSIC_CONFLICT"],
    ["catalog digest mismatch", "module-catalog-catalog-digest-mismatch.json", "BINDING_DIGEST_MISMATCH"],
  ] as const)("rejects %s with %s", async (_name, file, expectedCode) => {
    const input = await syntheticCatalogInput();
    input.moduleCatalogBytes = await loadBytes(`../fixtures/invalid/${file}`);
    expect(codes(validateCapabilityModuleCatalog(input))).toContain(expectedCode);
  });

  it.each([
    ["malformed module ID", "module-catalog-malformed-id.json"],
    ["duplicate selection", "module-catalog-duplicate-selection.json"],
    ["excessive selection", "module-catalog-excessive-selections.json"],
    ["duplicate dependency", "module-catalog-duplicate-dependency.json"],
    ["invalid unsupported form", "module-catalog-invalid-unsupported.json"],
    ["self conflict", "module-catalog-conflict-self.json"],
    ["unsafe safety", "module-catalog-unsafe-safety.json"],
    ["undeclared property", "module-catalog-undeclared-property.json"],
  ])("schema-rejects %s before resolution", async (_name, file) => {
    const input = await syntheticCatalogInput();
    input.moduleCatalogBytes = await loadBytes(`../fixtures/invalid/${file}`);
    expect(codes(validateCapabilityModuleCatalog(input))).toContain(
      "CONTRACT_SCHEMA_INVALID",
    );
  });

  it("returns diagnostics and no profile for catalog-byte digest mismatch", async () => {
    const input = await syntheticCatalogInput();
    const result = resolveProfile({
      ...input,
      propertyCatalogBytes: Buffer.concat([
        input.propertyCatalogBytes,
        Buffer.from("\n"),
      ]),
      requestBytes: await loadBytes(
        "../fixtures/valid/profile-request-complete-v1.json",
      ),
    });
    expect(result.valid).toBe(false);
    expect(codes(result)).toContain("BINDING_DIGEST_MISMATCH");
    expect(Object.hasOwn(result, "profile")).toBe(false);
  });

  it("returns diagnostics and no profile for module-catalog-byte digest mismatch", async () => {
    const input = await syntheticCatalogInput();
    const result = resolveProfile({
      ...input,
      moduleCatalogBytes: Buffer.concat([input.moduleCatalogBytes, Buffer.from("\n")]),
      requestBytes: await loadBytes(
        "../fixtures/valid/profile-request-complete-v1.json",
      ),
    });
    expect(result.valid).toBe(false);
    expect(codes(result)).toContain("BINDING_DIGEST_MISMATCH");
    expect(Object.hasOwn(result, "profile")).toBe(false);
  });

  it.each([
    "../fixtures/invalid/profile-request-duplicate-module.json",
    "../fixtures/invalid/profile-request-malformed-id.json",
  ])("schema-rejects invalid request %s with no resolved profile", async (requestFile) => {
    const result = resolveProfile({
      ...(await syntheticCatalogInput()),
      requestBytes: await loadBytes(requestFile),
    });
    expect(result.valid).toBe(false);
    expect(codes(result)).toContain("CONTRACT_SCHEMA_INVALID");
    expect(Object.hasOwn(result, "profile")).toBe(false);
  });

  it("rejects a valid-schema request whose exact module-catalog binding mismatches", async () => {
    const result = resolveProfile({
      ...(await syntheticCatalogInput()),
      requestBytes: await loadBytes(
        "../fixtures/invalid/profile-request-module-catalog-digest-mismatch.json",
      ),
    });
    expect(result.valid).toBe(false);
    expect(codes(result)).toContain("BINDING_DIGEST_MISMATCH");
  });

  it("rejects an inconsistent or non-canonical resolved profile", async () => {
    const base = {
      ...(await syntheticCatalogInput()),
      requestBytes: await loadBytes(
        "../fixtures/valid/profile-request-complete-v1.json",
      ),
    };
    expect(
      validateResolvedProfile({
        ...base,
        resolvedProfileBytes: await loadBytes(
          "../fixtures/valid/resolved-profile-complete-v1.json",
        ),
      }),
    ).toEqual({ valid: true, diagnostics: [] });
    expect(
      codes(
        validateResolvedProfile({
          ...base,
          resolvedProfileBytes: await loadBytes(
            "../fixtures/invalid/resolved-profile-inconsistent-v1.json",
          ),
        }),
      ),
    ).toEqual(["RESOLVED_PROFILE_INCONSISTENT"]);
  });

  it("strict-decodes all inputs before schema or semantic resolution", async () => {
    const result = resolveProfile({
      ...(await syntheticCatalogInput()),
      requestBytes: Buffer.from('{"profileId":"one","profile\\u0049d":"two"}'),
    });
    expect(result.valid).toBe(false);
    expect(codes(result)).toEqual(["JSON_DUPLICATE_MEMBER"]);
    expect(result.diagnostics[0]?.path).toBe("/request/profileId");
  });

  it("emits no execution/evidence status or mutable runtime identity", async () => {
    const result = requireSuccess(
      await resolveFixture("../fixtures/valid/profile-request-complete-v1.json"),
    );
    const decoded = decodeStrictJsonObject(Buffer.from(result.bytes));
    expect(decoded.valid).toBe(true);
    const forbidden = new Set([
      "status",
      "pass",
      "fail",
      "skip",
      "timeout",
      "tool-error",
      "not-run",
      "evidence",
      "approval",
      "timestamp",
      "runId",
      "hostname",
      "path",
    ]);
    const pending: unknown[] = result.valid ? [result.profile] : [];
    while (pending.length > 0) {
      const current = pending.pop();
      if (current === null || typeof current !== "object") continue;
      for (const [key, value] of Object.entries(current)) {
        expect(forbidden.has(key), key).toBe(false);
        pending.push(value);
      }
    }
  });
});
