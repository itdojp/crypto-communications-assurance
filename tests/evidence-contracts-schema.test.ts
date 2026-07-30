import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";

import { beforeAll, describe, expect, it } from "vitest";

import {
  compileContractBytes,
  decodeStrictJsonObject,
  executionStatuses,
  serializeEvidenceContract,
  type ContractBytesValidationResult,
} from "../packages/contracts/src/index.js";

const loadBytes = (relativePath: string): Promise<Buffer> =>
  readFile(new URL(relativePath, import.meta.url));
const loadJson = async <T extends object>(relativePath: string): Promise<T> => {
  const decoded = decodeStrictJsonObject<T>(await loadBytes(relativePath));
  if (!decoded.valid) throw new Error(`${relativePath}: strict decode failed`);
  return decoded.value;
};
const digest = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

describe("CCA-240 closed evidence contracts", () => {
  let execution: (bytes: Uint8Array) => ContractBytesValidationResult;
  let provenance: (bytes: Uint8Array) => ContractBytesValidationResult;
  let freshness: (bytes: Uint8Array) => ContractBytesValidationResult;
  let bindingSet: (bytes: Uint8Array) => ContractBytesValidationResult;
  let manifest: (bytes: Uint8Array) => ContractBytesValidationResult;

  beforeAll(async () => {
    const schemas = await Promise.all([
      loadJson("../schema/cryptocomm-execution-result-v1.schema.json"),
      loadJson("../schema/cryptocomm-evidence-provenance-v1.schema.json"),
      loadJson("../schema/cryptocomm-freshness-assessment-v1.schema.json"),
      loadJson("../schema/cryptocomm-evidence-binding-set-v1.schema.json"),
      loadJson("../schema/cryptocomm-pack-manifest-v1.schema.json"),
    ]);
    const validators = schemas.map((schema) => compileContractBytes(schema));
    const [executionValidator, provenanceValidator, freshnessValidator, bindingSetValidator, manifestValidator] = validators;
    if (
      executionValidator === undefined ||
      provenanceValidator === undefined ||
      freshnessValidator === undefined ||
      bindingSetValidator === undefined ||
      manifestValidator === undefined
    ) {
      throw new Error("CCA-240 schema validator initialization failed");
    }
    execution = executionValidator;
    provenance = provenanceValidator;
    freshness = freshnessValidator;
    bindingSet = bindingSetValidator;
    manifest = manifestValidator;
  });

  it("keeps exactly four new closed Draft 2020-12 contract IDs", async () => {
    const cases = [
      ["cryptocomm-execution-result-v1.schema.json", "cryptocomm-execution-result/v1"],
      ["cryptocomm-evidence-provenance-v1.schema.json", "cryptocomm-evidence-provenance/v1"],
      ["cryptocomm-freshness-assessment-v1.schema.json", "cryptocomm-freshness-assessment/v1"],
      ["cryptocomm-evidence-binding-set-v1.schema.json", "cryptocomm-evidence-binding-set/v1"],
    ] as const;
    for (const [file, contractId] of cases) {
      const schema = await loadJson<{
        $schema: string;
        additionalProperties: boolean;
        properties: { schemaVersion: { const: string } };
      }>(`../schema/${file}`);
      expect(schema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
      expect(schema.additionalProperties).toBe(false);
      expect(schema.properties.schemaVersion.const).toBe(contractId);
    }
  });

  it("strict-decodes and schema-validates every positive CCA-240 fixture", async () => {
    const names = (await readdir(new URL("../fixtures/valid/cca-240/", import.meta.url))).sort();
    expect(names).toHaveLength(21);
    for (const name of names) {
      const bytes = await loadBytes(`../fixtures/valid/cca-240/${name}`);
      const decoded = decodeStrictJsonObject<{ schemaVersion: string }>(bytes);
      expect(decoded.valid, name).toBe(true);
      if (!decoded.valid) continue;
      const validator =
        decoded.value.schemaVersion === "cryptocomm-execution-result/v1"
          ? execution
          : decoded.value.schemaVersion === "cryptocomm-evidence-provenance/v1"
            ? provenance
            : decoded.value.schemaVersion === "cryptocomm-freshness-assessment/v1"
              ? freshness
              : decoded.value.schemaVersion === "cryptocomm-evidence-binding-set/v1"
                ? bindingSet
                : manifest;
      expect(validator(bytes), name).toMatchObject({ valid: true, stage: "validated" });
    }
  });

  it("preserves all seven execution states literally", async () => {
    const files = [
      "execution-pass-v1.json",
      "execution-fail-v1.json",
      "execution-skip-v1.json",
      "execution-unsupported-v1.json",
      "execution-timeout-v1.json",
      "execution-tool-error-execution-v1.json",
      "execution-not-run-v1.json",
    ] as const;
    const values = await Promise.all(
      files.map((file) =>
        loadJson<{ status: string }>(`../fixtures/valid/cca-240/${file}`),
      ),
    );
    expect(values.map(({ status }) => status)).toEqual(executionStatuses);
  });

  it("keeps the machine-readable status and classification matrices exact", async () => {
    const statusMatrix = await loadJson<{
      statuses: Record<string, { permittedArtifactRoles: unknown }>;
    }>("../pack/evidence/v1/execution-status-matrix.json");
    expect(Object.keys(statusMatrix.statuses).sort()).toEqual(
      [...executionStatuses].sort(),
    );
    expect(statusMatrix.statuses["timeout"]?.permittedArtifactRoles).not.toContain(
      "substantive-result",
    );
    expect(statusMatrix.statuses["not-run"]?.permittedArtifactRoles).toEqual([
      "diagnostic",
      "log",
    ]);

    const classification = await loadJson<{
      rules: readonly {
        evidenceOrigin: string;
        useRestriction: string;
        allowed: boolean;
      }[];
    }>("../pack/evidence/v1/evidence-classification-matrix.json");
    expect(classification.rules).toContainEqual({
      evidenceOrigin: "synthetic",
      useRestriction: "policy-evaluable",
      allowed: false,
    });
    expect(classification.rules.filter(({ allowed }) => allowed)).toHaveLength(3);
  });

  it("enforces 64 input, artifact, and private-reference bounds", async () => {
    const result = await loadJson<Record<string, unknown>>(
      "../fixtures/valid/cca-240/execution-pass-v1.json",
    );
    const inputs = Array.from({ length: 64 }, (_, index) => ({
      inputId: `input.synthetic.i${index}`,
      digest: { algorithm: "sha256", value: index.toString(16).padStart(64, "0") },
      byteLength: index,
      mediaType: "application/json",
    }));
    const artifacts = Array.from({ length: 64 }, (_, index) => ({
      artifactId: `artifact.synthetic.a${index}`,
      role: "diagnostic",
    }));
    expect(
      execution(
        serializeEvidenceContract({ ...result, inputBindings: inputs, artifacts }),
      ).valid,
    ).toBe(true);
    expect(
      execution(
        serializeEvidenceContract({
          ...result,
          inputBindings: [...inputs, { ...inputs[0], inputId: "input.synthetic.overflow" }],
          artifacts,
        }),
      ).valid,
    ).toBe(false);
    expect(
      execution(
        serializeEvidenceContract({
          ...result,
          inputBindings: inputs,
          artifacts: [
            ...artifacts,
            { artifactId: "artifact.synthetic.overflow", role: "diagnostic" },
          ],
        }),
      ).valid,
    ).toBe(false);

    const privateProvenance = await loadJson<Record<string, unknown>>(
      "../fixtures/valid/cca-240/provenance-private-synthetic-test-only-v1.json",
    );
    const privateArtifacts = Array.from({ length: 64 }, (_, index) => ({
      kind: "private-opaque",
      artifactId: `artifact.synthetic.private-${index}`,
      classification: "private",
      role: "diagnostic",
      opaqueId: `opaque.SyntheticPrivate${index}`,
    }));
    expect(
      provenance(
        serializeEvidenceContract({
          ...privateProvenance,
          artifacts: privateArtifacts,
        }),
      ).valid,
    ).toBe(true);
    expect(
      provenance(
        serializeEvidenceContract({
          ...privateProvenance,
          artifacts: [
            ...privateArtifacts,
            {
              kind: "private-opaque",
              artifactId: "artifact.synthetic.private-overflow",
              classification: "private",
              role: "diagnostic",
              opaqueId: "opaque.SyntheticPrivateOverflow",
            },
          ],
        }),
      ).valid,
    ).toBe(false);
  });

  it("accepts 256 diagnostics and rejects 257", async () => {
    const result = await loadJson<Record<string, unknown>>(
      "../fixtures/valid/cca-240/execution-pass-v1.json",
    );
    const diagnostics = Array.from({ length: 256 }, (_, index) => ({
      code: "SYNTHETIC_DIAGNOSTIC",
      path: "",
      message: `Synthetic diagnostic ${index.toString().padStart(3, "0")}.`,
    }));
    expect(execution(serializeEvidenceContract({ ...result, diagnostics })).valid).toBe(
      true,
    );
    expect(
      execution(
        serializeEvidenceContract({
          ...result,
          diagnostics: [
            ...diagnostics,
            {
              code: "SYNTHETIC_DIAGNOSTIC",
              path: "",
              message: "Synthetic overflow diagnostic.",
            },
          ],
        }),
      ).valid,
    ).toBe(false);
  });

  it("accepts leap days and rejects impossible calendar timestamps", async () => {
    const executionValue = await loadJson<{
      execution: { startedAt: string; completedAt: string };
    }>("../fixtures/valid/cca-240/execution-pass-v1.json");
    const freshnessValue = await loadJson<{ asOf: string }>(
      "../fixtures/valid/cca-240/freshness-fresh-v1.json",
    );

    for (const date of ["2024-02-29", "2000-02-29", "2026-12-31"]) {
      expect(
        execution(
          serializeEvidenceContract({
            ...executionValue,
            execution: {
              ...executionValue.execution,
              startedAt: `${date}T12:00:00Z`,
              completedAt: `${date}T12:00:01.123456789Z`,
            },
          }),
        ).valid,
        date,
      ).toBe(true);
      expect(
        freshness(
          serializeEvidenceContract({
            ...freshnessValue,
            asOf: `${date}T12:00:00Z`,
          }),
        ).valid,
        date,
      ).toBe(true);
    }

    for (const date of ["1900-02-29", "2026-02-29", "2026-02-31", "2026-04-31"]) {
      expect(
        execution(
          serializeEvidenceContract({
            ...executionValue,
            execution: {
              ...executionValue.execution,
              startedAt: `${date}T12:00:00Z`,
              completedAt: `${date}T12:00:01Z`,
            },
          }),
        ).valid,
        date,
      ).toBe(false);
      expect(
        freshness(
          serializeEvidenceContract({
            ...freshnessValue,
            asOf: `${date}T12:00:00Z`,
          }),
        ).valid,
        date,
      ).toBe(false);
    }
  });

  it.each([
    "execution-missing-status-field.json",
    "execution-cross-status-field.json",
    "execution-timeout-substantive-result.json",
    "execution-preflight-partial-role.json",
    "execution-not-run-substantive-result.json",
    "execution-timeout-missing-limit.json",
    "execution-abbreviated-git-revision.json",
    "execution-mutable-branch-identity.json",
    "execution-diagnostic-limit-overflow.json",
  ])("schema-rejects status, identity, role, or bound violation: %s", async (file) => {
    expect(execution(await loadBytes(`../fixtures/invalid/cca-240/${file}`)).valid).toBe(false);
  });

  it("rejects every approval, satisfaction, certification, release, finding, no-findings, and proof promotion field", async () => {
    const names = (await readdir(new URL("../fixtures/invalid/cca-240/", import.meta.url)))
      .filter((name) => name.startsWith("execution-promotion-"))
      .sort();
    expect(names).toHaveLength(7);
    for (const name of names) {
      expect(execution(await loadBytes(`../fixtures/invalid/cca-240/${name}`)).valid, name).toBe(false);
    }
  });

  it("allows only the three approved origin/use combinations literally", async () => {
    const fixture = await loadJson<Record<string, unknown>>(
      "../fixtures/valid/cca-240/provenance-public-synthetic-test-only-v1.json",
    );
    const unmarked = structuredClone(fixture);
    delete unmarked.fixtureClassification;
    const candidates = [
      fixture,
      { ...unmarked, evidenceOrigin: "real", useRestriction: "test-only" },
      { ...unmarked, evidenceOrigin: "real", useRestriction: "policy-evaluable" },
    ];
    const combinations = candidates.map(
      (candidate) => `${String(candidate.evidenceOrigin)}+${String(candidate.useRestriction)}`,
    );
    expect(combinations).toEqual([
      "synthetic+test-only",
      "real+test-only",
      "real+policy-evaluable",
    ]);
    for (const candidate of candidates) {
      expect(provenance(serializeEvidenceContract(candidate)).valid).toBe(true);
    }
    for (const file of [
      "provenance-synthetic-policy-evaluable.json",
      "provenance-fixture-real-test-only.json",
      "provenance-fixture-real-policy-evaluable.json",
    ]) {
      expect(
        provenance(await loadBytes(`../fixtures/invalid/cca-240/${file}`)).valid,
        file,
      ).toBe(false);
    }
  });

  it("closes the private-opaque surface against every prohibited public metadata field", async () => {
    const names = (await readdir(new URL("../fixtures/invalid/cca-240/", import.meta.url)))
      .filter((name) => name.startsWith("provenance-private-forbidden-"))
      .sort();
    expect(names).toHaveLength(7);
    for (const name of names) {
      expect(provenance(await loadBytes(`../fixtures/invalid/cca-240/${name}`)).valid, name).toBe(false);
    }
  });

  it("closes recorded environment against hostname, credential, customer, and path fields", async () => {
    const names = (await readdir(new URL("../fixtures/invalid/cca-240/", import.meta.url)))
      .filter((name) => name.startsWith("provenance-environment-forbidden-"))
      .sort();
    expect(names).toHaveLength(4);
    for (const name of names) {
      expect(provenance(await loadBytes(`../fixtures/invalid/cca-240/${name}`)).valid, name).toBe(false);
    }
  });

  it("rejects origin/use promotion surfaces and undeclared approval fields", async () => {
    for (const file of [
      "provenance-origin-promotion-attempt.json",
      "provenance-use-promotion-attempt.json",
      "freshness-approval-promotion.json",
      "binding-set-aggregate-status.json",
    ]) {
      const bytes = await loadBytes(`../fixtures/invalid/cca-240/${file}`);
      const validator = file.startsWith("provenance")
        ? provenance
        : file.startsWith("freshness")
          ? freshness
          : bindingSet;
      expect(validator(bytes).valid, file).toBe(false);
    }
  });

  it("requires an explicit freshness artifact in every binding set", async () => {
    expect(
      bindingSet(
        await loadBytes("../fixtures/invalid/cca-240/binding-set-missing-freshness.json"),
      ).valid,
    ).toBe(false);
  });

  it("content-binds representative CCA-240 artifacts from the synthetic CCA-110 manifest", async () => {
    const fixture = await loadJson<{
      fixtureClassification: string;
      artifacts: Record<string, { digest: { value: string } }>;
    }>("../fixtures/valid/cca-240/cca-110-cca-240-manifest-v1.json");
    expect(fixture.fixtureClassification).toBe("synthetic-test-only");
    expect(Object.keys(fixture.artifacts)).toHaveLength(4);
    for (const [path, declaration] of Object.entries(fixture.artifacts)) {
      expect(declaration.digest.value, path).toBe(digest(await readFile(new URL(`../${path}`, import.meta.url))));
    }
  });
});
