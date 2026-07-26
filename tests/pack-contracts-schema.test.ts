import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { beforeAll, describe, expect, it } from "vitest";

import { compileContract, type ValidationResult } from "../packages/contracts/src/index.js";

const loadBytes = (relativePath: string): Promise<Buffer> =>
  readFile(new URL(relativePath, import.meta.url));

const loadJson = async (relativePath: string): Promise<unknown> =>
  JSON.parse((await loadBytes(relativePath)).toString("utf8")) as unknown;

const digest = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

describe("CCA-110 JSON Schema contracts", () => {
  let validateManifest: (candidate: unknown) => ValidationResult;
  let validateLock: (candidate: unknown) => ValidationResult;
  let validateCompatibility: (candidate: unknown) => ValidationResult;

  beforeAll(async () => {
    const [manifestSchema, lockSchema, compatibilitySchema] = await Promise.all([
      loadJson("../schema/cryptocomm-pack-manifest-v1.schema.json"),
      loadJson("../schema/cryptocomm-pack-lock-v1.schema.json"),
      loadJson("../schema/cryptocomm-compatibility-record-v1.schema.json"),
    ]);
    validateManifest = compileContract(manifestSchema as object);
    validateLock = compileContract(lockSchema as object);
    validateCompatibility = compileContract(compatibilitySchema as object);
  });

  it.each([
    [
      "cryptocomm-pack-manifest/v1",
      "../fixtures/valid/pack-manifest-v1.json",
      () => validateManifest,
    ],
    [
      "cryptocomm-pack-lock/v1",
      "../fixtures/valid/pack-lock-v1.json",
      () => validateLock,
    ],
    [
      "cryptocomm-compatibility-record/v1 unknown",
      "../fixtures/valid/compatibility-unknown-v1.json",
      () => validateCompatibility,
    ],
    [
      "cryptocomm-compatibility-record/v1 compatible",
      "../fixtures/valid/compatibility-compatible-v1.json",
      () => validateCompatibility,
    ],
  ])("accepts the explicitly synthetic %s fixture", async (_name, path, validator) => {
    const fixture = await loadJson(path);
    expect(validator()(fixture)).toEqual({ valid: true, errors: [] });
    expect(fixture).toMatchObject({ fixtureClassification: "synthetic-test-only" });
  });

  it("binds the lock and compatibility subjects to exact manifest bytes", async () => {
    const manifestBytes = await loadBytes("../fixtures/valid/pack-manifest-v1.json");
    const expected = digest(manifestBytes);
    const lock = (await loadJson("../fixtures/valid/pack-lock-v1.json")) as {
      manifest: { digest: { value: string } };
    };
    const unknown = (await loadJson("../fixtures/valid/compatibility-unknown-v1.json")) as {
      subject: { manifestDigest: { value: string } };
    };
    const compatible = (await loadJson(
      "../fixtures/valid/compatibility-compatible-v1.json",
    )) as {
      subject: { manifestDigest: { value: string } };
    };

    expect(lock.manifest.digest.value).toBe(expected);
    expect(unknown.subject.manifestDigest.value).toBe(expected);
    expect(compatible.subject.manifestDigest.value).toBe(expected);
  });

  it("binds every resolved compatibility record to exact record bytes", async () => {
    const lock = (await loadJson("../fixtures/valid/pack-lock-v1.json")) as {
      compatibilityRecords: Record<string, { digest: { value: string } }>;
    };
    const cases = [
      ["synthetic-unknown-record", "../fixtures/valid/compatibility-unknown-v1.json"],
      [
        "synthetic-compatible-record",
        "../fixtures/valid/compatibility-compatible-v1.json",
      ],
    ] as const;

    for (const [recordId, path] of cases) {
      expect(lock.compatibilityRecords[recordId]?.digest.value).toBe(
        digest(await loadBytes(path)),
      );
    }
  });

  it("content-binds exact synthetic artifact and evidence bytes", async () => {
    const manifest = (await loadJson("../fixtures/valid/pack-manifest-v1.json")) as {
      artifacts: Record<string, { digest: { value: string } }>;
    };
    const compatible = (await loadJson(
      "../fixtures/valid/compatibility-compatible-v1.json",
    )) as {
      evidence: Record<string, { digest: { value: string } }>;
    };

    for (const [path, declaration] of Object.entries(manifest.artifacts)) {
      expect(digest(await loadBytes("../" + path))).toBe(declaration.digest.value);
    }
    for (const [path, reference] of Object.entries(compatible.evidence)) {
      expect(digest(await loadBytes("../" + path))).toBe(reference.digest.value);
    }
  });

  it.each([
    [
      "unsafe artifact path",
      "../fixtures/invalid/pack-manifest-unsafe-artifact-path.json",
      () => validateManifest,
      "propertyNames",
    ],
    [
      "missing media type",
      "../fixtures/invalid/pack-manifest-missing-media-type.json",
      () => validateManifest,
      "required",
    ],
    [
      "invalid digest",
      "../fixtures/invalid/pack-manifest-invalid-digest.json",
      () => validateManifest,
      "pattern",
    ],
    [
      "undeclared manifest property",
      "../fixtures/invalid/pack-manifest-undeclared-property.json",
      () => validateManifest,
      "additionalProperties",
    ],
    [
      "missing resolver identity",
      "../fixtures/invalid/pack-lock-missing-resolver.json",
      () => validateLock,
      "required",
    ],
    [
      "timestamp and local path identity",
      "../fixtures/invalid/pack-lock-forbidden-runtime-identity.json",
      () => validateLock,
      "additionalProperties",
    ],
    [
      "compatible without evidence",
      "../fixtures/invalid/compatibility-compatible-missing-evidence.json",
      () => validateCompatibility,
      "required",
    ],
    [
      "incompatible without evidence",
      "../fixtures/invalid/compatibility-incompatible-missing-evidence.json",
      () => validateCompatibility,
      "required",
    ],
    [
      "unsupported without reason",
      "../fixtures/invalid/compatibility-unsupported-missing-reason.json",
      () => validateCompatibility,
      "required",
    ],
    [
      "unknown compatibility state",
      "../fixtures/invalid/compatibility-unknown-state.json",
      () => validateCompatibility,
      "enum",
    ],
  ])("rejects synthetic negative fixture: %s", async (_name, path, validator, keyword) => {
    const candidate = await loadJson(path);
    const validation = validator()(candidate);

    expect(candidate).toMatchObject({ fixtureClassification: "synthetic-test-only" });
    expect(validation.valid).toBe(false);
    if (!validation.valid) {
      expect(validation.errors.some((error) => error.keyword === keyword)).toBe(true);
    }
  });

  it("accepts evidence-backed incompatible and bounded unsupported states", async () => {
    const compatible = (await loadJson(
      "../fixtures/valid/compatibility-compatible-v1.json",
    )) as Record<string, unknown>;
    const unknown = (await loadJson(
      "../fixtures/valid/compatibility-unknown-v1.json",
    )) as Record<string, unknown>;

    const incompatible = structuredClone(compatible);
    incompatible.state = "incompatible";
    expect(validateCompatibility(incompatible)).toEqual({ valid: true, errors: [] });

    const unsupported = structuredClone(unknown);
    unsupported.state = "unsupported";
    unsupported.unsupported = {
      reason: "Synthetic target contract is outside this test profile.",
      scope: "synthetic-target-adapter",
    };
    expect(validateCompatibility(unsupported)).toEqual({ valid: true, errors: [] });
  });

  it("rejects evidence on unknown because unknown makes no compatibility claim", async () => {
    const unknown = (await loadJson(
      "../fixtures/valid/compatibility-unknown-v1.json",
    )) as Record<string, unknown>;
    unknown.evidence = {
      "fixtures/artifacts/synthetic-compatibility-evidence.json": {
        digest: { algorithm: "sha256", value: "0".repeat(64) },
        mediaType: "application/json",
        evidenceType: "synthetic-test-result",
      },
    };

    expect(validateCompatibility(unknown).valid).toBe(false);
  });

  it.each([
    "ae-framework/assurance-profile/v1",
    "genai-repo-auditor/audit-context/v1",
  ])("accepts a generic hierarchical target contract ID: %s", async (contractId) => {
    const candidate = (await loadJson(
      "../fixtures/valid/compatibility-unknown-v1.json",
    )) as Record<string, unknown> & {
      target: { contract: { contractId: string } };
    };
    candidate.target.contract.contractId = contractId;

    expect(validateCompatibility(candidate)).toEqual({ valid: true, errors: [] });
  });

  it("keeps the evidence payload explicitly synthetic and test-only", async () => {
    expect(
      await loadJson("../fixtures/artifacts/synthetic-compatibility-evidence.json"),
    ).toMatchObject({ classification: "synthetic-test-only" });
  });

  it("keeps all three schemas closed Draft 2020-12 contracts", async () => {
    for (const path of [
      "../schema/cryptocomm-pack-manifest-v1.schema.json",
      "../schema/cryptocomm-pack-lock-v1.schema.json",
      "../schema/cryptocomm-compatibility-record-v1.schema.json",
    ]) {
      const schema = (await loadJson(path)) as Record<string, unknown>;
      expect(schema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
      expect(schema.additionalProperties).toBe(false);
    }
  });
});
