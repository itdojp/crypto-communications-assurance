import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { beforeAll, describe, expect, it } from "vitest";

import {
  compileContractBytes,
  type ContractBytesValidationResult,
  decodeStrictJsonObject,
} from "../packages/contracts/src/index.js";

const loadBytes = (relativePath: string): Promise<Buffer> =>
  readFile(new URL(relativePath, import.meta.url));

const loadJson = async (relativePath: string): Promise<unknown> =>
  JSON.parse((await loadBytes(relativePath)).toString("utf8")) as unknown;

const loadContractObject = async (
  relativePath: string,
): Promise<Readonly<Record<string, unknown>>> => {
  const decoded = decodeStrictJsonObject(await loadBytes(relativePath));
  if (!decoded.valid) throw new Error(`${relativePath} failed strict decoding`);
  return decoded.value;
};

const jsonBytes = (value: unknown): Buffer =>
  Buffer.from(JSON.stringify(value), "utf8");

const digest = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

describe("CCA-110 JSON Schema contracts", () => {
  let validateManifest: (candidate: Uint8Array) => ContractBytesValidationResult;
  let validateLock: (candidate: Uint8Array) => ContractBytesValidationResult;
  let validateCompatibility: (candidate: Uint8Array) => ContractBytesValidationResult;

  beforeAll(async () => {
    const [manifestSchema, lockSchema, compatibilitySchema] = await Promise.all([
      loadJson("../schema/cryptocomm-pack-manifest-v1.schema.json"),
      loadJson("../schema/cryptocomm-pack-lock-v1.schema.json"),
      loadJson("../schema/cryptocomm-compatibility-record-v1.schema.json"),
    ]);
    validateManifest = compileContractBytes(manifestSchema as object);
    validateLock = compileContractBytes(lockSchema as object);
    validateCompatibility = compileContractBytes(compatibilitySchema as object);
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
    const validation = validator()(await loadBytes(path));
    expect(validation.valid).toBe(true);
    if (validation.valid) {
      expect(validation.stage).toBe("validated");
      expect(validation.value).toMatchObject({
        fixtureClassification: "synthetic-test-only",
      });
    }
  });

  it.each([
    [
      "manifest",
      "../fixtures/valid/pack-manifest-v1.json",
      '"packId":"synthetic-shadow-pack",',
      () => validateManifest,
    ],
    [
      "lock",
      "../fixtures/valid/pack-lock-v1.json",
      '"packVersion":"9.9.9-synthetic.9",',
      () => validateLock,
    ],
    [
      "compatibility record",
      "../fixtures/valid/compatibility-unknown-v1.json",
      String.raw`"record\u0049d":"synthetic-shadow-record",`,
      () => validateCompatibility,
    ],
  ])(
    "rejects a duplicate decoded member before %s schema validation",
    async (_name, path, injectedMember, validator) => {
      const original = await loadBytes(path);
      const candidate = Buffer.concat([
        Buffer.from(`{${injectedMember}`, "utf8"),
        original.subarray(1),
      ]);
      const validation = validator()(candidate);

      expect(validation.valid).toBe(false);
      if (!validation.valid) {
        expect(validation.stage).toBe("decode");
        if (validation.stage === "decode") {
          expect(validation.errors).toMatchObject([
            { code: "JSON_DUPLICATE_MEMBER" },
          ]);
        }
      }
    },
  );

  it("binds the lock and compatibility subjects to exact manifest bytes", async () => {
    const manifestBytes = await loadBytes("../fixtures/valid/pack-manifest-v1.json");
    const expected = digest(manifestBytes);
    const lock = (await loadContractObject("../fixtures/valid/pack-lock-v1.json")) as {
      manifest: { digest: { value: string } };
    };
    const unknown = (await loadContractObject("../fixtures/valid/compatibility-unknown-v1.json")) as {
      subject: { manifestDigest: { value: string } };
    };
    const compatible = (await loadContractObject(
      "../fixtures/valid/compatibility-compatible-v1.json",
    )) as {
      subject: { manifestDigest: { value: string } };
    };

    expect(lock.manifest.digest.value).toBe(expected);
    expect(unknown.subject.manifestDigest.value).toBe(expected);
    expect(compatible.subject.manifestDigest.value).toBe(expected);
  });

  it("binds every resolved compatibility record to exact record bytes", async () => {
    const lock = (await loadContractObject("../fixtures/valid/pack-lock-v1.json")) as {
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
    const manifest = (await loadContractObject("../fixtures/valid/pack-manifest-v1.json")) as {
      artifacts: Record<string, { digest: { value: string } }>;
    };
    const compatible = (await loadContractObject(
      "../fixtures/valid/compatibility-compatible-v1.json",
    )) as {
      evidence: Record<string, { digest: { value: string } }>;
    };

    for (const [path, declaration] of Object.entries(manifest.artifacts)) {
      expect(digest(await loadBytes("../" + path))).toBe(declaration.digest.value);
    }
    const evidenceFixtureById: Readonly<Record<string, string>> = {
      "evidence/synthetic-compatibility-result":
        "../fixtures/artifacts/synthetic-compatibility-evidence.json",
    };
    for (const [identifier, reference] of Object.entries(compatible.evidence)) {
      const fixturePath = evidenceFixtureById[identifier];
      expect(fixturePath).toBeDefined();
      if (fixturePath !== undefined) {
        expect(digest(await loadBytes(fixturePath))).toBe(reference.digest.value);
      }
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
    [
      "network evidence identifier",
      "../fixtures/invalid/compatibility-invalid-evidence-identifier-v1.json",
      () => validateCompatibility,
      "pattern",
    ],
  ])("rejects synthetic negative fixture: %s", async (_name, path, validator, keyword) => {
    const candidate = await loadContractObject(path);
    const validation = validator()(await loadBytes(path));

    expect(candidate).toMatchObject({ fixtureClassification: "synthetic-test-only" });
    expect(validation.valid).toBe(false);
    if (!validation.valid) {
      expect(validation.stage).toBe("schema");
      if (validation.stage === "schema") {
        expect(validation.errors.some((error) => error.keyword === keyword)).toBe(true);
      }
    }
  });

  it("accepts evidence-backed incompatible and bounded unsupported states", async () => {
    const compatible = (await loadContractObject(
      "../fixtures/valid/compatibility-compatible-v1.json",
    )) as Record<string, unknown>;
    const unknown = (await loadContractObject(
      "../fixtures/valid/compatibility-unknown-v1.json",
    )) as Record<string, unknown>;

    const incompatible = structuredClone(compatible);
    incompatible.state = "incompatible";
    expect(validateCompatibility(jsonBytes(incompatible)).valid).toBe(true);

    const unsupported = structuredClone(unknown);
    unsupported.state = "unsupported";
    unsupported.unsupported = {
      reason: "Synthetic target contract is outside this test profile.",
      scope: "synthetic-target-adapter",
    };
    expect(validateCompatibility(jsonBytes(unsupported)).valid).toBe(true);
  });

  it("rejects evidence on unknown because unknown makes no compatibility claim", async () => {
    const unknown = (await loadContractObject(
      "../fixtures/valid/compatibility-unknown-v1.json",
    )) as Record<string, unknown>;
    unknown.evidence = {
      "evidence/synthetic-unknown-result": {
        digest: { algorithm: "sha256", value: "0".repeat(64) },
        mediaType: "application/json",
        evidenceType: "synthetic-test-result",
      },
    };

    expect(validateCompatibility(jsonBytes(unknown)).valid).toBe(false);
  });

  it.each([
    "ae-framework/assurance-profile/v1",
    "genai-repo-auditor/audit-context/v1",
  ])("accepts a generic hierarchical target contract ID: %s", async (contractId) => {
    const candidate = (await loadContractObject(
      "../fixtures/valid/compatibility-unknown-v1.json",
    )) as Record<string, unknown> & {
      target: { contract: { contractId: string } };
    };
    candidate.target.contract.contractId = contractId;

    expect(validateCompatibility(jsonBytes(candidate)).valid).toBe(true);
  });

  it.each([
    ["manifest producer", "manifest"],
    ["lock resolver", "lock"],
    ["compatibility target", "compatibility"],
  ] as const)(
    "rejects a leading-zero numeric SemVer prerelease in the %s identity",
    async (_name, contract) => {
      if (contract === "manifest") {
        const candidate = (await loadContractObject(
          "../fixtures/valid/pack-manifest-v1.json",
        )) as { producer: { version: string } };
        candidate.producer.version = "1.2.3-01";
        expect(validateManifest(jsonBytes(candidate)).valid).toBe(false);
        return;
      }
      if (contract === "lock") {
        const candidate = (await loadContractObject(
          "../fixtures/valid/pack-lock-v1.json",
        )) as { resolver: { version: string } };
        candidate.resolver.version = "1.2.3-01";
        expect(validateLock(jsonBytes(candidate)).valid).toBe(false);
        return;
      }

      const candidate = (await loadContractObject(
        "../fixtures/valid/compatibility-unknown-v1.json",
      )) as { target: { implementation: { version: string } } };
      candidate.target.implementation.version = "1.2.3-01";
      expect(validateCompatibility(jsonBytes(candidate)).valid).toBe(false);
    },
  );

  it.each([
    "github:itdojp/repository",
    "https://example.invalid/evidence",
    "/var/private/evidence",
    "../private/evidence",
    String.raw`C:\private\evidence`,
    "evidence//result",
    "evidence/" + "a".repeat(257),
    "a/b/c/d/e/f/g/h/i",
  ])("rejects a non-bundle-relative evidence identifier: %s", async (identifier) => {
    const candidate = (await loadContractObject(
      "../fixtures/valid/compatibility-compatible-v1.json",
    )) as Record<string, unknown> & { evidence: Record<string, unknown> };
    const reference = Object.values(candidate.evidence)[0];
    if (reference === undefined) throw new Error("Expected evidence fixture");
    candidate.evidence = { [identifier]: reference };

    const validation = validateCompatibility(jsonBytes(candidate));
    expect(validation.valid).toBe(false);
    if (!validation.valid) expect(validation.stage).toBe("schema");
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
