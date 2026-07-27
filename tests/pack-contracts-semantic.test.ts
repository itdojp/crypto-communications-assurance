import { readFile } from "node:fs/promises";

import { beforeAll, describe, expect, it } from "vitest";

import {
  type CompatibilityRecord,
  type CompatibilityState,
  decodeStrictJsonObject,
  maximumContractJsonBytes,
  type PackLock,
  type PackManifest,
  validateCompatibilityRecordBinding,
  validateLegacyCompatibilityMigration,
  validateManifestLockBinding,
  validatePackResolution,
} from "../packages/contracts/src/index.js";

type Mutable<T> = T extends object
  ? { -readonly [Key in keyof T]: Mutable<T[Key]> }
  : T;

const mutableClone = <T>(value: T): Mutable<T> =>
  structuredClone(value) as Mutable<T>;

const loadBytes = (relativePath: string): Promise<Buffer> =>
  readFile(new URL(relativePath, import.meta.url));

const loadStrictObject = async <T extends object>(relativePath: string): Promise<T> => {
  const decoded = decodeStrictJsonObject<T>(await loadBytes(relativePath));
  if (!decoded.valid) {
    throw new Error(
      `${relativePath} did not strict-decode: ${decoded.diagnostics
        .map((entry) => entry.code)
        .join(", ")}`,
    );
  }
  return decoded.value;
};

const jsonBytes = (value: unknown): Buffer =>
  Buffer.from(JSON.stringify(value), "utf8");

const sha256Value = async (bytes: Uint8Array): Promise<string> => {
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(bytes).digest("hex");
};

describe("CCA-110 semantic bindings", () => {
  let manifest: PackManifest;
  let manifestBytes: Buffer;
  let lock: PackLock;
  let lockBytes: Buffer;
  let unknown: CompatibilityRecord;
  let unknownBytes: Buffer;
  let compatible: CompatibilityRecord;
  let compatibleBytes: Buffer;
  let conflictingBytes: Buffer;
  let duplicatePairLockBytes: Buffer;

  beforeAll(async () => {
    [
      manifest,
      manifestBytes,
      lock,
      lockBytes,
      unknown,
      unknownBytes,
      compatible,
      compatibleBytes,
      conflictingBytes,
      duplicatePairLockBytes,
    ] = await Promise.all([
      loadStrictObject<PackManifest>("../fixtures/valid/pack-manifest-v1.json"),
      loadBytes("../fixtures/valid/pack-manifest-v1.json"),
      loadStrictObject<PackLock>("../fixtures/valid/pack-lock-v1.json"),
      loadBytes("../fixtures/valid/pack-lock-v1.json"),
      loadStrictObject<CompatibilityRecord>(
        "../fixtures/valid/compatibility-unknown-v1.json",
      ),
      loadBytes("../fixtures/valid/compatibility-unknown-v1.json"),
      loadStrictObject<CompatibilityRecord>(
        "../fixtures/valid/compatibility-compatible-v1.json",
      ),
      loadBytes("../fixtures/valid/compatibility-compatible-v1.json"),
      loadBytes("../fixtures/invalid/compatibility-conflicting-same-pair-v1.json"),
      loadBytes("../fixtures/invalid/pack-lock-duplicate-subject-target-v1.json"),
    ]);
  });

  const codes = (
    validation: ReturnType<typeof validateManifestLockBinding>,
  ): readonly string[] => validation.diagnostics.map((entry) => entry.code);

  it("accepts exact strict-decoded manifest, lock, record bytes, and distinct pairs", () => {
    expect(
      validatePackResolution({
        manifestBytes,
        lockBytes,
        compatibilityRecordBytes: {
          "synthetic-unknown-record": unknownBytes,
          "synthetic-compatible-record": compatibleBytes,
        },
      }),
    ).toEqual({ valid: true, diagnostics: [] });
  });

  it("derives the lock object from the exact supplied lock bytes", () => {
    const candidate = mutableClone(lock);
    candidate.packId = "synthetic-other-pack";

    expect(codes(validateManifestLockBinding(manifestBytes, jsonBytes(candidate)))).toContain(
      "PACK_ID_MISMATCH",
    );
  });

  it("detects MANIFEST_DIGEST_MISMATCH over exact bytes", () => {
    const candidate = mutableClone(lock);
    candidate.manifest.digest.value = "0".repeat(64);

    expect(
      validateManifestLockBinding(manifestBytes, jsonBytes(candidate)).diagnostics,
    ).toContainEqual({
      code: "MANIFEST_DIGEST_MISMATCH",
      path: "/lock/manifest/digest",
      message: "The lock does not bind the exact supplied manifest bytes.",
    });
  });

  it("derives the manifest identity from the exact bytes being hashed", () => {
    const candidate = mutableClone(manifest);
    candidate.packId = "synthetic-other-pack";

    expect(codes(validateManifestLockBinding(jsonBytes(candidate), lockBytes))).toEqual([
      "MANIFEST_DIGEST_MISMATCH",
      "PACK_ID_MISMATCH",
    ]);
  });

  it.each([
    ["PACK_ID_MISMATCH", "/lock/packId", (candidate: Mutable<PackLock>) => {
      candidate.packId = "synthetic-other-pack";
    }],
    ["PACK_VERSION_MISMATCH", "/lock/packVersion", (candidate: Mutable<PackLock>) => {
      candidate.packVersion = "0.2.0-synthetic.1";
    }],
    ["SOURCE_IDENTITY_MISMATCH", "/lock/manifest/source", (candidate: Mutable<PackLock>) => {
      candidate.manifest.source.revision.value = "9".repeat(40);
    }],
    ["IMPLEMENTATION_IDENTITY_INVALID", "/lock/resolver", (candidate: Mutable<PackLock>) => {
      candidate.resolver.sourceRevision.value = "main";
    }],
  ] as const)("detects %s at its artifact-rooted path", (expectedCode, path, mutate) => {
    const candidate = mutableClone(lock);
    mutate(candidate);
    expect(
      validateManifestLockBinding(manifestBytes, jsonBytes(candidate)).diagnostics,
    ).toEqual(expect.arrayContaining([expect.objectContaining({ code: expectedCode, path })]));
  });

  it("roots producer identity diagnostics at the manifest", () => {
    const candidate = mutableClone(manifest);
    candidate.producer.sourceRevision.value = "main";

    expect(
      validateManifestLockBinding(jsonBytes(candidate), lockBytes).diagnostics,
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "IMPLEMENTATION_IDENTITY_INVALID",
          path: "/manifest/producer",
        }),
      ]),
    );
  });

  it("rejects a SemVer numeric prerelease identifier with a leading zero", () => {
    const candidate = mutableClone(lock);
    candidate.resolver.version = "1.2.3-01";

    expect(codes(validateManifestLockBinding(manifestBytes, jsonBytes(candidate)))).toContain(
      "IMPLEMENTATION_IDENTITY_INVALID",
    );
  });

  it.each([
    "0.0.0",
    "1.2.3-0",
    "1.2.3-alpha.01x",
    "1.2.3+01",
    "1.2.3-alpha-1+build.01",
  ])("accepts a bounded valid resolver SemVer: %s", (version) => {
    const candidate = mutableClone(lock);
    candidate.resolver.version = version;

    expect(validateManifestLockBinding(manifestBytes, jsonBytes(candidate))).toEqual({
      valid: true,
      diagnostics: [],
    });
  });

  it.each([
    "01.2.3",
    "1.02.3",
    "1.2.03",
    "1.2.3-01",
    "1.2.3-alpha.01",
    "1.2.3-",
    "1.2.3+",
    "1.2.3+build+again",
    "0.0.0-0." + "--.".repeat(64),
  ])("rejects an invalid or unbounded resolver SemVer: %s", (version) => {
    const candidate = mutableClone(lock);
    candidate.resolver.version = version;

    expect(codes(validateManifestLockBinding(manifestBytes, jsonBytes(candidate)))).toContain(
      "IMPLEMENTATION_IDENTITY_INVALID",
    );
  });

  it("detects COMPATIBILITY_SUBJECT_MISMATCH from exact record bytes", () => {
    const candidate = mutableClone(compatible);
    candidate.subject.manifestSource.revision.value = "8".repeat(40);

    expect(
      codes(validateCompatibilityRecordBinding(manifestBytes, jsonBytes(candidate))),
    ).toContain("COMPATIBILITY_SUBJECT_MISMATCH");
  });

  it("detects COMPATIBILITY_TARGET_MISMATCH against the lock reference", () => {
    const candidate = mutableClone(compatible);
    candidate.target.contract.version = "1.0.1-synthetic.1";

    expect(
      codes(
        validatePackResolution({
          manifestBytes,
          lockBytes,
          compatibilityRecordBytes: {
            "synthetic-unknown-record": unknownBytes,
            "synthetic-compatible-record": jsonBytes(candidate),
          },
        }),
      ),
    ).toContain("COMPATIBILITY_TARGET_MISMATCH");
  });

  it("detects COMPATIBILITY_EVIDENCE_REQUIRED", () => {
    const candidate = mutableClone(compatible) as { evidence?: unknown };
    delete candidate.evidence;

    expect(
      codes(validateCompatibilityRecordBinding(manifestBytes, jsonBytes(candidate))),
    ).toContain("COMPATIBILITY_EVIDENCE_REQUIRED");
  });

  it("allows multiple supporting results inside one record evidence map", async () => {
    const candidateRecord = mutableClone(compatible);
    if (candidateRecord.state !== "compatible" && candidateRecord.state !== "incompatible") {
      throw new Error("Expected assessed compatibility fixture");
    }
    const firstEvidence = Object.values(candidateRecord.evidence)[0];
    if (firstEvidence === undefined) throw new Error("Expected evidence fixture");
    candidateRecord.evidence["evidence/synthetic-second-result"] = firstEvidence;
    const candidateRecordBytes = jsonBytes(candidateRecord);

    const candidateLock = mutableClone(lock);
    const reference = candidateLock.compatibilityRecords?.["synthetic-compatible-record"];
    if (reference === undefined) throw new Error("Expected lock reference");
    reference.digest.value = await sha256Value(candidateRecordBytes);

    expect(
      validatePackResolution({
        manifestBytes,
        lockBytes: jsonBytes(candidateLock),
        compatibilityRecordBytes: {
          "synthetic-unknown-record": unknownBytes,
          "synthetic-compatible-record": candidateRecordBytes,
        },
      }),
    ).toEqual({ valid: true, diagnostics: [] });
  });

  it("rejects duplicate or conflicting records for one exact subject/target pair", () => {
    expect(
      codes(
        validatePackResolution({
          manifestBytes,
          lockBytes: duplicatePairLockBytes,
          compatibilityRecordBytes: {
            "synthetic-unknown-record": unknownBytes,
            "synthetic-compatible-record": compatibleBytes,
            "synthetic-conflicting-record": conflictingBytes,
          },
        }),
      ),
    ).toContain("COMPATIBILITY_PAIR_DUPLICATE");
  });

  it("rejects two same-state assessments for one exact subject/target pair", async () => {
    const secondUnknown = mutableClone(unknown);
    secondUnknown.recordId = "synthetic-second-unknown-record";
    const secondUnknownBytes = jsonBytes(secondUnknown);
    const candidateLock = mutableClone(lock);
    if (candidateLock.compatibilityRecords === undefined) {
      throw new Error("Expected lock references");
    }
    candidateLock.compatibilityRecords[secondUnknown.recordId] = {
      digest: {
        algorithm: "sha256",
        value: await sha256Value(secondUnknownBytes),
      },
      subject: secondUnknown.subject,
      target: secondUnknown.target,
    };

    expect(
      codes(
        validatePackResolution({
          manifestBytes,
          lockBytes: jsonBytes(candidateLock),
          compatibilityRecordBytes: {
            "synthetic-unknown-record": unknownBytes,
            "synthetic-compatible-record": compatibleBytes,
            [secondUnknown.recordId]: secondUnknownBytes,
          },
        }),
      ),
    ).toContain("COMPATIBILITY_PAIR_DUPLICATE");
  });

  it("detects COMPATIBILITY_RECORD_MISSING", () => {
    const validation = validatePackResolution({
      manifestBytes,
      lockBytes,
      compatibilityRecordBytes: {
        "synthetic-compatible-record": compatibleBytes,
      },
    });

    expect(validation.diagnostics).toContainEqual({
      code: "COMPATIBILITY_RECORD_MISSING",
      path: "/lock/compatibilityRecords/synthetic-unknown-record",
      message:
        "A lock reference has no supplied compatibility record.",
    });
  });

  it("treats an inherited record-map property as missing", () => {
    const candidateLock = mutableClone(lock);
    if (candidateLock.compatibilityRecords === undefined) {
      throw new Error("Expected lock references");
    }
    const reference = candidateLock.compatibilityRecords["synthetic-unknown-record"];
    if (reference === undefined) throw new Error("Expected unknown record reference");
    Object.defineProperty(candidateLock.compatibilityRecords, "constructor", {
      value: structuredClone(reference),
      enumerable: true,
      configurable: true,
      writable: true,
    });

    expect(
      codes(
        validatePackResolution({
          manifestBytes,
          lockBytes: jsonBytes(candidateLock),
          compatibilityRecordBytes: {
            "synthetic-unknown-record": unknownBytes,
            "synthetic-compatible-record": compatibleBytes,
          },
        }),
      ),
    ).toContain("COMPATIBILITY_RECORD_MISSING");
  });

  it("strict-rejects an oversized record before exact-byte hashing", () => {
    const oversizedBytes = Buffer.alloc(maximumContractJsonBytes + 1, 0x20);

    expect(() =>
      validatePackResolution({
        manifestBytes,
        lockBytes,
        compatibilityRecordBytes: {
          "synthetic-unknown-record": oversizedBytes,
          "synthetic-compatible-record": compatibleBytes,
        },
      }),
    ).not.toThrow();
    expect(
      codes(
        validatePackResolution({
          manifestBytes,
          lockBytes,
          compatibilityRecordBytes: {
            "synthetic-unknown-record": oversizedBytes,
            "synthetic-compatible-record": compatibleBytes,
          },
        }),
      ),
    ).toContain("JSON_INPUT_TOO_LARGE");
  });

  it("detects COMPATIBILITY_RECORD_ID_MISMATCH", () => {
    const candidate = mutableClone(unknown);
    candidate.recordId = "synthetic-different-record";

    expect(
      codes(
        validatePackResolution({
          manifestBytes,
          lockBytes,
          compatibilityRecordBytes: {
            "synthetic-unknown-record": jsonBytes(candidate),
            "synthetic-compatible-record": compatibleBytes,
          },
        }),
      ),
    ).toContain("COMPATIBILITY_RECORD_ID_MISMATCH");
  });

  it("detects a compatibility-record digest mismatch over exact bytes", () => {
    const alteredBytes = Buffer.concat([compatibleBytes, Buffer.from("\n")]);

    expect(
      codes(
        validatePackResolution({
          manifestBytes,
          lockBytes,
          compatibilityRecordBytes: {
            "synthetic-unknown-record": unknownBytes,
            "synthetic-compatible-record": alteredBytes,
          },
        }),
      ),
    ).toContain("COMPATIBILITY_RECORD_DIGEST_MISMATCH");
  });

  it("rejects a supplied compatibility record absent from the lock", () => {
    expect(
      codes(
        validatePackResolution({
          manifestBytes,
          lockBytes,
          compatibilityRecordBytes: {
            "synthetic-unknown-record": unknownBytes,
            "synthetic-compatible-record": compatibleBytes,
            "synthetic-extra-record": unknownBytes,
          },
        }),
      ),
    ).toContain("COMPATIBILITY_RECORD_UNREFERENCED");
  });

  it("does not treat an inherited lock-reference property as declared", () => {
    const candidateLock = mutableClone(lock) as Mutable<PackLock> & {
      compatibilityRecords?: unknown;
    };
    delete candidateLock.compatibilityRecords;
    const compatibilityRecordBytes: Record<string, Uint8Array> = {};
    Object.defineProperty(compatibilityRecordBytes, "constructor", {
      value: unknownBytes,
      enumerable: true,
      configurable: true,
      writable: true,
    });

    expect(
      codes(
        validatePackResolution({
          manifestBytes,
          lockBytes: jsonBytes(candidateLock),
          compatibilityRecordBytes,
        }),
      ),
    ).toEqual(["COMPATIBILITY_RECORD_UNREFERENCED"]);
  });

  it("returns one bounded diagnostic above the 256-record input limit", () => {
    const compatibilityRecordBytes: Record<string, Uint8Array> = {};
    for (let index = 0; index < 257; index += 1) {
      compatibilityRecordBytes[`synthetic-extra-${index.toString().padStart(3, "0")}`] =
        unknownBytes;
    }

    expect(
      codes(
        validatePackResolution({
          manifestBytes,
          lockBytes,
          compatibilityRecordBytes,
        }),
      ),
    ).toEqual(["COMPATIBILITY_RECORD_LIMIT_EXCEEDED"]);
  });

  it("returns strict JSON diagnostics for non-JSON exact bytes", () => {
    expect(codes(validateManifestLockBinding(Buffer.from("{"), lockBytes))).toEqual([
      "JSON_SYNTAX_INVALID",
    ]);
    expect(
      codes(validateCompatibilityRecordBinding(manifestBytes, Buffer.from("["))),
    ).toEqual(["JSON_SYNTAX_INVALID"]);
  });

  it("returns diagnostics in deterministic code-unit order", () => {
    const candidate = mutableClone(lock);
    candidate.packId = "synthetic-other-pack";
    candidate.packVersion = "0.2.0-synthetic.1";
    candidate.manifest.digest.value = "0".repeat(64);

    expect(codes(validateManifestLockBinding(manifestBytes, jsonBytes(candidate)))).toEqual([
      "MANIFEST_DIGEST_MISMATCH",
      "PACK_ID_MISMATCH",
      "PACK_VERSION_MISMATCH",
    ]);
  });

  const legacyStatuses = ["planned", "compatible", "unsupported"] as const;
  const compatibilityStates: readonly CompatibilityState[] = [
    "unknown",
    "compatible",
    "incompatible",
    "unsupported",
  ];
  const migrationMatrix = legacyStatuses.flatMap((legacyStatus) =>
    compatibilityStates.map((migratedState) => [legacyStatus, migratedState] as const),
  );

  it.each(migrationMatrix)(
    "applies the fail-closed legacy migration matrix: %s -> %s",
    (legacyStatus, migratedState) => {
      const validation = validateLegacyCompatibilityMigration(
        legacyStatus,
        migratedState,
      );
      if (legacyStatus === "planned" && migratedState === "unknown") {
        expect(validation).toEqual({ valid: true, diagnostics: [] });
      } else {
        expect(codes(validation)).toEqual(["LEGACY_STATUS_MIGRATION_FORBIDDEN"]);
      }
    },
  );

  it("does not introduce a manifest self-digest or a live source self-reference", () => {
    const candidate = manifest as PackManifest & Record<string, unknown>;

    expect(Object.hasOwn(candidate, "digest")).toBe(false);
    expect(Object.hasOwn(candidate, "manifestDigest")).toBe(false);
    expect(manifest.source.repositoryId).toBe("synthetic:example/pack-source");
    expect(manifest.source.revision.value).toBe("1".repeat(40));
    expect(manifest.source.tree.value).toBe("2".repeat(40));
  });
});
