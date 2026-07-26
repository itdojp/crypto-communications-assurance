import { readFile } from "node:fs/promises";

import { beforeAll, describe, expect, it } from "vitest";

import {
  type CompatibilityRecord,
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

const loadJson = async <T>(relativePath: string): Promise<T> =>
  JSON.parse((await loadBytes(relativePath)).toString("utf8")) as T;

describe("CCA-110 semantic bindings", () => {
  let manifest: PackManifest;
  let manifestBytes: Buffer;
  let lock: PackLock;
  let unknown: CompatibilityRecord;
  let unknownBytes: Buffer;
  let compatible: CompatibilityRecord;
  let compatibleBytes: Buffer;

  beforeAll(async () => {
    [
      manifest,
      manifestBytes,
      lock,
      unknown,
      unknownBytes,
      compatible,
      compatibleBytes,
    ] = await Promise.all([
      loadJson<PackManifest>("../fixtures/valid/pack-manifest-v1.json"),
      loadBytes("../fixtures/valid/pack-manifest-v1.json"),
      loadJson<PackLock>("../fixtures/valid/pack-lock-v1.json"),
      loadJson<CompatibilityRecord>(
        "../fixtures/valid/compatibility-unknown-v1.json",
      ),
      loadBytes("../fixtures/valid/compatibility-unknown-v1.json"),
      loadJson<CompatibilityRecord>(
        "../fixtures/valid/compatibility-compatible-v1.json",
      ),
      loadBytes("../fixtures/valid/compatibility-compatible-v1.json"),
    ]);
  });

  const codes = (
    validation: ReturnType<typeof validateManifestLockBinding>,
  ): readonly string[] => validation.diagnostics.map((entry) => entry.code);

  it("accepts exact manifest, lock, record bytes, subject, and target bindings", () => {
    expect(
      validatePackResolution({
        manifest,
        manifestBytes,
        lock,
        compatibilityRecords: {
          "synthetic-unknown-record": { record: unknown, bytes: unknownBytes },
          "synthetic-compatible-record": {
            record: compatible,
            bytes: compatibleBytes,
          },
        },
      }),
    ).toEqual({ valid: true, diagnostics: [] });
  });

  it("detects MANIFEST_DIGEST_MISMATCH over exact bytes", () => {
    const candidate = mutableClone(lock);
    candidate.manifest.digest.value = "0".repeat(64);

    expect(codes(validateManifestLockBinding(manifest, manifestBytes, candidate))).toContain(
      "MANIFEST_DIGEST_MISMATCH",
    );
  });

  it("detects PACK_ID_MISMATCH", () => {
    const candidate = mutableClone(lock);
    candidate.packId = "synthetic-other-pack";

    expect(codes(validateManifestLockBinding(manifest, manifestBytes, candidate))).toContain(
      "PACK_ID_MISMATCH",
    );
  });

  it("detects PACK_VERSION_MISMATCH", () => {
    const candidate = mutableClone(lock);
    candidate.packVersion = "0.2.0-synthetic.1";

    expect(codes(validateManifestLockBinding(manifest, manifestBytes, candidate))).toContain(
      "PACK_VERSION_MISMATCH",
    );
  });

  it("detects SOURCE_IDENTITY_MISMATCH", () => {
    const candidate = mutableClone(lock);
    candidate.manifest.source.revision.value = "9".repeat(40);

    expect(codes(validateManifestLockBinding(manifest, manifestBytes, candidate))).toContain(
      "SOURCE_IDENTITY_MISMATCH",
    );
  });

  it("detects IMPLEMENTATION_IDENTITY_INVALID", () => {
    const candidate = mutableClone(lock);
    candidate.resolver.sourceRevision.value = "main";

    expect(codes(validateManifestLockBinding(manifest, manifestBytes, candidate))).toContain(
      "IMPLEMENTATION_IDENTITY_INVALID",
    );
  });

  it("detects COMPATIBILITY_SUBJECT_MISMATCH", () => {
    const candidate = mutableClone(compatible);
    candidate.subject.manifestSource.revision.value = "8".repeat(40);

    expect(
      codes(validateCompatibilityRecordBinding(manifest, manifestBytes, candidate)),
    ).toContain("COMPATIBILITY_SUBJECT_MISMATCH");
  });

  it("detects COMPATIBILITY_TARGET_MISMATCH against the lock reference", () => {
    const candidate = mutableClone(compatible);
    candidate.target.contract.version = "1.0.1-synthetic.1";

    expect(
      codes(
        validatePackResolution({
          manifest,
          manifestBytes,
          lock,
          compatibilityRecords: {
            "synthetic-unknown-record": { record: unknown, bytes: unknownBytes },
            "synthetic-compatible-record": {
              record: candidate,
              bytes: compatibleBytes,
            },
          },
        }),
      ),
    ).toContain("COMPATIBILITY_TARGET_MISMATCH");
  });

  it("detects COMPATIBILITY_EVIDENCE_REQUIRED", () => {
    const candidate = mutableClone(compatible);
    delete candidate.evidence;

    expect(
      codes(validateCompatibilityRecordBinding(manifest, manifestBytes, candidate)),
    ).toContain("COMPATIBILITY_EVIDENCE_REQUIRED");
  });

  it("detects COMPATIBILITY_RECORD_MISSING", () => {
    expect(
      codes(
        validatePackResolution({
          manifest,
          manifestBytes,
          lock,
          compatibilityRecords: {
            "synthetic-compatible-record": {
              record: compatible,
              bytes: compatibleBytes,
            },
          },
        }),
      ),
    ).toContain("COMPATIBILITY_RECORD_MISSING");
  });

  it("detects COMPATIBILITY_RECORD_ID_MISMATCH", () => {
    const candidate = mutableClone(unknown);
    candidate.recordId = "synthetic-different-record";

    expect(
      codes(
        validatePackResolution({
          manifest,
          manifestBytes,
          lock,
          compatibilityRecords: {
            "synthetic-unknown-record": { record: candidate, bytes: unknownBytes },
            "synthetic-compatible-record": {
              record: compatible,
              bytes: compatibleBytes,
            },
          },
        }),
      ),
    ).toContain("COMPATIBILITY_RECORD_ID_MISMATCH");
  });

  it("detects a compatibility-record digest mismatch", () => {
    const alteredBytes = Buffer.concat([compatibleBytes, Buffer.from("\n")]);

    expect(
      codes(
        validatePackResolution({
          manifest,
          manifestBytes,
          lock,
          compatibilityRecords: {
            "synthetic-unknown-record": { record: unknown, bytes: unknownBytes },
            "synthetic-compatible-record": {
              record: compatible,
              bytes: alteredBytes,
            },
          },
        }),
      ),
    ).toContain("COMPATIBILITY_RECORD_DIGEST_MISMATCH");
  });

  it("returns diagnostics in deterministic code-unit order", () => {
    const candidate = mutableClone(lock);
    candidate.packId = "synthetic-other-pack";
    candidate.packVersion = "0.2.0-synthetic.1";
    candidate.manifest.digest.value = "0".repeat(64);

    expect(codes(validateManifestLockBinding(manifest, manifestBytes, candidate))).toEqual([
      "MANIFEST_DIGEST_MISMATCH",
      "PACK_ID_MISMATCH",
      "PACK_VERSION_MISMATCH",
    ]);
  });

  it("forbids promoting legacy planned to compatible", () => {
    expect(codes(validateLegacyCompatibilityMigration("planned", "compatible"))).toEqual([
      "LEGACY_STATUS_PROMOTION_FORBIDDEN",
    ]);
    expect(validateLegacyCompatibilityMigration("planned", "unknown")).toEqual({
      valid: true,
      diagnostics: [],
    });
  });

  it("does not introduce a manifest self-digest or a live source self-reference", () => {
    const candidate = manifest as PackManifest & Record<string, unknown>;

    expect(Object.hasOwn(candidate, "digest")).toBe(false);
    expect(Object.hasOwn(candidate, "manifestDigest")).toBe(false);
    expect(manifest.source.repositoryId).toBe("synthetic:example/pack-source");
    expect(manifest.source.revision.value).toBe("1".repeat(40));
    expect(manifest.source.tree.value).toBe("2".repeat(40));
  });
});
