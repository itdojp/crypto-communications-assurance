import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import {
  compileContractBytes,
  decodeStrictJsonObject,
} from "../packages/contracts/src/index.js";
import { readRepositoryFile } from "./helpers/cca-210.js";

const pin = "c5da6115638fdbfeebbc458b39fa6916db66afb0";
const pinRoot = `../integrations/ae-framework/pins/${pin}/`;
const loadBytes = (relativePath: string): Promise<Buffer> =>
  readFile(new URL(relativePath, import.meta.url));

const gitBlobSha = (bytes: Uint8Array): string =>
  createHash("sha1")
    .update(`blob ${bytes.byteLength}\0`)
    .update(bytes)
    .digest("hex");

describe("CCA-210 render-plan contract and exact upstream pin", () => {
  it("strict-decodes the exact 12-file positive synthetic fixture set", async () => {
    const files = [
      "ae-render-plan-v1.json",
      "context-pack-v1.json",
      "profile-request-v1.json",
      "resolved-profile-v1.json",
      "records/evidence-binding-set-v1.json",
      "records/evidence-provenance-v1.json",
      "records/execution-result-v1.json",
      "records/freshness-assessment-v1.json",
      "rendered/assurance-profile-v1.json",
      "rendered/security-audit-scope-v1.json",
      "rendered/security-claim-v1.json",
      "rendered/security-threat-model-v1.json",
    ] as const;
    expect(files).toHaveLength(12);
    for (const file of files) {
      expect(
        decodeStrictJsonObject(
          await loadBytes(`../fixtures/valid/cca-210/${file}`),
        ).valid,
        file,
      ).toBe(true);
    }
  });

  it("keeps the sole CCA-210 contract closed and Draft 2020-12", async () => {
    const bytes = await loadBytes(
      "../schema/cryptocomm-ae-render-plan-v1.schema.json",
    );
    const decoded = decodeStrictJsonObject<{
      $schema: string;
      additionalProperties: boolean;
      properties: { schemaVersion: { const: string } };
    }>(bytes);
    expect(decoded.valid).toBe(true);
    if (!decoded.valid) return;

    expect(decoded.value.$schema).toBe(
      "https://json-schema.org/draft/2020-12/schema",
    );
    expect(decoded.value.additionalProperties).toBe(false);
    expect(decoded.value.properties.schemaVersion.const).toBe(
      "cryptocomm-ae-render-plan/v1",
    );

    const validate = compileContractBytes(decoded.value);
    expect(validate(Buffer.from("{}\n"))).toMatchObject({
      valid: false,
      stage: "schema",
    });
  });

  it("closes every object shape owned by the render-plan schema", async () => {
    const decoded = decodeStrictJsonObject(
      await loadBytes("../schema/cryptocomm-ae-render-plan-v1.schema.json"),
    );
    expect(decoded.valid).toBe(true);
    if (!decoded.valid) return;

    const pending: unknown[] = [decoded.value];
    while (pending.length > 0) {
      const value = pending.pop();
      if (Array.isArray(value)) {
        pending.push(...value);
      } else if (value !== null && typeof value === "object") {
        const record = value as Record<string, unknown>;
        if (record.type === "object") {
          expect(record.additionalProperties, JSON.stringify(record)).toBe(false);
        }
        pending.push(...Object.values(record));
      }
    }
  });

  it("binds only the five authorized exact upstream schema snapshots", async () => {
    const decoded = decodeStrictJsonObject<{
      repository: string;
      commit: string;
      tree: string;
      selectedSchemas: readonly {
        path: string;
        pinnedPath: string;
        blobSha: string;
        contentSha256: string;
        byteLength: number;
      }[];
    }>(await loadBytes(`${pinRoot}UPSTREAM.json`));
    expect(decoded.valid).toBe(true);
    if (!decoded.valid) return;

    expect(decoded.value).toMatchObject({
      repository: "itdojp/ae-framework",
      commit: pin,
      tree: "0d69865b37a4476a20f0f1f1f42031967d3ec3a7",
    });
    expect(Object.keys(decoded.value).sort()).toEqual([
      "commit",
      "notice",
      "repository",
      "selectedSchemas",
      "tree",
      "upstreamLicense",
    ]);
    expect(decoded.value.selectedSchemas).toHaveLength(5);
    expect(decoded.value.selectedSchemas.map(({ path }) => path).sort()).toEqual([
      "schema/assurance-profile.schema.json",
      "schema/context-pack-v1.schema.json",
      "schema/security-audit-scope-v1.schema.json",
      "schema/security-claim-v1.schema.json",
      "schema/security-threat-model-v1.schema.json",
    ]);

    for (const entry of decoded.value.selectedSchemas) {
      expect(Object.keys(entry).sort()).toEqual([
        "blobSha",
        "byteLength",
        "contentSha256",
        "path",
        "pinnedPath",
        "purpose",
      ]);
      expect(entry.pinnedPath).toBe(entry.path);
      const bytes = await loadBytes(`${pinRoot}${entry.pinnedPath}`);
      expect(bytes.byteLength, entry.path).toBe(entry.byteLength);
      expect(createHash("sha256").update(bytes).digest("hex"), entry.path).toBe(
        entry.contentSha256,
      );
      expect(gitBlobSha(bytes), entry.path).toBe(entry.blobSha);
    }
  });

  it("retains Apache-2.0 and upstream NOTICE attribution", async () => {
    const [license, notice] = await Promise.all([
      loadBytes("../LICENSE"),
      loadBytes("../NOTICE"),
    ]);
    expect(license.toString("utf8")).toContain("Apache License");
    expect(license.toString("utf8")).toContain("Version 2.0");
    expect(notice.toString("utf8")).toContain("ae-framework contributors");
  });

  it("keeps the renderer free of filesystem, network, clock, and upstream execution APIs", async () => {
    const source = (
      await loadBytes("../packages/contracts/src/ae-renderer.ts")
    ).toString("utf8");
    for (const prohibited of [
      'from "node:fs',
      'from "node:http',
      'from "node:https',
      "fetch(",
      "Date.now(",
      "new Date(",
      "process.env",
      "child_process",
    ]) {
      expect(source, prohibited).not.toContain(prohibited);
    }
  });

  it("uses an array index for native output schema diagnostic JSON Pointers", async () => {
    const source = (
      await loadBytes("../packages/contracts/src/ae-renderer.ts")
    ).toString("utf8");
    expect(source).toContain("`/outputs/${outputIndex}`");
    expect(source).not.toContain("`/outputs/${kind}`");
  });

  it("precompiles the five CCA input validators instead of recompiling per call", async () => {
    const source = (
      await loadBytes("../packages/contracts/src/ae-renderer.ts")
    ).toString("utf8");
    expect(source).toContain("const ccaValidatorByRole");
    expect(source).toContain("ccaValidatorByRole[role](bytes)");
    expect(source).not.toContain("compileContractBytes(ccaSchemaByRole[role])");
  });

  it("binds the renderer identity and package version to the exact current source snapshot", async () => {
    const [schemaBytes, planBytes, packageBytes, sourceBytes] = await Promise.all([
      loadBytes("../schema/cryptocomm-ae-render-plan-v1.schema.json"),
      loadBytes("../fixtures/valid/cca-210/ae-render-plan-v1.json"),
      loadBytes("../packages/contracts/package.json"),
      loadBytes("../packages/contracts/src/ae-renderer.ts"),
    ]);
    const schema = decodeStrictJsonObject<{
      properties: {
        renderer: {
          properties: Record<string, { const: string }>;
        };
      };
    }>(schemaBytes);
    const plan = decodeStrictJsonObject<{
      renderer: Record<string, string>;
    }>(planBytes);
    const packageManifest = decodeStrictJsonObject<{
      name: string;
      version: string;
    }>(packageBytes);
    expect(schema.valid).toBe(true);
    expect(plan.valid).toBe(true);
    expect(packageManifest.valid).toBe(true);
    if (!schema.valid || !plan.valid || !packageManifest.valid) return;

    const exactIdentity = {
      implementationId: "cca-ae-renderer/v1",
      packageName: packageManifest.value.name,
      packageVersion: packageManifest.value.version,
      sourcePath: "packages/contracts/src/ae-renderer.ts",
      sourceSha256: createHash("sha256").update(sourceBytes).digest("hex"),
    };
    expect(packageManifest.value).toMatchObject({
      name: "@itdojp/cryptocomm-contracts",
      version: "0.0.0",
    });
    expect(plan.value.renderer).toEqual(exactIdentity);
    expect(
      Object.fromEntries(
        Object.entries(schema.value.properties.renderer.properties).map(
          ([key, value]) => [key, value.const],
        ),
      ),
    ).toEqual(exactIdentity);
  });

  it.each([
    "../package.json",
    "/etc/passwd",
    "C:\\secret.json",
    "C:/secret.json",
    "%2e%2e/secret.json",
    "fixtures//file.json",
  ])(
    "rejects an unsafe repository test-helper path: %s",
    (path) => {
      expect(() => readRepositoryFile(path)).toThrow(
        "Repository-relative non-traversing path required",
      );
    },
  );
});
