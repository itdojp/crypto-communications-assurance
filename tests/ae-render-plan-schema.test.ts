import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import {
  compileContractBytes,
  decodeStrictJsonObject,
} from "../packages/contracts/src/index.js";

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
    expect(decoded.value.selectedSchemas).toHaveLength(5);
    expect(decoded.value.selectedSchemas.map(({ path }) => path).sort()).toEqual([
      "schema/assurance-profile.schema.json",
      "schema/context-pack-v1.schema.json",
      "schema/security-audit-scope-v1.schema.json",
      "schema/security-claim-v1.schema.json",
      "schema/security-threat-model-v1.schema.json",
    ]);

    for (const entry of decoded.value.selectedSchemas) {
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
});
