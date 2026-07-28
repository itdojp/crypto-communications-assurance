import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

import { beforeAll, describe, expect, it } from "vitest";

import {
  compileContractBytes,
  decodeStrictJsonObject,
  type ContractBytesValidationResult,
} from "../packages/contracts/src/index.js";

const loadBytes = (relativePath: string): Promise<Buffer> =>
  readFile(new URL(relativePath, import.meta.url));
const loadJson = async (relativePath: string): Promise<unknown> => {
  const decoded = decodeStrictJsonObject(await loadBytes(relativePath));
  if (!decoded.valid) throw new Error(`${relativePath}: strict decode failed`);
  return decoded.value;
};
const digest = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

describe("CCA-130 closed profile contracts", () => {
  let moduleValidator: (bytes: Uint8Array) => ContractBytesValidationResult;
  let requestValidator: (bytes: Uint8Array) => ContractBytesValidationResult;
  let resolvedValidator: (bytes: Uint8Array) => ContractBytesValidationResult;
  let manifestValidator: (bytes: Uint8Array) => ContractBytesValidationResult;

  beforeAll(async () => {
    const [modules, request, resolved, manifest] = await Promise.all([
      loadJson("../schema/cryptocomm-capability-module-catalog-v1.schema.json"),
      loadJson("../schema/cryptocomm-profile-request-v1.schema.json"),
      loadJson("../schema/cryptocomm-resolved-profile-v1.schema.json"),
      loadJson("../schema/cryptocomm-pack-manifest-v1.schema.json"),
    ]);
    moduleValidator = compileContractBytes(modules as object);
    requestValidator = compileContractBytes(request as object);
    resolvedValidator = compileContractBytes(resolved as object);
    manifestValidator = compileContractBytes(manifest as object);
  });

  it.each([
    [
      "authoritative module catalog",
      "../pack/modules/v1/capability-module-catalog.json",
      () => moduleValidator,
    ],
    [
      "synthetic module catalog",
      "../fixtures/valid/capability-module-catalog-v1.json",
      () => moduleValidator,
    ],
    [
      "synthetic complete request",
      "../fixtures/valid/profile-request-complete-v1.json",
      () => requestValidator,
    ],
    [
      "synthetic dependency request",
      "../fixtures/valid/profile-request-dependency-v1.json",
      () => requestValidator,
    ],
    [
      "synthetic unknown request",
      "../fixtures/valid/profile-request-unknown-v1.json",
      () => requestValidator,
    ],
    [
      "synthetic unsupported request",
      "../fixtures/valid/profile-request-unsupported-v1.json",
      () => requestValidator,
    ],
    [
      "synthetic conflict request",
      "../fixtures/valid/profile-request-conflict-v1.json",
      () => requestValidator,
    ],
    [
      "synthetic resolved profile",
      "../fixtures/valid/resolved-profile-complete-v1.json",
      () => resolvedValidator,
    ],
    [
      "synthetic CCA-110 profile manifest",
      "../fixtures/valid/cca-130-profile-manifest-v1.json",
      () => manifestValidator,
    ],
  ])("strict-decodes and schema-validates %s", async (_name, file, validator) => {
    expect(validator()(await loadBytes(file))).toMatchObject({
      valid: true,
      stage: "validated",
    });
  });

  it.each([
    [
      "malformed module ID",
      "../fixtures/invalid/module-catalog-malformed-id.json",
      () => moduleValidator,
      "propertyNames",
    ],
    [
      "duplicate module selection",
      "../fixtures/invalid/module-catalog-duplicate-selection.json",
      () => moduleValidator,
      "uniqueItems",
    ],
    [
      "excessive module selections",
      "../fixtures/invalid/module-catalog-excessive-selections.json",
      () => moduleValidator,
      "maxItems",
    ],
    [
      "duplicate dependency",
      "../fixtures/invalid/module-catalog-duplicate-dependency.json",
      () => moduleValidator,
      "uniqueItems",
    ],
    [
      "invalid unsupported form",
      "../fixtures/invalid/module-catalog-invalid-unsupported.json",
      () => moduleValidator,
      "oneOf",
    ],
    [
      "self conflict",
      "../fixtures/invalid/module-catalog-conflict-self.json",
      () => moduleValidator,
      "uniqueItems",
    ],
    [
      "unsafe safety flag",
      "../fixtures/invalid/module-catalog-unsafe-safety.json",
      () => moduleValidator,
      "const",
    ],
    [
      "undeclared field",
      "../fixtures/invalid/module-catalog-undeclared-property.json",
      () => moduleValidator,
      "additionalProperties",
    ],
    [
      "duplicate request",
      "../fixtures/invalid/profile-request-duplicate-module.json",
      () => requestValidator,
      "uniqueItems",
    ],
    [
      "malformed profile ID",
      "../fixtures/invalid/profile-request-malformed-id.json",
      () => requestValidator,
      "pattern",
    ],
  ])("schema-rejects %s", async (_name, file, validator, keyword) => {
    const validation = validator()(await loadBytes(file));
    expect(validation.valid).toBe(false);
    if (!validation.valid) {
      expect(validation.stage).toBe("schema");
      if (validation.stage === "schema") {
        expect(validation.errors.some((error) => error.keyword === keyword)).toBe(
          true,
        );
      }
    }
  });

  it.each([
    "../fixtures/invalid/module-catalog-key-id-mismatch.json",
    "../fixtures/invalid/module-catalog-dangling-property.json",
    "../fixtures/invalid/module-catalog-dangling-capability.json",
    "../fixtures/invalid/module-catalog-dangling-attacker.json",
    "../fixtures/invalid/module-catalog-dangling-threat.json",
    "../fixtures/invalid/module-catalog-self-dependency.json",
    "../fixtures/invalid/module-catalog-dangling-dependency.json",
    "../fixtures/invalid/module-catalog-dependency-cycle.json",
    "../fixtures/invalid/module-catalog-conflict-noncanonical.json",
    "../fixtures/invalid/module-catalog-conflict-reversed-duplicate.json",
    "../fixtures/invalid/module-catalog-conflict-dangling.json",
    "../fixtures/invalid/module-catalog-intrinsic-conflict.json",
    "../fixtures/invalid/module-catalog-catalog-digest-mismatch.json",
  ])("keeps %s as a semantic or binding rejection boundary", async (file) => {
    expect(moduleValidator(await loadBytes(file))).toMatchObject({
      valid: true,
      stage: "validated",
    });
  });

  it("keeps all three schemas closed Draft 2020-12 contracts", async () => {
    const cases = [
      [
        "../schema/cryptocomm-capability-module-catalog-v1.schema.json",
        "cryptocomm-capability-module-catalog/v1",
      ],
      [
        "../schema/cryptocomm-profile-request-v1.schema.json",
        "cryptocomm-profile-request/v1",
      ],
      [
        "../schema/cryptocomm-resolved-profile-v1.schema.json",
        "cryptocomm-resolved-profile/v1",
      ],
    ] as const;
    for (const [file, contractId] of cases) {
      const schema = (await loadJson(file)) as {
        $schema: string;
        additionalProperties: boolean;
        properties: { schemaVersion: { const: string } };
      };
      expect(schema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
      expect(schema.additionalProperties).toBe(false);
      expect(schema.properties.schemaVersion.const).toBe(contractId);
    }
  });

  it("content-binds exact CCA-120 catalog bytes from both module catalogs", async () => {
    const cases = [
      [
        "../pack/modules/v1/capability-module-catalog.json",
        {
          propertyCatalog: "../pack/catalogs/v1/property-catalog.json",
          attackerCatalog: "../pack/catalogs/v1/attacker-catalog.json",
          threatCatalog: "../pack/catalogs/v1/threat-catalog.json",
        },
      ],
      [
        "../fixtures/valid/capability-module-catalog-v1.json",
        {
          propertyCatalog: "../fixtures/valid/property-catalog-v1.json",
          attackerCatalog: "../fixtures/valid/attacker-catalog-v1.json",
          threatCatalog: "../fixtures/valid/threat-catalog-v1.json",
        },
      ],
    ] as const;
    for (const [catalogFile, paths] of cases) {
      const catalog = (await loadJson(catalogFile)) as {
        catalogBindings: Record<string, { digest: { value: string } }>;
      };
      for (const [name, file] of Object.entries(paths)) {
        expect(catalog.catalogBindings[name]?.digest.value).toBe(
          digest(await loadBytes(file)),
        );
      }
    }
  });

  it("content-binds exact module-catalog bytes from every valid request", async () => {
    const files = (await readdir(new URL("../fixtures/valid/", import.meta.url)))
      .filter((name) => name.startsWith("profile-request-") && name.endsWith(".json"))
      .sort();
    expect(files.length).toBe(8);
    for (const name of files) {
      const request = (await loadJson(`../fixtures/valid/${name}`)) as {
        moduleCatalog: { catalogId: string; digest: { value: string } };
      };
      const moduleFile = request.moduleCatalog.catalogId.startsWith("synthetic-")
        ? "../fixtures/valid/capability-module-catalog-v1.json"
        : "../pack/modules/v1/capability-module-catalog.json";
      expect(request.moduleCatalog.digest.value, name).toBe(
        digest(await loadBytes(moduleFile)),
      );
    }
  });

  it("content-binds the synthetic module, request, and resolved profile in one CCA-110 manifest", async () => {
    const manifest = (await loadJson(
      "../fixtures/valid/cca-130-profile-manifest-v1.json",
    )) as {
      source: { repositoryId: string };
      artifacts: Record<
        string,
        { digest: { value: string }; contract: { contractId: string } }
      >;
    };
    expect(manifest.source.repositoryId).toBe(
      "synthetic:example/cca-130-profile-source",
    );
    expect(Object.keys(manifest.artifacts)).toHaveLength(3);
    for (const [artifactPath, declaration] of Object.entries(manifest.artifacts)) {
      expect(declaration.digest.value).toBe(
        digest(await readFile(new URL(`../${artifactPath}`, import.meta.url))),
      );
      expect(declaration.contract.contractId).toMatch(
        /^cryptocomm-(capability-module-catalog|profile-request|resolved-profile)\/v1$/,
      );
    }
  });

  it("keeps the golden resolved profile in deterministic UTF-8 JSON encoding", async () => {
    const bytes = await loadBytes("../fixtures/valid/resolved-profile-complete-v1.json");
    const text = bytes.toString("utf8");
    expect(text.endsWith("\n")).toBe(true);
    expect(text.endsWith("\n\n")).toBe(false);
    expect(text.includes("\r")).toBe(false);
    expect(text).toBe(`${JSON.stringify(JSON.parse(text), undefined, 2)}\n`);
  });

  it("strict-decodes every CCA-130 JSON artifact", async () => {
    const selected = [
      "../schema/cryptocomm-capability-module-catalog-v1.schema.json",
      "../schema/cryptocomm-profile-request-v1.schema.json",
      "../schema/cryptocomm-resolved-profile-v1.schema.json",
      "../pack/modules/v1/capability-module-catalog.json",
    ];
    for (const root of ["../fixtures/valid", "../fixtures/invalid"]) {
      const directory = new URL(root + "/", import.meta.url);
      for (const name of await readdir(directory)) {
        if (
          name.endsWith(".json") &&
          (name.includes("module") ||
            name.includes("profile") ||
            name === "cca-130-profile-manifest-v1.json")
        ) {
          selected.push(path.posix.join(root, name));
        }
      }
    }
    expect(selected.length).toBeGreaterThanOrEqual(39);
    for (const file of selected.sort()) {
      expect(decodeStrictJsonObject(await loadBytes(file)).valid, file).toBe(true);
    }
  });
});
