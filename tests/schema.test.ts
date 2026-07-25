import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { beforeAll, describe, expect, it } from "vitest";

import { compileContract, type ValidationResult } from "../packages/contracts/src/index.js";

const loadJson = async (relativePath: string): Promise<unknown> =>
  JSON.parse(await readFile(new URL(relativePath, import.meta.url), "utf8")) as unknown;

describe("cryptocomm pack v1 schema", () => {
  let validate: (candidate: unknown) => ValidationResult;
  let validFixture: Record<string, unknown>;

  beforeAll(async () => {
    const schema = await loadJson("../schema/cryptocomm-pack-v1.schema.json");
    validate = compileContract(schema as object);
    validFixture = (await loadJson("../fixtures/valid/bootstrap-pack.json")) as Record<
      string,
      unknown
    >;
  });

  it("accepts the explicitly synthetic valid fixture", () => {
    expect(validate(validFixture)).toEqual({ valid: true, errors: [] });
  });

  it("content-binds the synthetic referenced artifact with SHA-256", async () => {
    const [artifact] = validFixture.artifacts as Array<{ path: string; sha256: string }>;
    if (artifact === undefined) throw new Error("valid fixture has no artifact");

    const bytes = await readFile(new URL(`../${artifact.path}`, import.meta.url));
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(artifact.sha256);
  });

  it("rejects the invalid fixture that omits an artifact digest", async () => {
    const invalidFixture = await loadJson(
      "../fixtures/invalid/bootstrap-pack-missing-digest.json",
    );
    const result = validate(invalidFixture);

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.errors.some((error) => error.keyword === "required")).toBe(true);
    }
  });

  it.each(["/etc/passwd", "../secret.json", "docs/../secret.json", "C:\\secret.json"])(
    "rejects an unbounded artifact path: %s",
    (path) => {
      const candidate = structuredClone(validFixture);
      candidate.artifacts = [
        {
          path,
          sha256: "0".repeat(64),
        },
      ];

      expect(validate(candidate).valid).toBe(false);
    },
  );

  it.each(["executable", "networkRequired", "secretsAllowed"])(
    "rejects %s=true",
    (property) => {
      const candidate = structuredClone(validFixture);
      candidate[property] = true;

      expect(validate(candidate).valid).toBe(false);
    },
  );

  it("rejects undeclared fields", () => {
    const candidate = structuredClone(validFixture);
    candidate.humanApproved = true;

    expect(validate(candidate).valid).toBe(false);
  });
});
