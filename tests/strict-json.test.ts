import { describe, expect, it } from "vitest";

import {
  compileContractBytes,
  decodeStrictJsonObject,
  maximumContractJsonBytes,
  maximumContractJsonDepth,
} from "../packages/contracts/src/index.js";

const bytes = (text: string): Buffer => Buffer.from(text, "utf8");
const codes = (
  validation: ReturnType<typeof decodeStrictJsonObject>,
): readonly string[] => validation.diagnostics.map((entry) => entry.code);

describe("CCA-110 strict exact-byte JSON decoding", () => {
  it("accepts strict object JSON at the exact documented byte limit", () => {
    const candidate = Buffer.concat([
      bytes("{}"),
      Buffer.alloc(maximumContractJsonBytes - 2, 0x20),
    ]);

    expect(candidate.byteLength).toBe(maximumContractJsonBytes);
    expect(decodeStrictJsonObject(candidate)).toMatchObject({
      valid: true,
      diagnostics: [],
    });
  });

  it("rejects input one byte above the documented limit before decoding", () => {
    const candidate = Buffer.concat([
      bytes("{}"),
      Buffer.alloc(maximumContractJsonBytes - 1, 0x20),
    ]);

    expect(candidate.byteLength).toBe(maximumContractJsonBytes + 1);
    expect(codes(decodeStrictJsonObject(candidate))).toEqual([
      "JSON_INPUT_TOO_LARGE",
    ]);
  });

  it("rejects fatal invalid UTF-8", () => {
    const candidate = Buffer.concat([
      bytes('{"value":"'),
      Buffer.from([0xc3, 0x28]),
      bytes('"}'),
    ]);

    expect(codes(decodeStrictJsonObject(candidate))).toEqual(["JSON_INVALID_UTF8"]);
  });

  it("accepts JSON at the exact documented container-depth limit", () => {
    const arrayDepth = maximumContractJsonDepth - 1;
    const candidate = bytes(
      `{"value":${"[".repeat(arrayDepth)}null${"]".repeat(arrayDepth)}}`,
    );

    expect(decodeStrictJsonObject(candidate).valid).toBe(true);
  });

  it("rejects JSON one container above the documented depth limit", () => {
    const arrayDepth = maximumContractJsonDepth;
    const candidate = bytes(
      `{"value":${"[".repeat(arrayDepth)}null${"]".repeat(arrayDepth)}}`,
    );

    expect(codes(decodeStrictJsonObject(candidate))).toEqual([
      "JSON_NESTING_TOO_DEEP",
    ]);
  });

  it("returns a bounded diagnostic instead of overflowing on extreme nesting", () => {
    const candidate = bytes(
      `{"value":${"[".repeat(5_000)}null${"]".repeat(5_000)}}`,
    );

    expect(() => decodeStrictJsonObject(candidate)).not.toThrow();
    expect(codes(decodeStrictJsonObject(candidate))).toEqual([
      "JSON_NESTING_TOO_DEEP",
    ]);
  });

  it("does not count escaped structural characters inside strings as nesting", () => {
    const candidate = bytes(
      JSON.stringify({ value: `${"[".repeat(256)}"${"]".repeat(256)}` }),
    );

    expect(decodeStrictJsonObject(candidate).valid).toBe(true);
  });

  it.each([
    ["top-level duplicate", '{"packId":"one","packId":"two"}', "/packId"],
    [
      "nested duplicate",
      '{"source":{"revision":"one","revision":"two"}}',
      "/source/revision",
    ],
    [
      "array-nested duplicate",
      '{"records":[{"state":"unknown","state":"compatible"}]}',
      "/records/0/state",
    ],
    [
      "escaped duplicate",
      String.raw`{"packId":"one","pack\u0049d":"two"}`,
      "/packId",
    ],
    [
      "escaped slash duplicate",
      String.raw`{"a/b":1,"a\u002fb":2}`,
      "/a~1b",
    ],
  ])("rejects %s member names after JSON escape decoding", (_name, text, path) => {
    const validation = decodeStrictJsonObject(bytes(text));

    expect(validation.valid).toBe(false);
    if (!validation.valid) {
      expect(validation.diagnostics).toMatchObject([
        { code: "JSON_DUPLICATE_MEMBER", path },
      ]);
    }
  });

  it.each([
    ["trailing data", '{} {"second":true}'],
    ["line comment", '{"value":true // comment\n}'],
    ["block comment", '{"value":/* comment */true}'],
    ["trailing object comma", '{"value":true,}'],
    ["trailing array comma", '{"values":[true,]}'],
    ["JavaScript literal", '{"value":undefined}'],
    ["UTF-8 BOM", "\ufeff{}"],
  ])("rejects non-strict syntax: %s", (_name, text) => {
    expect(codes(decodeStrictJsonObject(bytes(text)))).toEqual([
      "JSON_SYNTAX_INVALID",
    ]);
  });

  it("rejects a non-object JSON root", () => {
    expect(codes(decodeStrictJsonObject(bytes("[]")))).toEqual([
      "JSON_ROOT_NOT_OBJECT",
    ]);
  });

  it("runs duplicate-member rejection before JSON Schema validation", () => {
    const validate = compileContractBytes({
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      additionalProperties: false,
      required: ["state"],
      properties: { state: { const: "unknown" } },
    });

    const validation = validate(bytes('{"state":"compatible","state":"unknown"}'));
    expect(validation.valid).toBe(false);
    if (!validation.valid) {
      expect(validation.stage).toBe("decode");
      expect(validation.errors).toMatchObject([
        { code: "JSON_DUPLICATE_MEMBER", path: "/state" },
      ]);
    }
  });
});
