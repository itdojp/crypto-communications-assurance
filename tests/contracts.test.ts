import { describe, expect, it } from "vitest";

import { compileContract } from "../packages/contracts/src/index.js";

describe("compileContract", () => {
  it("returns stable local validation errors without mutating the candidate", () => {
    const schema = {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      required: ["value"],
      additionalProperties: false,
      properties: { value: { type: "string" } },
    };
    const candidate = Object.freeze({ value: 42 });
    const validate = compileContract(schema);

    const first = validate(candidate);
    const second = validate(candidate);

    expect(first.valid).toBe(false);
    expect(second).toEqual(first);
    expect(candidate).toEqual({ value: 42 });
  });
});
