import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { decodeStrictJsonObject } from "../packages/contracts/src/strict-json.js";
import {
  evidenceDefinitionDrift,
  sharedEvidenceDefinitionNames,
  type EvidenceSchemaSnapshot,
} from "./helpers/evidence-schema-coherence.js";

const schemaFiles = [
  "cryptocomm-execution-result-v1.schema.json",
  "cryptocomm-evidence-provenance-v1.schema.json",
  "cryptocomm-freshness-assessment-v1.schema.json",
  "cryptocomm-evidence-binding-set-v1.schema.json",
] as const;

function syntheticSnapshots(): Array<{
  name: string;
  schema: { $defs: Record<string, Record<string, unknown>> };
}> {
  return schemaFiles.map((name) => ({
    name,
    schema: {
      $defs: Object.fromEntries(sharedEvidenceDefinitionNames.map((definition) => [
        definition,
        { type: "string", minLength: 1, maxLength: 128, description: definition },
      ])),
    },
  }));
}

describe("CCA-240 shared schema definition coherence", () => {
  it("checks all 36 shared definitions in all four strict-decoded repository schemas", async () => {
    expect(sharedEvidenceDefinitionNames).toHaveLength(36);
    expect(new Set(sharedEvidenceDefinitionNames).size).toBe(36);
    const snapshots: EvidenceSchemaSnapshot[] = await Promise.all(schemaFiles.map(async (name) => {
      const bytes = await readFile(new URL(`../schema/${name}`, import.meta.url));
      const decoded = decodeStrictJsonObject(bytes);
      if (!decoded.valid) throw new Error(`${name}: strict schema decode failed`);
      return { name, schema: decoded.value };
    }));
    expect(snapshots).toHaveLength(4);
    expect(evidenceDefinitionDrift(snapshots)).toEqual([]);
  });

  it.each([0, 1, 2, 3])("detects one-copy nested safety drift in schema %i", (index) => {
    const snapshots = syntheticSnapshots();
    for (const snapshot of snapshots) {
      snapshot.schema.$defs.safety = {
        type: "object", additionalProperties: false,
        properties: { executable: { const: false } },
      };
    }
    const selected = snapshots[index];
    if (selected === undefined) throw new Error("Missing synthetic schema");
    selected.schema.$defs.safety = {
      type: "object", additionalProperties: false,
      properties: { executable: { const: true } },
    };
    expect(evidenceDefinitionDrift(snapshots)).toContainEqual({
      schema: expect.any(String), definition: "safety", kind: "different-definition",
    });
  });

  it.each(["bindingFingerprint", "sha256Digest", "timestamp"])(
    "detects a changed %s constraint without changing real schema bytes", (definition) => {
      const snapshots = syntheticSnapshots();
      const selected = snapshots[1];
      if (selected === undefined) throw new Error("Missing synthetic schema");
      selected.schema.$defs[definition] = { const: "synthetic-mutated-constraint" };
      expect(evidenceDefinitionDrift(snapshots).some((entry) => entry.definition === definition)).toBe(true);
    },
  );

  it("detects deletion from the comparison baseline and from every copy", () => {
    const snapshots = syntheticSnapshots();
    for (const snapshot of snapshots) delete snapshot.schema.$defs.gitSha1;
    const failures = evidenceDefinitionDrift(snapshots);
    expect(failures).toHaveLength(4);
    expect(failures.every(({ definition, kind }) =>
      definition === "gitSha1" && kind === "missing-definition")).toBe(true);
  });

  it("detects a missing definition even in the first sorted schema", () => {
    const snapshots = syntheticSnapshots();
    const first = [...snapshots].sort((a, b) => a.name < b.name ? -1 : 1)[0];
    if (first === undefined) throw new Error("Missing synthetic schema");
    delete first.schema.$defs.inputBindings;
    expect(evidenceDefinitionDrift(snapshots)).toEqual([
      { schema: first.name, definition: "inputBindings", kind: "missing-definition" },
    ]);
  });

  it.each([null, [], "not-a-definition-map"])("rejects malformed $defs: %j", (defs) => {
    const snapshots: EvidenceSchemaSnapshot[] = syntheticSnapshots();
    snapshots[0] = { name: schemaFiles[0], schema: { $defs: defs } };
    expect(evidenceDefinitionDrift(snapshots)).toContainEqual({
      schema: schemaFiles[0], definition: "$defs", kind: "missing-definitions",
    });
  });

  it("ignores object key order but does not erase array changes", () => {
    const snapshots = syntheticSnapshots();
    const first = snapshots[0];
    if (first === undefined) throw new Error("Missing synthetic schema");
    first.schema.$defs.boundedId = {
      description: "boundedId", maxLength: 128, minLength: 1, type: "string",
    };
    expect(evidenceDefinitionDrift(snapshots)).toEqual([]);
    for (const snapshot of snapshots) {
      snapshot.schema.$defs.subject = { required: ["kind", "identity"] };
    }
    first.schema.$defs.subject = { required: ["identity", "kind"] };
    expect(evidenceDefinitionDrift(snapshots).some(({ definition }) => definition === "subject")).toBe(true);
  });

  it("allows contract-specific definitions and remains input-order independent", () => {
    const snapshots = syntheticSnapshots();
    const first = snapshots[0];
    if (first === undefined) throw new Error("Missing synthetic schema");
    first.schema.$defs.localExecutionDetails = { type: "object" };
    expect(evidenceDefinitionDrift(snapshots)).toEqual([]);
    first.schema.$defs.version = { const: "synthetic-drift" };
    expect(evidenceDefinitionDrift([...snapshots].reverse())).toEqual(evidenceDefinitionDrift(snapshots));
  });
});
