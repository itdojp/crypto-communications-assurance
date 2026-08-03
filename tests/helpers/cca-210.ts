import { readFile } from "node:fs/promises";

import {
  aeCcaInputRoles,
  aeUpstreamSchemaRoles,
  decodeStrictJsonObject,
  type AeCcaInputRole,
  type AeRenderPlanValidationInput,
  type AeUpstreamSchemaRole,
} from "../../packages/contracts/src/index.js";

const pin = "c5da6115638fdbfeebbc458b39fa6916db66afb0";

const ccaPaths: Readonly<Record<AeCcaInputRole, string>> = {
  propertyCatalog: "pack/catalogs/v1/property-catalog.json",
  attackerCatalog: "pack/catalogs/v1/attacker-catalog.json",
  threatCatalog: "pack/catalogs/v1/threat-catalog.json",
  capabilityModuleCatalog: "pack/modules/v1/capability-module-catalog.json",
  resolvedProfile: "fixtures/valid/cca-210/resolved-profile-v1.json",
};

const upstreamPaths: Readonly<Record<AeUpstreamSchemaRole, string>> = {
  assuranceProfile: "schema/assurance-profile.schema.json",
  securityClaim: "schema/security-claim-v1.schema.json",
  securityThreatModel: "schema/security-threat-model-v1.schema.json",
  securityAuditScope: "schema/security-audit-scope-v1.schema.json",
  contextPack: "schema/context-pack-v1.schema.json",
};

export const readRepositoryFile = (path: string): Promise<Buffer> => {
  const segments = path.split("/");
  if (
    !/^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/u.test(path) ||
    segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")
  ) {
    throw new Error(`Repository-relative non-traversing path required: ${path}`);
  }
  return readFile(new URL(`../../${path}`, import.meta.url));
};

export async function loadCca210ValidationInput(): Promise<AeRenderPlanValidationInput> {
  const ccaEntries = await Promise.all(
    aeCcaInputRoles.map(async (role) => [role, await readRepositoryFile(ccaPaths[role])] as const),
  );
  const upstreamEntries = await Promise.all(
    aeUpstreamSchemaRoles.map(
      async (role) =>
        [
          role,
          await readRepositoryFile(
            `integrations/ae-framework/pins/${pin}/${upstreamPaths[role]}`,
          ),
        ] as const,
    ),
  );
  return {
    planBytes: await readRepositoryFile("fixtures/valid/cca-210/ae-render-plan-v1.json"),
    ccaInputBytes: Object.fromEntries(ccaEntries) as unknown as Record<AeCcaInputRole, Uint8Array>,
    contextPackBytes: new Map([
      [
        "context.synthetic.cca-210",
        await readRepositoryFile("fixtures/valid/cca-210/context-pack-v1.json"),
      ],
    ]),
    upstreamSchemaBytes: Object.fromEntries(upstreamEntries) as unknown as Record<
      AeUpstreamSchemaRole,
      Uint8Array
    >,
    rendererSourceBytes: await readRepositoryFile(
      "packages/contracts/src/ae-renderer.ts",
    ),
  };
}

export async function loadCca210Plan(): Promise<Record<string, unknown>> {
  const decoded = decodeStrictJsonObject<Record<string, unknown>>(
    await readRepositoryFile("fixtures/valid/cca-210/ae-render-plan-v1.json"),
  );
  if (!decoded.valid) throw new Error("CCA-210 fixture strict decoding failed");
  return structuredClone(decoded.value);
}

export function serializePlan(plan: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(`${JSON.stringify(plan, undefined, 2)}\n`);
}
