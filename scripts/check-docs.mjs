import { access, readFile } from "node:fs/promises";

const requiredFiles = [
  "README.md",
  "AGENTS.md",
  "CONTRIBUTING.md",
  "GOVERNANCE.md",
  "SECURITY.md",
  "NOTICE",
  "REUSE.toml",
  "LICENSE",
  ".gitignore",
  ".editorconfig",
  ".node-version",
  "package.json",
  "pnpm-workspace.yaml",
  "tsconfig.json",
  ".github/CODEOWNERS",
  ".github/pull_request_template.md",
  ".github/ISSUE_TEMPLATE/config.yml",
  "docs/PRODUCT_BOUNDARY.md",
  "docs/ARCHITECTURE.md",
  "docs/PUBLIC_PRIVATE_BOUNDARY.md",
  "docs/STATUS_SEMANTICS.md",
  "docs/ROADMAP.md",
  "docs/CONTRACT_VERSIONING.md",
  "docs/CATALOG_COVERAGE.md",
  "docs/SOURCE_BASELINE.md",
  "docs/decisions/0001-repository-and-product-boundary.md",
  "docs/decisions/0002-pack-manifest-lock-and-compatibility.md",
  "docs/decisions/0003-security-catalog-separation-and-relationships.md",
  "docs/decisions/0004-capability-modules-and-deterministic-profile-resolution.md",
  "docs/decisions/0005-execution-provenance-freshness-and-binding.md",
  "docs/decisions/0006-cca-owned-render-plan-and-pinned-ae-native-projection.md",
  "docs/EVIDENCE_CONTRACTS.md",
  "schema/cryptocomm-pack-v1.schema.json",
  "schema/README.md",
  "schema/cryptocomm-pack-manifest-v1.schema.json",
  "schema/cryptocomm-pack-lock-v1.schema.json",
  "schema/cryptocomm-compatibility-record-v1.schema.json",
  "schema/cryptocomm-property-catalog-v1.schema.json",
  "schema/cryptocomm-attacker-catalog-v1.schema.json",
  "schema/cryptocomm-threat-catalog-v1.schema.json",
  "schema/cryptocomm-capability-module-catalog-v1.schema.json",
  "schema/cryptocomm-profile-request-v1.schema.json",
  "schema/cryptocomm-resolved-profile-v1.schema.json",
  "schema/cryptocomm-execution-result-v1.schema.json",
  "schema/cryptocomm-evidence-provenance-v1.schema.json",
  "schema/cryptocomm-freshness-assessment-v1.schema.json",
  "schema/cryptocomm-evidence-binding-set-v1.schema.json",
  "schema/cryptocomm-ae-render-plan-v1.schema.json",
  "integrations/ae-framework/pins/c5da6115638fdbfeebbc458b39fa6916db66afb0/UPSTREAM.json",
  "pack/modules/v1/capability-module-catalog.json",
  "pack/evidence/v1/execution-status-matrix.json",
  "pack/evidence/v1/evidence-classification-matrix.json",
  "packages/contracts/src/evidence.ts",
  "packages/contracts/src/ae-renderer.ts",
  "fixtures/valid/cca-210/ae-render-plan-v1.json",
  "fixtures/valid/cca-210/records/evidence-binding-set-v1.json",
];

const requiredDirectories = [
  "pack",
  "packages/contracts",
  "packages/cli",
  "packages/bridge",
  "packages/ae-pack",
  "packages/gra-pack",
  "integrations/ae-framework",
  "integrations/genai-repo-auditor",
  "adapters/contracts",
  "fixtures",
  "examples",
  "schema",
  "docs",
  "tests",
];

const requiredStatusTerms = [
  "`pass`",
  "`fail`",
  "`skip`",
  "`unsupported`",
  "`timeout`",
  "`tool-error`",
  "`not-run`",
];

const failures = [];
for (const path of requiredFiles) {
  try {
    await access(path);
  } catch {
    failures.push(`missing required file: ${path}`);
  }
}
for (const path of requiredDirectories) {
  try {
    await access(path);
  } catch {
    failures.push(`missing required directory: ${path}`);
  }
}

const statusSemantics = await readFile("docs/STATUS_SEMANTICS.md", "utf8");
for (const term of requiredStatusTerms) {
  if (!statusSemantics.includes(term)) {
    failures.push(`STATUS_SEMANTICS.md does not define ${term}`);
  }
}

const readme = await readFile("README.md", "utf8");
for (const command of [
  "pnpm run build",
  "pnpm run typecheck",
  "pnpm run lint",
  "pnpm run test",
  "pnpm run check:schemas",
  "pnpm run check:docs",
  "pnpm run lint:workflows",
  "pnpm run verify",
]) {
  if (!readme.includes(command)) {
    failures.push(`README.md does not document ${command}`);
  }
}

const architecture = await readFile("docs/ARCHITECTURE.md", "utf8");
for (const distinction of [
  "`bootstrap envelope != manifest`",
  "`manifest != lock`",
  "`lock != compatibility record`",
  "`compatibility != human approval`",
  "`schema validation != semantic validation`",
  "`content binding != security proof`",
  "`module != attacker capability`",
  "`module != product capability`",
  "`profile request != approval`",
  "`resolved profile != product claim`",
  "`resolution outcome != evidence status`",
  "`complete resolution != product security`",
  "`pass != evidence requirement satisfied`",
  "`real != fresh`",
  "`policy-evaluable != policy satisfied`",
  "`fresh != sufficient`",
  "`evidence result != human approval`",
  "`scanner finding != confirmed vulnerability`",
  "`no findings != satisfied claim`",
  "`local proof != machine-checked proof`",
  "`runtime mitigation != absence of a bug`",
  "`binding set != evidence storage`",
  "`property != product claim`",
  "`generated native claim != satisfied claim`",
  "`shape-valid != semantically compatible`",
  "`pass render != evidence satisfied`",
  "`Context Pack reference != Context Pack synthesis`",
  "`full commit in native audit scope != full CCA target identity`",
  "`explicit STRIDE/CWE mapping != automated threat classification`",
  "`renderer != ae-framework execution`",
  "`pinned schema conformance != product-wide compatibility`",
]) {
  if (!architecture.includes(distinction)) {
    failures.push(`ARCHITECTURE.md does not document ${distinction}`);
  }
}
for (const strictBoundary of [
  "1,048,576",
  "128 nested object/array containers",
  "duplicate decoded member names",
  "at most one record for each exact subject/target pair",
  "bounded bundle-relative identifiers",
  "no implicit JSON canonicalization",
]) {
  if (!architecture.includes(strictBoundary)) {
    failures.push(`ARCHITECTURE.md does not document ${strictBoundary}`);
  }
}

const versioning = await readFile("docs/CONTRACT_VERSIONING.md", "utf8");
for (const migrationBoundary of [
  "The only accepted pair is legacy `planned` to new `unknown`",
  "`LEGACY_STATUS_MIGRATION_FORBIDDEN`",
  "evidence-enriching migration",
  "exact dated CWE Top 25 edition",
  "implementation-identity, package-version, or render-plan contract-version",
]) {
  if (!versioning.includes(migrationBoundary)) {
    failures.push(`CONTRACT_VERSIONING.md does not document ${migrationBoundary}`);
  }
}

const schemaReadme = await readFile("schema/README.md", "utf8");
for (const contractId of [
  "`cryptocomm-pack/v1`",
  "`cryptocomm-pack-manifest/v1`",
  "`cryptocomm-pack-lock/v1`",
  "`cryptocomm-compatibility-record/v1`",
  "`cryptocomm-property-catalog/v1`",
  "`cryptocomm-attacker-catalog/v1`",
  "`cryptocomm-threat-catalog/v1`",
  "`cryptocomm-capability-module-catalog/v1`",
  "`cryptocomm-profile-request/v1`",
  "`cryptocomm-resolved-profile/v1`",
  "`cryptocomm-execution-result/v1`",
  "`cryptocomm-evidence-provenance/v1`",
  "`cryptocomm-freshness-assessment/v1`",
  "`cryptocomm-evidence-binding-set/v1`",
  "`cryptocomm-ae-render-plan/v1`",
]) {
  if (!schemaReadme.includes(contractId)) {
    failures.push(`schema/README.md does not document ${contractId}`);
  }
}

const evidenceContracts = await readFile("docs/EVIDENCE_CONTRACTS.md", "utf8");
for (const boundary of [
  "`pass != evidence requirement satisfied`",
  "`real != fresh`",
  "`policy-evaluable != policy satisfied`",
  "`fresh != sufficient`",
  "`evidence result != human approval`",
  "`scanner finding != confirmed vulnerability`",
  "`no findings != satisfied claim`",
  "`local proof != machine-checked proof`",
  "`runtime mitigation != absence of a bug`",
  "`binding set != evidence storage`",
]) {
  if (!evidenceContracts.includes(boundary)) {
    failures.push(`EVIDENCE_CONTRACTS.md does not document ${boundary}`);
  }
}
for (const state of ["`fresh`", "`stale`", "`mismatched`", "`unknown`", "`not-assessed`"]) {
  if (!evidenceContracts.includes(state)) {
    failures.push(`EVIDENCE_CONTRACTS.md does not define freshness state ${state}`);
  }
}
if (
  !evidenceContracts.includes(
    "A `private-opaque` artifact reference inside a public-safe provenance record",
  )
) {
  failures.push(
    "EVIDENCE_CONTRACTS.md does not distinguish a private-opaque artifact reference from its public-safe provenance record",
  );
}

const aeIntegration = await readFile("integrations/ae-framework/README.md", "utf8");
for (const boundary of [
  "c5da6115638fdbfeebbc458b39fa6916db66afb0",
  "0d69865b37a4476a20f0f1f1f42031967d3ec3a7",
  "do not execute ae-framework",
  "not product-wide compatibility",
]) {
  if (!aeIntegration.includes(boundary)) {
    failures.push(`ae-framework integration documentation does not include ${boundary}`);
  }
}

const renderDecision = await readFile(
  "docs/decisions/0006-cca-owned-render-plan-and-pinned-ae-native-projection.md",
  "utf8",
);
for (const boundary of [
  "cryptocomm-ae-render-plan/v1",
  "There is no CCA-210 render-result or output-index contract",
  "operational-procedure",
  "human-review",
  "treeProjection",
  "CCA-330",
]) {
  if (!renderDecision.includes(boundary)) {
    failures.push(`ADR 0006 does not document ${boundary}`);
  }
}

const catalogCoverage = await readFile("docs/CATALOG_COVERAGE.md", "utf8");
for (const boundary of [
  "`catalog entry != product claim`",
  "`catalog coverage != security proof`",
  "`threat != confirmed vulnerability`",
  "`attacker model != universal requirement`",
  "`evidence need != evidence result`",
  "`reference source != compliance claim`",
]) {
  if (!catalogCoverage.includes(boundary)) failures.push(`CATALOG_COVERAGE.md does not document ${boundary}`);
}

const sourceBaseline = await readFile("docs/SOURCE_BASELINE.md", "utf8");
for (const source of ["RFC 3552", "NIST SP 800-57 Part 1 Rev. 5", "NIST SP 800-30 Rev. 1", "RFC 4949", "RFC 9180", "RFC 9420"]) {
  if (!sourceBaseline.includes(source)) failures.push(`SOURCE_BASELINE.md does not document ${source}`);
}
for (const sectionBoundary of [
  "3, 4.4, 5–5.6.4, 6.2, 7, 8–8.4, 9.5",
  "2.3, 3.2 Tasks 2-1 through 2-3, 3.3, Appendices D–F",
]) {
  if (!sourceBaseline.includes(sectionBoundary)) {
    failures.push(`SOURCE_BASELINE.md does not document catalog source boundary ${sectionBoundary}`);
  }
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log(`Documentation checks passed (${requiredFiles.length} required files).`);
}
