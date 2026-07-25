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
  "docs/decisions/0001-repository-and-product-boundary.md",
  "schema/cryptocomm-pack-v1.schema.json",
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
  "pnpm run verify",
]) {
  if (!readme.includes(command)) {
    failures.push(`README.md does not document ${command}`);
  }
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log(`Documentation checks passed (${requiredFiles.length} required files).`);
}
