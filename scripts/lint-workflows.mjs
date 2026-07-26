import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

import { parseDocument } from "yaml";

const workflowDirectory = ".github/workflows";
const workflowFiles = (await readdir(workflowDirectory))
  .filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"))
  .sort();
const failures = [];
const jobNames = new Set();

if (workflowFiles.length === 0) {
  failures.push("no workflow files found");
}

for (const file of workflowFiles) {
  const filePath = path.join(workflowDirectory, file);
  const source = await readFile(filePath, "utf8");
  const document = parseDocument(source, { prettyErrors: true, strict: true });
  const rawUsesLines = source
    .split("\n")
    .map((line, lineIndex) => {
      const match = line.match(
        /^\s*-?\s*uses:\s*(?:"[^"]*"|'[^']*'|[^\s#]+)\s*(?:#\s*(.+))?$/,
      );
      return match
        ? { lineNumber: lineIndex + 1, versionComment: match[1] }
        : undefined;
    })
    .filter((entry) => entry !== undefined);
  let parsedUsesCount = 0;

  for (const error of document.errors) {
    failures.push(`${filePath}: ${error.message}`);
  }

  const workflow = document.toJS();
  if (workflow === null || typeof workflow !== "object" || Array.isArray(workflow)) {
    failures.push(`${filePath}: workflow root must be a mapping`);
    continue;
  }
  if (!("on" in workflow)) {
    failures.push(`${filePath}: missing on trigger`);
  }
  if (!("permissions" in workflow)) {
    failures.push(`${filePath}: explicit top-level permissions are required`);
  } else if (
    workflow.permissions === null ||
    typeof workflow.permissions !== "object" ||
    Array.isArray(workflow.permissions)
  ) {
    failures.push(`${filePath}: top-level permissions must be a least-privilege mapping`);
  } else {
    for (const [permission, access] of Object.entries(workflow.permissions)) {
      if (access === "write" && permission !== "security-events") {
        failures.push(`${filePath}: unexpected write permission: ${permission}`);
      }
    }
  }
  if (!("jobs" in workflow) || typeof workflow.jobs !== "object" || workflow.jobs === null) {
    failures.push(`${filePath}: jobs must be a mapping`);
    continue;
  }

  for (const [jobId, jobValue] of Object.entries(workflow.jobs)) {
    if (jobValue === null || typeof jobValue !== "object" || Array.isArray(jobValue)) {
      failures.push(`${filePath}: job ${jobId} must be a mapping`);
      continue;
    }
    const displayName = typeof jobValue.name === "string" ? jobValue.name : jobId;
    jobNames.add(displayName);
    if (!Number.isInteger(jobValue["timeout-minutes"]) || jobValue["timeout-minutes"] <= 0) {
      failures.push(`${filePath}: job ${jobId} needs a positive integer timeout-minutes`);
    }
    if (typeof jobValue["runs-on"] !== "string") {
      failures.push(`${filePath}: job ${jobId} needs an explicit runs-on value`);
    }
    if (!Array.isArray(jobValue.steps) || jobValue.steps.length === 0) {
      failures.push(`${filePath}: job ${jobId} needs at least one step`);
      continue;
    }
    for (const [stepIndex, stepValue] of jobValue.steps.entries()) {
      if (stepValue === null || typeof stepValue !== "object" || Array.isArray(stepValue)) {
        failures.push(`${filePath}: job ${jobId} step ${stepIndex + 1} must be a mapping`);
        continue;
      }
      const hasRun = typeof stepValue.run === "string";
      const hasUses = typeof stepValue.uses === "string";
      if (hasRun === hasUses) {
        failures.push(
          `${filePath}: job ${jobId} step ${stepIndex + 1} needs exactly one of run or uses`,
        );
      }
      if (!hasUses) continue;

      const reference = stepValue.uses;
      const rawUsesLine = rawUsesLines[parsedUsesCount];
      parsedUsesCount += 1;
      const lineNumber = rawUsesLine?.lineNumber ?? "unknown";

      if (reference.startsWith("actions/checkout@")) {
        if (stepValue.with?.["persist-credentials"] !== false) {
          failures.push(
            `${filePath}: job ${jobId} checkout must set persist-credentials to false`,
          );
        }
      }

      if (reference.startsWith("./")) continue;
      if (reference.startsWith("docker://")) {
        if (!/@sha256:[0-9a-f]{64}$/.test(reference)) {
          failures.push(`${filePath}:${lineNumber}: Docker actions require a SHA-256 digest`);
        }
        continue;
      }
      if (!/@[0-9a-f]{40}$/.test(reference)) {
        failures.push(
          `${filePath}:${lineNumber}: action must use a full 40-character commit SHA`,
        );
      }
      if (!rawUsesLine?.versionComment || !/v[0-9]/.test(rawUsesLine.versionComment)) {
        failures.push(`${filePath}:${lineNumber}: pinned action needs a release-version comment`);
      }
    }
  }

  if (parsedUsesCount !== rawUsesLines.length) {
    failures.push(
      `${filePath}: parsed ${parsedUsesCount} action references but found ${rawUsesLines.length} source anchors`,
    );
  }
}

for (const expected of [
  "verify",
  "schema-validation",
  "tests",
  "workflow-lint",
  "codeql",
  "dependency-review",
]) {
  if (!jobNames.has(expected)) {
    failures.push(`missing expected check name: ${expected}`);
  }
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log(`Workflow checks passed (${workflowFiles.length} files).`);
}
