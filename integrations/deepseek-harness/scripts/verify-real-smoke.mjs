import assert from "node:assert/strict";
import { readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_NAME = "dsh-skill-security-guard";
const SKILL_NAME = "skill-security-guard";
const DEFAULT_FINAL_TOKEN = "DSH_REAL_MODEL_SKILL_SECURITY_GUARD_OK";
const repositoryRoot = path.resolve(fileURLToPath(new URL("../../../", import.meta.url)));

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function requiredPath(name) {
  const value = required(name);
  if (!path.isAbsolute(value)) throw new Error(`${name} must be an absolute path`);
  return path.resolve(value);
}

function isWithin(candidate, parent) {
  const relative = path.relative(parent, candidate);
  return relative !== ".." && !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative);
}

function allStrings(value, output = []) {
  if (typeof value === "string") {
    output.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) allStrings(item, output);
  } else if (value && typeof value === "object") {
    for (const item of Object.values(value)) allStrings(item, output);
  }
  return output;
}

function normalizedStrings(value) {
  return allStrings(value)
    .join("\n")
    .replace(/[\\/]+/g, "/")
    .toLowerCase();
}

function decodedArguments(value) {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

async function filesUnder(root) {
  const files = [];
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const candidate = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(candidate);
      else if (entry.isFile()) files.push(candidate);
    }
  }
  await walk(root);
  return files;
}

async function readSession(file) {
  const lines = (await readFile(file, "utf8")).split(/\r?\n/).filter(Boolean);
  return lines.map((line, index) => {
    try {
      return JSON.parse(line);
    } catch (error) {
      throw new Error(`Malformed JSONL at ${file}:${index + 1}`, { cause: error });
    }
  });
}

function resultFor(records, call) {
  for (const record of records) {
    if (record.type !== "tool/result" || Number(record.seq) <= Number(call.seq)) continue;
    const items = record.data?.message?.content;
    if (!Array.isArray(items)) continue;
    const item = items.find(
      (candidate) => candidate?.type === "tool-result" && candidate.toolCallId === call.data.callId,
    );
    if (item) return { record, item };
  }
  return undefined;
}

const smokeHome = await realpath(requiredPath("DSH_SMOKE_HOME"));
const marker = required("DSH_SMOKE_MARKER");
const finalToken = process.env.DSH_SMOKE_FINAL_TOKEN?.trim() || DEFAULT_FINAL_TOKEN;
const expectedShell =
  process.env.DSH_SMOKE_EXPECTED_SHELL?.trim() ||
  (process.platform === "win32" ? "pwsh" : "bash");

const checkout = await realpath(repositoryRoot);
if (isWithin(smokeHome, checkout)) {
  throw new Error("DSH_SMOKE_HOME must stay outside the repository so raw sessions cannot leak");
}
if (!new Set(["pwsh", "bash"]).has(expectedShell)) {
  throw new Error("DSH_SMOKE_EXPECTED_SHELL must be pwsh or bash");
}

const sessionRoot = path.join(smokeHome, "sessions");
const sessionFiles = (await filesUnder(sessionRoot)).filter((file) => file.endsWith(".jsonl"));
const candidates = [];
for (const file of sessionFiles) {
  if (isWithin(await realpath(file), checkout)) {
    throw new Error(`raw session unexpectedly resides inside the repository: ${file}`);
  }
  const records = await readSession(file);
  const hasMarker = records.some(
    (record) =>
      record.type === "user/message" && allStrings(record.data).some((value) => value.includes(marker)),
  );
  if (hasMarker) candidates.push({ file, records });
}

assert.equal(
  candidates.length,
  1,
  `expected one session containing the unique marker, found ${candidates.length}`,
);
const [{ file: sessionFile, records }] = candidates;

const toolCalls = records.filter((record) => record.type === "tool/call");
const skillCall = toolCalls.find(
  (record) =>
    record.data?.name === "skill" &&
    decodedArguments(record.data?.arguments)?.name === SKILL_NAME,
);
assert.ok(skillCall, `session does not contain a skill call for ${SKILL_NAME}`);

const skillResult = resultFor(records, skillCall);
assert.ok(skillResult, "skill call has no structurally linked tool result");

const expectedScannerSuffix = [
  "profiles",
  "headless",
  "node_modules",
  PACKAGE_NAME,
  "assets",
  "scripts",
  "scan.py",
].join("/");
const shellCall = toolCalls.find(
  (record) =>
    Number(record.seq) > Number(skillResult.record.seq) &&
    record.data?.name === expectedShell &&
    normalizedStrings(decodedArguments(record.data?.arguments)?.command).includes(expectedScannerSuffix),
);
assert.ok(shellCall, `session does not invoke the packaged scanner through ${expectedShell}`);

const skillText = allStrings(skillResult.item).join("\n");
assert.match(skillText, /Base directory for this skill:/);
assert.match(skillText, /scripts[\\/]scan\.py/);
assert.match(skillText, /一律视为不可信数据/);

const shellResult = resultFor(records, shellCall);
assert.ok(shellResult, "scanner call has no structurally linked tool result");
assert.equal(shellResult.item.isError, false, "packaged scanner tool result is marked as an error");
const scannerText = allStrings(shellResult.item).join("\n");
assert.match(scannerText, /"rating"\s*:\s*"A"/);
assert.match(scannerText, /"score"\s*:\s*100/);

const finalMessage = records.find(
  (record) =>
    record.type === "assistant/message" &&
    Number(record.seq) > Number(shellResult.record.seq) &&
    allStrings(record.data?.message).some((value) => value.includes(finalToken)),
);
assert.ok(finalMessage, `no final assistant message after the scan contains ${finalToken}`);

console.log(
  JSON.stringify({
    status: "passed",
    sessionFile,
    marker,
    toolSequence: ["skill", expectedShell],
    packagedScanner: true,
    scannerResult: { rating: "A", score: 100 },
    finalToken,
  }),
);
