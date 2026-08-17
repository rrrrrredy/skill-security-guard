import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_NAME = "dsh-skill-security-guard";
const FINAL_TEXT = "DETERMINISTIC_DSH_SKILL_E2E_OK";
const TASK_TEXT =
  "Load skill-security-guard, scan the safe fixture with its packaged scanner, and report the rating.";
const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const realSmokeVerifier = fileURLToPath(new URL("./verify-real-smoke.mjs", import.meta.url));

function requiredPath(name) {
  const value = process.env[name];
  if (!value?.trim()) throw new Error(`${name} must be an absolute path`);
  if (!path.isAbsolute(value)) throw new Error(`${name} must be an absolute path`);
  return path.normalize(value);
}

const dshEntry = requiredPath("DSH_ENTRY");
const packageSpec = process.env.DSH_PACKAGE_SPEC?.trim();
const tarball = process.env.DSH_TARBALL?.trim();
if (!packageSpec && !tarball) {
  throw new Error("exactly one of DSH_PACKAGE_SPEC or DSH_TARBALL must be set");
}
if (packageSpec && tarball) {
  throw new Error("DSH_PACKAGE_SPEC and DSH_TARBALL are mutually exclusive");
}
const installSpec = packageSpec || requiredPath("DSH_TARBALL");
const scratchRoot = requiredPath("DSH_E2E_ROOT");
const pythonExecutable = requiredPath("PYTHON_EXECUTABLE");
const keepArtifacts = process.env.DSH_E2E_KEEP === "1";
const permissionMode = process.env.DSH_E2E_PERMISSION_MODE ?? "workspace-write";
if (!new Set(["workspace-write", "danger-full-access"]).has(permissionMode)) {
  throw new Error("DSH_E2E_PERMISSION_MODE must be workspace-write or danger-full-access");
}

await Promise.all([
  access(dshEntry),
  access(pythonExecutable),
  ...(packageSpec ? [] : [access(installSpec)]),
]);
await mkdir(scratchRoot, { recursive: true });
const home = await mkdtemp(path.join(scratchRoot, "skill-security-guard-"));

function runDsh(args, extraEnv = {}, timeoutMs = 60_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [dshEntry, ...args], {
      cwd: repositoryRoot,
      env: {
        ...process.env,
        DSH_HOME: home,
        DSH_TELEMETRY_MODE: "DISABLED",
        ...extraEnv,
      },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", reject);
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`dsh timed out after ${timeoutMs}ms: ${args.join(" ")}\n${stderr}`));
    }, timeoutMs);
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code: code ?? -1, signal, stdout, stderr });
    });
  });
}

function runNodeScript(script, extraEnv = {}, timeoutMs = 30_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script], {
      cwd: repositoryRoot,
      env: { ...process.env, ...extraEnv },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.once("error", reject);
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`node script timed out after ${timeoutMs}ms: ${script}\n${stderr}`));
    }, timeoutMs);
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code: code ?? -1, signal, stdout, stderr });
    });
  });
}

function sse(response, payload) {
  response.write(`data: ${typeof payload === "string" ? payload : JSON.stringify(payload)}\n\n`);
}

function finishToolCall(response, id, toolName, toolArguments) {
  response.writeHead(200, {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });
  sse(response, {
    choices: [
      {
        index: 0,
        delta: {
          tool_calls: [
            {
              index: 0,
              id,
              type: "function",
              function: { name: toolName, arguments: JSON.stringify(toolArguments) },
            },
          ],
        },
        finish_reason: null,
      },
    ],
  });
  sse(response, {
    choices: [{ index: 0, delta: { content: "" }, finish_reason: "tool_calls" }],
    usage: { prompt_tokens: 3, completion_tokens: 2 },
  });
  sse(response, "[DONE]");
  response.end();
}

function finishText(response, text) {
  response.writeHead(200, {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });
  sse(response, {
    choices: [{ index: 0, delta: { content: text }, finish_reason: null }],
  });
  sse(response, {
    choices: [{ index: 0, delta: { content: "" }, finish_reason: "stop" }],
    usage: { prompt_tokens: 3, completion_tokens: text.length },
  });
  sse(response, "[DONE]");
  response.end();
}

function quoteShell(value) {
  if (process.platform === "win32") return `'${value.replaceAll("'", "''")}'`;
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
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

let server;
let passed = false;
const requestBodies = [];
try {
  const install = await runDsh(["plugin", "--profile", "headless", "add", installSpec]);
  assert.equal(install.code, 0, install.stderr || install.stdout);

  const profileDir = path.join(home, "profiles", "headless");
  const installedRoot = path.join(profileDir, "node_modules", PACKAGE_NAME);
  const scanner = path.join(installedRoot, "assets", "scripts", "scan.py");
  const safeFixture = path.join(repositoryRoot, "tests", "fixtures", "safe-skill");
  await Promise.all([access(scanner), access(safeFixture)]);
  await writeFile(
    path.join(profileDir, "cordis.patch.yml"),
    [
      "- id: session-title-llm",
      "  disabled: true",
      "- id: session-persistence-jsonl",
      "  config:",
      "    root: !!js dshHomePath('sessions')",
      "    compression: none",
      "",
    ].join("\n"),
    "utf8",
  );

  const shellTool = process.platform === "win32" ? "pwsh" : "bash";
  const quotedScanCommand = `${quoteShell(pythonExecutable)} ${quoteShell(scanner)} ${quoteShell(
    safeFixture,
  )} --format json`;
  const scanCommand = process.platform === "win32" ? `& ${quotedScanCommand}` : quotedScanCommand;
  server = createServer(async (request, response) => {
    try {
      if (request.method !== "POST" || !request.url?.endsWith("/chat/completions")) {
        response.writeHead(404).end();
        return;
      }
      if (request.headers.authorization !== "Bearer deterministic-mock-key") {
        response.writeHead(401, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: { message: "bad mock key" } }));
        return;
      }
      const body = await readBody(request);
      requestBodies.push(body);
      if (requestBodies.length === 1) {
        finishToolCall(response, "call-skill-1", "skill", { name: "skill-security-guard" });
      } else if (requestBodies.length === 2) {
        finishToolCall(response, "call-shell-2", shellTool, {
          command: scanCommand,
          description: "Scan the safe fixture with the packaged security scanner",
          timeoutMs: 30_000,
        });
      } else if (requestBodies.length === 3) {
        finishText(response, FINAL_TEXT);
      } else {
        response.writeHead(500, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: { message: "mock script exhausted" } }));
      }
    } catch (error) {
      response.writeHead(500, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { message: String(error) } }));
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const baseURL = `http://127.0.0.1:${address.port}`;

  const run = await runDsh(
    [
      "--profile",
      "headless",
      TASK_TEXT,
    ],
    {
      DEEPSEEK_API_KEY: "deterministic-mock-key",
      DEEPSEEK_BASE_URL: baseURL,
      DSH_PERMISSION_MODE: permissionMode,
      NO_PROXY: "127.0.0.1,localhost",
    },
  );
  assert.equal(run.code, 0, run.stderr || run.stdout);
  assert.equal(run.stderr, "");
  assert.equal(run.stdout.trim(), FINAL_TEXT);
  assert.equal(requestBodies.length, 3);
  if (keepArtifacts) {
    await writeFile(
      path.join(home, "mock-requests.json"),
      `${JSON.stringify(requestBodies, null, 2)}\n`,
      "utf8",
    );
  }

  const advertisedTools = requestBodies[0].tools?.map((tool) => tool.function?.name) ?? [];
  assert.ok(advertisedTools.includes("skill"));
  assert.ok(advertisedTools.includes(shellTool));
  const afterSkill = allStrings(requestBodies[1]).join("\n");
  assert.ok(afterSkill.includes('<skill_content name="skill-security-guard">'));
  assert.ok(afterSkill.includes("Base directory for this skill:"));
  assert.ok(afterSkill.includes("scripts/scan.py"));
  assert.ok(afterSkill.includes("一律视为不可信数据"));
  const afterScan = allStrings(requestBodies[2]).join("\n");
  assert.match(afterScan, /"rating":\s*"A"/);
  assert.match(afterScan, /"score":\s*100/);

  const sessionRoot = path.join(home, "sessions");
  const sessionFiles = (await filesUnder(sessionRoot)).filter((file) => file.endsWith(".jsonl"));
  assert.ok(sessionFiles.length > 0, "headless run did not persist a JSONL session");
  const sessionText = (
    await Promise.all(sessionFiles.map((file) => readFile(file, "utf8")))
  ).join("\n");
  const sessionRecords = sessionText
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  assert.ok(sessionRecords.some((record) => record.type === "tool/call"));
  assert.ok(sessionRecords.some((record) => record.type === "tool/result"));
  const sessionStrings = allStrings(sessionRecords).join("\n");
  assert.ok(sessionStrings.includes("skill-security-guard"));
  assert.ok(sessionStrings.includes(shellTool));
  assert.match(sessionStrings, /"rating":\s*"A"/);

  const verification = await runNodeScript(realSmokeVerifier, {
    DSH_SMOKE_HOME: home,
    DSH_SMOKE_MARKER: TASK_TEXT,
    DSH_SMOKE_FINAL_TOKEN: FINAL_TEXT,
    DSH_SMOKE_EXPECTED_SHELL: shellTool,
  });
  assert.equal(verification.code, 0, verification.stderr || verification.stdout);
  assert.equal(verification.stderr, "");
  const verificationSummary = JSON.parse(verification.stdout);
  assert.equal(verificationSummary.status, "passed");
  assert.equal(verificationSummary.packagedScanner, true);
  assert.deepEqual(verificationSummary.scannerResult, { rating: "A", score: 100 });

  const remove = await runDsh([
    "plugin",
    "--profile",
    "headless",
    "remove",
    PACKAGE_NAME,
  ]);
  assert.equal(remove.code, 0, remove.stderr || remove.stdout);
  const afterRemove = await runDsh(["--profile", "headless", "--dump-config"]);
  assert.equal(afterRemove.code, 0, afterRemove.stderr || afterRemove.stdout);
  assert.ok(
    !`${afterRemove.stdout}\n${afterRemove.stderr}`.includes(PACKAGE_NAME),
    "removed Bundle remains in the dumped profile configuration",
  );
  await assert.rejects(access(installedRoot), { code: "ENOENT" });

  passed = true;
  console.log(
    JSON.stringify({
      status: "passed",
      requests: requestBodies.length,
      toolSequence: ["skill", shellTool],
      scannerResult: "A",
      sessionJsonlFiles: sessionFiles.length,
      structuralVerifier: verificationSummary.status,
      removed: true,
      artifactsKept: keepArtifacts,
      ...(keepArtifacts ? { artifactRoot: home } : {}),
    }),
  );
} finally {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
  if (passed && !keepArtifacts) {
    const parent = path.dirname(home);
    if (parent !== path.resolve(scratchRoot) || !path.basename(home).startsWith("skill-security-guard-")) {
      throw new Error(`refusing to remove unexpected E2E directory: ${home}`);
    }
    await rm(home, { recursive: true, force: true });
  } else if (!passed) {
    console.error(`Deterministic E2E artifacts retained at ${home}`);
  }
}
