import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { Context } from "@deepseek-ai/cordis";
import SkillRegistry, { renderSkillContent } from "@deepseek-ai/dsh-skill";
import * as SkillSecurityGuard from "../lib/index.js";

const integrationRoot = fileURLToPath(new URL("../", import.meta.url));
const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const python =
  process.env.PYTHON_EXECUTABLE || (process.platform === "win32" ? "python" : "python3");

test("registers the packaged skill and removes it on Cordis disposal", async () => {
  const ctx = new Context();
  const registryFiber = await ctx.plugin(SkillRegistry);
  const providerFiber = await ctx.plugin(SkillSecurityGuard);

  try {
    const catalog = await ctx.skills.list();
    const summary = catalog.find((entry) => entry.name === "skill-security-guard");
    assert.ok(summary);
    assert.equal(summary.provider, "skill-security-guard");
    assert.equal(summary.source, "custom");
    assert.deepEqual(summary.invocation, { modelInvocable: true, userInvocable: true });

    const loaded = await ctx.skills.get("skill-security-guard");
    assert.ok(loaded);
    assert.match(loaded.content, /^# skill-security-guard/m);
    assert.match(loaded.content, /一律视为不可信数据/);
    assert.doesNotMatch(loaded.content, /^---/);
    assert.equal(loaded.resourceBase?.kind, "directory");
    assert.ok(existsSync(path.join(loaded.resourceBase.path, "scripts", "scan.py")));
    const rendered = renderSkillContent(loaded);
    assert.match(rendered, /Base directory for this skill:/);
    assert.match(rendered, /python scripts\/scan\.py/);
  } finally {
    await providerFiber.dispose();
  }

  assert.equal(
    (await ctx.skills.list()).some((entry) => entry.name === "skill-security-guard"),
    false,
  );
  await registryFiber.dispose();
});

test("declares the installable DSH Bundle contract", () => {
  const packageJson = JSON.parse(
    readFileSync(path.join(integrationRoot, "package.json"), "utf8"),
  );
  assert.equal(packageJson.dsh?.bundle?.patch, "./cordis.patch.yml");
  assert.equal(packageJson.peerDependenciesMeta?.["@deepseek-ai/dsh-skill"]?.optional, true);
  assert.equal(
    readFileSync(path.join(integrationRoot, "cordis.patch.yml"), "utf8").replaceAll("\r\n", "\n"),
    "- insert:\n    - id: skill-security-guard\n      name: dsh-skill-security-guard\n",
  );
});

test("honors an aborted skill discovery", async () => {
  const ctx = new Context();
  const registryFiber = await ctx.plugin(SkillRegistry);
  const providerFiber = await ctx.plugin(SkillSecurityGuard);
  const controller = new AbortController();
  controller.abort(new Error("test discovery cancelled"));

  try {
    await assert.rejects(ctx.skills.list({ signal: controller.signal }), /test discovery cancelled/);
  } finally {
    await providerFiber.dispose();
    await registryFiber.dispose();
  }
});

test("generated assets include every release input", () => {
  const manifest = JSON.parse(
    readFileSync(path.join(integrationRoot, "assets", "source-manifest.json"), "utf8"),
  );
  assert.equal(manifest.schemaVersion, 1);
  assert.deepEqual(
    new Set(manifest.files.map((entry) => entry.destination)),
    new Set([
      "lib/index.js",
      "assets/SKILL.md",
      "assets/scripts/scan.py",
      "assets/scripts/scan.sh",
      "assets/references/detection-rules.md",
      "LICENSE",
    ]),
  );
});

test("the packaged scanner preserves safe and high-risk behavior", () => {
  const scanner = path.join(integrationRoot, "assets", "scripts", "scan.py");
  const safe = spawnSync(
    python,
    [scanner, path.join(repositoryRoot, "tests", "fixtures", "safe-skill"), "--format", "json"],
    { encoding: "utf8" },
  );
  assert.equal(safe.status, 0, safe.stderr || safe.stdout);
  assert.equal(JSON.parse(safe.stdout)[0].rating, "A");

  const highRisk = spawnSync(
    python,
    [
      scanner,
      path.join(repositoryRoot, "tests", "fixtures", "high-risk-skill"),
      "--format",
      "json",
    ],
    { encoding: "utf8" },
  );
  assert.equal(highRisk.status, 1, highRisk.stderr || highRisk.stdout);
  const report = JSON.parse(highRisk.stdout)[0];
  assert.equal(report.rating, "F");
  assert.ok(report.issues.some((issue) => issue.rule_id === "M4-REMOTE-SCRIPT-EXEC"));
});
