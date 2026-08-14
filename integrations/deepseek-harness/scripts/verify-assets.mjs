import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const integrationRoot = fileURLToPath(new URL("../", import.meta.url));
const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const requiredDestinations = new Set([
  "lib/index.js",
  "assets/SKILL.md",
  "assets/scripts/scan.py",
  "assets/scripts/scan.sh",
  "assets/references/detection-rules.md",
  "LICENSE",
]);

function sourcePath(relativePath) {
  return relativePath.startsWith("src/")
    ? path.join(integrationRoot, relativePath)
    : path.join(repositoryRoot, relativePath);
}

function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}

const manifestPath = path.join(integrationRoot, "assets", "source-manifest.json");
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.files)) {
  throw new Error("Unsupported or malformed source manifest");
}

const seen = new Set();
for (const record of manifest.files) {
  if (!requiredDestinations.has(record.destination) || seen.has(record.destination)) {
    throw new Error(`Unexpected or duplicate manifest destination: ${record.destination}`);
  }
  seen.add(record.destination);

  const [source, destination] = await Promise.all([
    readFile(sourcePath(record.source)),
    readFile(path.join(integrationRoot, record.destination)),
  ]);
  const sourceHash = sha256(source);
  if (
    record.bytes !== source.byteLength ||
    record.sha256 !== sourceHash ||
    sha256(destination) !== sourceHash
  ) {
    throw new Error(`Generated asset does not match its source: ${record.destination}`);
  }
}

for (const required of requiredDestinations) {
  if (!seen.has(required)) {
    throw new Error(`Required generated file is missing from manifest: ${required}`);
  }
}

console.log(`Verified ${seen.size} generated files against canonical sources.`);
