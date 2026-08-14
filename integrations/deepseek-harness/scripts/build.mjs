import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const integrationRoot = fileURLToPath(new URL("../", import.meta.url));
const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));

const copies = [
  ["src/index.js", "lib/index.js"],
  ["SKILL.md", "assets/SKILL.md"],
  ["scripts/scan.py", "assets/scripts/scan.py"],
  ["scripts/scan.sh", "assets/scripts/scan.sh"],
  ["references/detection-rules.md", "assets/references/detection-rules.md"],
  ["LICENSE", "LICENSE"],
];

function sourcePath(relativePath) {
  return relativePath.startsWith("src/")
    ? path.join(integrationRoot, relativePath)
    : path.join(repositoryRoot, relativePath);
}

function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}

await Promise.all([
  rm(path.join(integrationRoot, "assets"), { recursive: true, force: true }),
  rm(path.join(integrationRoot, "lib"), { recursive: true, force: true }),
  rm(path.join(integrationRoot, "LICENSE"), { force: true }),
]);

const records = [];
for (const [source, destination] of copies) {
  const sourceFile = sourcePath(source);
  const destinationFile = path.join(integrationRoot, destination);
  await mkdir(path.dirname(destinationFile), { recursive: true });
  await copyFile(sourceFile, destinationFile);
  const content = await readFile(sourceFile);
  records.push({
    source,
    destination,
    bytes: content.byteLength,
    sha256: sha256(content),
  });
}

const manifest = { schemaVersion: 1, files: records };
await writeFile(
  path.join(integrationRoot, "assets", "source-manifest.json"),
  `${JSON.stringify(manifest, null, 2)}\n`,
  "utf8",
);

console.log(`Built ${records.length} files from canonical repository sources.`);
