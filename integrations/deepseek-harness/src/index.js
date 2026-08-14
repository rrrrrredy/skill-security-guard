import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { BUNDLED_SKILL_RANK } from "@deepseek-ai/dsh-skill";

const PROVIDER_NAME = "skill-security-guard";
const SKILL_DOCUMENT_URL = new URL("../assets/SKILL.md", import.meta.url);
const RESOURCE_BASE = Object.freeze({
  kind: "directory",
  path: fileURLToPath(new URL("../assets/", import.meta.url)),
});

function unquote(value) {
  if (
    value.length >= 2 &&
    ((value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'")))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

function parseSkillDocument(document) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/.exec(document);
  if (!match) {
    throw new Error("Packaged SKILL.md is missing YAML frontmatter");
  }

  const metadata = new Map();
  for (const line of match[1].split(/\r?\n/)) {
    const separator = line.indexOf(":");
    if (separator <= 0) continue;
    metadata.set(line.slice(0, separator).trim(), unquote(line.slice(separator + 1).trim()));
  }

  const name = metadata.get("name");
  const description = metadata.get("description");
  if (!name || !description) {
    throw new Error("Packaged SKILL.md must define name and description");
  }

  return { name, description, content: match[2] };
}

const packagedMetadata = parseSkillDocument(readFileSync(SKILL_DOCUMENT_URL, "utf8"));
const CANDIDATE = Object.freeze({
  name: packagedMetadata.name,
  description: packagedMetadata.description,
  invocation: Object.freeze({ modelInvocable: true, userInvocable: true }),
  provider: PROVIDER_NAME,
  source: "custom",
  resourceBase: RESOURCE_BASE,
  rank: BUNDLED_SKILL_RANK,
  locator: SKILL_DOCUMENT_URL,
});

const provider = Object.freeze({
  name: PROVIDER_NAME,
  async list(options = {}) {
    options.signal?.throwIfAborted();
    return [CANDIDATE];
  },
  async get(candidate, options = {}) {
    if (candidate.name !== CANDIDATE.name || candidate.provider !== PROVIDER_NAME) {
      return undefined;
    }

    const document = await readFile(SKILL_DOCUMENT_URL, {
      encoding: "utf8",
      signal: options.signal,
    });
    const skill = parseSkillDocument(document);
    if (skill.name !== CANDIDATE.name || skill.description !== CANDIDATE.description) {
      throw new Error("Packaged SKILL.md metadata changed after provider discovery");
    }

    return {
      name: CANDIDATE.name,
      description: CANDIDATE.description,
      invocation: CANDIDATE.invocation,
      provider: CANDIDATE.provider,
      source: CANDIDATE.source,
      resourceBase: RESOURCE_BASE,
      content: skill.content,
    };
  },
});

export const name = "skill-security-guard";
export const inject = ["skills"];

export function apply(ctx) {
  ctx.skills.registerProvider(() => provider);
}
