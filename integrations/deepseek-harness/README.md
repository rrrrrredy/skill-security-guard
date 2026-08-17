# dsh-skill-security-guard

Community DeepSeek Harness Bundle for [`skill-security-guard`](https://github.com/rrrrrredy/skill-security-guard). It registers the existing static-analysis skill and packages its Python scanner as a resolvable skill resource.

This is a community plugin, not an official DeepSeek plugin.

## Compatibility

- DeepSeek Harness / `@deepseek-ai/dsh`: `0.1.0-rc.6`
- Node.js: `22.19.x` or `24+` (matching the package `engines` declaration)
- Python: `3.10+`

## Install

Install the public npm package into a Harness profile:

```bash
dsh plugin --profile headless add dsh-skill-security-guard@0.1.0
dsh --profile headless --dump-config
```

For a local release candidate, replace the npm specifier with the path to the packed `.tgz`.

Use the npm package or a reviewed tarball. A `github:` install is intentionally unsupported because generated `lib/` and `assets/` are not committed, and this package does not request permission to execute a build during installation.

## Use

Run a one-shot task and ask the agent to use `skill-security-guard` before installing or trusting an agent skill:

```bash
dsh --profile headless "Use skill-security-guard to scan ./path/to/a-skill and explain every confirmed finding."
```

For the browser surface, install the Bundle into the separate `web` profile and start it:

```bash
dsh plugin --profile web add dsh-skill-security-guard@0.1.0
dsh --profile web
```

The skill instructs the agent to run the packaged `scripts/scan.py`; it does not add a new model tool or silently scan unrelated files.

## Uninstall

```bash
dsh plugin --profile headless remove dsh-skill-security-guard
dsh --profile headless --dump-config
```

After removal, the `skill-security-guard` provider and its catalog entry are absent.

## Permissions and privacy

- The Bundle itself performs no network requests and has no telemetry.
- The scanner reads only the target supplied by the user or agent. Public URL input is fetched only when explicitly passed to the scanner.
- The Bundle adds no upload path of its own. In an LLM-backed Harness profile, skill instructions, shell commands, and scanner output can still be sent to the model provider configured for that profile as part of normal agent operation.
- This is static analysis, not runtime monitoring, sandboxing, provenance verification, or a substitute for human review.

## Reproduce the package tests

From this directory:

```bash
pnpm install --frozen-lockfile
pnpm verify
pnpm pack --pack-destination .pack
```

`pnpm verify` builds assets from the canonical repository files, checks their SHA-256 manifest, loads and disposes the provider through real Cordis services, and runs the packaged scanner against safe and malicious fixtures.

The deterministic full-Harness test additionally needs an installed DSH entry, a packed tarball, Python, and an explicit scratch root:

```bash
DSH_ENTRY=/absolute/path/to/@deepseek-ai/dsh/lib/bin.js \
DSH_TARBALL=/absolute/path/to/dsh-skill-security-guard-0.1.0.tgz \
DSH_E2E_ROOT=/absolute/path/to/scratch \
PYTHON_EXECUTABLE=/absolute/path/to/python \
pnpm test:e2e:dsh
```

PowerShell equivalent:

```powershell
$env:DSH_ENTRY = "D:\path\to\@deepseek-ai\dsh\lib\bin.js"
$env:DSH_TARBALL = "D:\path\to\dsh-skill-security-guard-0.1.0.tgz"
$env:DSH_E2E_ROOT = "D:\path\to\scratch"
$env:PYTHON_EXECUTABLE = "C:\path\to\python.exe"
pnpm test:e2e:dsh
```

It installs the tarball into a fresh headless profile, drives `skill` and the platform shell through a loopback-only deterministic DeepSeek protocol server, verifies the packaged scanner returns rating A, and checks the append-only session JSONL for structural `tool/call` and `tool/result` evidence. Successful artifacts are deleted by default; set `DSH_E2E_KEEP=1` to retain the isolated profile for local inspection. The mock test does not replace the separate real-model release smoke.

Versioned candidate results and the still-open external release gates are recorded in the public [`0.1.0 release evidence`](https://github.com/rrrrrredy/skill-security-guard/blob/main/integrations/deepseek-harness/release-evidence/0.1.0.md). A candidate is not treated as publicly released until every external gate in that record is complete.
