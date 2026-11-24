# skill-security-guard

[![CI](https://github.com/rrrrrredy/skill-security-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/rrrrrredy/skill-security-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

Static security scanner for agent skill packages.

`skill-security-guard` performs a deterministic 7-dimension scan, assigns an A-F risk rating, reports confidence levels, and gives remediation guidance. The CLI uses only the Python standard library, so it runs on Windows, macOS, and Linux without project dependencies.

It can be used as an OpenClaw skill, as a DeepSeek Harness community Bundle, or as a standalone scanner for local skill packages.

## What It Scans

- Prompt-injection and instruction-override patterns
- Sensitive file reads and data exfiltration patterns
- Compliance red lines such as tunneling, restricted-system access, highly sensitive data handling, and sensitive config backup/upload
- Malicious script patterns in `scripts/`
- Dependency installation from non-default or suspicious sources
- Over-broad or unclear `description` trigger scopes
- Frontmatter compliance (`name` and `description`)

## Quick Start

```bash
git clone https://github.com/rrrrrredy/skill-security-guard.git
cd skill-security-guard

python scripts/scan.py path/to/SKILL.md
python scripts/scan.py path/to/skill-directory
python scripts/scan.py path/to/skills.zip
python scripts/scan.py --text "inline skill text"
```

Shell wrapper:

```bash
bash scripts/scan.sh path/to/skill-directory
```

JSON output:

```bash
python scripts/scan.py path/to/skill-directory --format json
```

Default JSON emits an array of deterministic `skill-security-scan.v1` attestations.
It includes the scanner version, SHA-256 of the exact scanned UTF-8 bundle,
the sorted per-run ignore list, and `complete: true`. A downstream release or
impact ledger should reject a report whose `input_sha256` does not match the
candidate bytes. See `schemas/skill-security-scan.v1.schema.json`.

Ignore a reviewed rule for one run:

```bash
python scripts/scan.py path/to/skill-directory --ignore R3-N5
```

## Example Output

Safe skill:

```text
Skill Security Report: safe-skill
Scanner: 5.3.0 (skill-security-scan.v1)
Input SHA-256: sha256:<64 lowercase hex characters>
Complete: true
Rating: A (100/100)

Issues: none

Passed dimensions:
- Prompt injection
- Sensitive file access / data exfiltration
- Compliance violations
- Malicious scripts
- Dependency safety
- Description trigger reasonability
- Frontmatter compliance
```

High-risk skill:

```text
Skill Security Report: high-risk-skill
Rating: F (0/100)

Issues (5):
- [high/confirmed] M4-REMOTE-SCRIPT-EXEC: Remote script execution detected
- [high/confirmed] S2-EXFILTRATION: Sensitive data exfiltration pattern detected
- [medium/confirmed] P1-PROMPT-INJECTION: Prompt-injection instruction detected
```

## Input Support

- `SKILL.md` or any local text/code file
- Skill directory containing one or more `SKILL.md` files
- `.zip`, `.tar`, `.tar.gz` and `.tgz` packages, inspected in memory
- `-` for stdin
- `--text` for inline text
- Public `http://` or `https://` text URLs, capped by response size and timeout

Package scans include `SKILL.md`, supported files under `scripts/` and `tests/`, and executable source files elsewhere in the package. Use `--include-references` to include reference Markdown. Archives reject absolute paths, traversal, links, conflicting entries and special files. The defaults are 500 members and 10 MiB each for the compressed input and the combined member contents. TAR framing and extension metadata have a separate bounded allowance. Local scans reject file links leaving their individual skill root and directory links. Local text files decode with replacement for invalid bytes. Stdin remains strict UTF-8.

## Package census

```bash
python scripts/scan.py --batch-dir packages --workers 4 --format jsonl --output census.jsonl
python scripts/scan.py path/to/skill --extract-intent-context
```

Each JSONL record conforms to `schemas/skill-security-scan.v2-census.schema.json`. A directory, archive or standalone input can opt in with `--format jsonl` or `--extract-intent-context`. Batch mode defaults to JSONL. Explicit `--format json` in census mode writes an array of the same records. Place `--output` outside the input packages. Files use UTF-8 and are replaced after the scan finishes.

A successful row contains a batch-relative POSIX source path, scanner version, both digests, declared name and description, and redacted ±3-line context on each finding. Rows are emitted in stable package order for all worker counts. An unreadable or rejected package produces a `complete: false` error row and scanning continues. Exit 0 means every rating is A–C, 1 means at least one D/F, and 2 means an input or output error occurred.

`canonical_tree_sha256` sorts package-relative POSIX paths in UTF-8 order. For each file it hashes an eight-byte big-endian path length, the path bytes, an eight-byte big-endian content length, and the 32 raw bytes of that file's SHA-256. The final value is `sha256:` plus the lowercase hex digest. This includes binary assets and unselected references. Archive wrappers, file order, timestamps and permissions do not affect it. Nested skill packages have their own boundaries; test fixture skills are excluded from their parent. VCS data, `node_modules`, virtual environments and Python caches are excluded. Internal file symlinks contribute their logical path and target bytes.

## Requirements

- Python 3.10+
- No runtime package dependencies

Every push and pull request runs the core tests with site packages disabled and validates emitted records against both schemas on Ubuntu and Windows with Python 3.10, 3.11 and 3.12. The JSON Schema validator is a CI-only dependency. Bundle inputs additionally trigger the DeepSeek Harness provider and headless tests.

## DeepSeek Harness

The `dsh-skill-security-guard` community Bundle registers this repository's existing `SKILL.md` through the native Cordis Skill Provider API. It packages the same scanner and detection rules rather than maintaining a second implementation.

After the package is published, install it into a profile:

```bash
dsh plugin --profile headless add dsh-skill-security-guard@0.1.0
dsh --profile headless --dump-config
dsh --profile headless "Use skill-security-guard to scan ./path/to/a-skill."
```

Then ask the agent to use `skill-security-guard` to scan a file, directory, zip, URL, or inline skill text. Python 3.10+ is required when the scanner runs. See [`integrations/deepseek-harness`](integrations/deepseek-harness) for compatibility, privacy boundaries, local package verification, and uninstall instructions.

This is a community plugin, not an official DeepSeek plugin.

## Rating Model

- `A`: no findings
- `B`: advisory-only or light findings
- `C`: medium-risk findings that should be reviewed
- `D`: multiple confirmed medium-risk findings or serious degradation
- `F`: direct high-risk finding, such as exfiltration, tunneling, destructive commands, or remote script execution

The exact detection patterns and scoring rules live in [`references/detection-rules.md`](references/detection-rules.md).

## Development

Run tests:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

Run sample scans:

```bash
python scripts/scan.py tests/fixtures/safe-skill
python scripts/scan.py tests/fixtures/high-risk-skill
```

Run the scanner against this repository:

```bash
python scripts/scan.py .
```

## Project Structure

```text
skill-security-guard/
├── SKILL.md
├── scripts/
│   ├── scan.py
│   └── scan.sh
├── references/
│   └── detection-rules.md
├── tests/
│   ├── fixtures/
│   └── test_scan.py
└── .github/workflows/ci.yml
```

The DeepSeek Harness integration, including its package manifest, source, build scripts, and tests, lives in [`integrations/deepseek-harness`](integrations/deepseek-harness).

## Limits

This is a static scanner. It does not execute skills, monitor runtime behavior, prove package provenance, or replace human security review. Findings are intentionally conservative and should be reviewed before blocking a skill.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for local development and rule-design guidance.

For vulnerability reports, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
