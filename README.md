# skill-security-guard

[![CI](https://github.com/rrrrrredy/skill-security-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/rrrrrredy/skill-security-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

Static security scanner for agent skill packages.

`skill-security-guard` performs a deterministic 7-dimension scan, assigns an A-F risk rating, reports confidence levels, and gives remediation guidance. The CLI uses only the Python standard library, so it runs on Windows, macOS, and Linux without project dependencies.

It can be used as an OpenClaw skill or as a standalone scanner for local skill packages.

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

Ignore a reviewed rule for one run:

```bash
python scripts/scan.py path/to/skill-directory --ignore R3-N5
```

## Example Output

Safe skill:

```text
Skill Security Report: safe-skill
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
- `.zip` packages, extracted with path traversal checks and size/file-count limits
- `-` for stdin
- `--text` for inline text
- Public `http://` or `https://` text URLs, capped by response size and timeout

Directory and zip scans include `SKILL.md` and files under `scripts/` by default. Reference docs are skipped to reduce false positives; use `--include-references` when you explicitly want to scan reference markdown too.

## Requirements

- Python 3.10+
- No runtime package dependencies

The CI workflow currently tests Python 3.11 and 3.12 on Ubuntu.

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

## Limits

This is a static scanner. It does not execute skills, monitor runtime behavior, prove package provenance, or replace human security review. Findings are intentionally conservative and should be reviewed before blocking a skill.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for local development and rule-design guidance.

For vulnerability reports, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
