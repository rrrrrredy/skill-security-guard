# skill-security-guard

Scan Skill code for security risks across 7 dimensions, output A-F rating with remediation advice.

An [OpenClaw](https://github.com/openclaw/openclaw) Skill for auditing the security of AI agent skills before installation.

## Installation

### Option A: OpenClaw (recommended)
```bash
# Clone to OpenClaw skills directory
git clone https://github.com/rrrrrredy/skill-security-guard ~/.openclaw/skills/skill-security-guard
```

### Option B: Standalone
```bash
git clone https://github.com/rrrrrredy/skill-security-guard
cd skill-security-guard
```

## Dependencies

No additional Python/Node dependencies required. The scanning logic is driven by the AI agent using the detection rules.

### System tools (for zip scanning)
- `unzip` (fallback: `python3 -m zipfile`)

## Usage

### Scan a single Skill
Upload a SKILL.md file or paste its content, then ask:
```
帮我检查这个 Skill
```

### Scan a zip package
Upload a zip containing multiple skills:
```
批量检查这个包里所有 Skill
```

### Auto-fix
After scanning, reply:
```
修复
```
to generate a fixed version of the SKILL.md.

### 7 Security Dimensions
1. **Prompt Injection** — trigger words, role-playing, instruction override
2. **Sensitive File Access / Data Exfiltration** — accessing private paths, sending data externally
3. **Privilege Escalation** — accessing restricted systems, sensitive identifier extraction
4. **Malicious Scripts** — destructive commands, reverse shells, crypto miners
5. **Dependency Safety** — typosquatting, unofficial package sources
6. **Description Trigger Reasonability** — over-broad or mismatched triggers
7. **Frontmatter Compliance** — non-standard fields

## Project Structure

```
skill-security-guard/
├── SKILL.md                        # Main skill definition
├── scripts/
│   └── scan.sh                     # CLI entry point for zip/file scanning
├── references/
│   └── detection-rules.md          # Detailed detection patterns & scoring algorithm
└── README.md
```

## License

MIT
