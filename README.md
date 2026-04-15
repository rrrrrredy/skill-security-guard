# skill-security-guard

Skill code security scanner — 7-dimension analysis with A-F rating and fix suggestions.

> OpenClaw Skill — works with [OpenClaw](https://github.com/openclaw/openclaw) AI agents

## What It Does

Scans OpenClaw skill code for security risks across 7 dimensions: prompt injection, sensitive file access, privilege escalation, malicious scripts, dependency safety, description trigger reasonableness, and frontmatter compliance. Outputs a structured report with A-F security rating, per-issue confidence levels (confirmed / suspected / advisory), and actionable fix suggestions. Supports `.zip`, `.md`, plain text, code blocks, and batch scanning.

## Quick Start

```bash
openclaw skill install skill-security-guard
# Or:
git clone https://github.com/rrrrrredy/skill-security-guard.git ~/.openclaw/skills/skill-security-guard
```

## Features

- **7-dimension security scan**: Prompt injection, sensitive file reads, privilege escalation (Meituan red lines), malicious scripts, dependency safety, description triggers, frontmatter compliance
- **A-F security rating**: Quantified scoring with per-issue confidence levels
- **Batch scanning**: Upload a zip with multiple skills, get individual + summary reports
- **Auto-fix**: Reply "修复" to auto-fix safe issues (non-standard frontmatter, missing comments)
- **Whitelist mechanism**: Mark known-acceptable risks to exclude from scoring (session-scoped)
- **Multiple input formats**: `.zip`, `.md`, plain text, code blocks, Friday platform links

## Usage

**Trigger phrases:**
- `安全检查`, `Skill 安全`, `安全扫描` — run a security scan
- `检查 Skill`, `审查 skill`, `skill 审计` — audit a skill
- `装之前检查` — pre-install security review

**Example output:**
```
🛡️ Skill 安全报告：my-skill

📊 安全评级：B（85分）— 较安全，有轻微问题

🚨 风险项（共 2 项）：
1. [中危·确定] non-standard frontmatter fields
2. [低危·疑似] unexplained external request in scripts/

✅ 通过项（5 项）：...
```

## Project Structure

```
skill-security-guard/
├── SKILL.md                        # Main skill documentation
├── scripts/
│   └── scan.sh                     # Zip extraction & SKILL.md enumeration entry point
└── references/
    └── detection-rules.md          # Detection patterns, keywords & scoring algorithm
```

## Requirements

- OpenClaw agent runtime
- `unzip` or Python 3 (for zip extraction fallback)

## License

[MIT](LICENSE)
