# Detection Rules

This document describes the rule intent used by `scripts/scan.py`. The scanner is intentionally conservative: high-confidence direct-danger patterns return `F`, while ambiguous patterns are reported with lower confidence for human review.

## Dimension 1: Prompt Injection

Confirmed medium risk:

- Instructions to ignore previous instructions
- Role overrides such as unrestricted assistant personas
- Claims that the system prompt or safety policy has been replaced

Suspected medium risk:

- Requests to override safety rules
- Descriptions that trigger for unrelated broad scenarios

## Dimension 2: Sensitive File Access / Data Exfiltration

Confirmed high risk, direct `F`:

- Sending local secrets, identity files, private memory files, or credential directories to a remote host
- Network commands that include local sensitive files as request data

Confirmed medium risk:

- Reading sensitive config, credential, identity, or memory files without clear need

## Dimension 3: Compliance Violations

Confirmed or suspected high risk, direct `F`:

- `R3-N1`: tunneling tools or tunnel setup
- `R3-N2`: access to restricted organizational systems
- `R3-N3`: handling highly sensitive classified data
- `R3-N4`: backup, upload, or duplication of sensitive auth/device config

Suspected medium risk:

- `R3-N5`: description trigger scope is too broad for the skill purpose

## Dimension 4: Malicious Scripts

Confirmed high risk, direct `F`:

- Destructive filesystem commands
- Remote script execution via shell pipelines
- Reverse shell patterns
- Privilege escalation or mining behavior

Suspected medium risk:

- Dynamic execution through `eval` or unconstrained `exec`

## Dimension 5: Dependency Safety

Advisory:

- `pip install` from non-default index, URL, or Git source
- `npm install` from non-default registry, URL, or Git source
- Package names that look like common typosquatting variants

## Dimension 6: Description Trigger Reasonability

Confirmed medium risk:

- Missing description
- Description too short to define a safe trigger boundary

Suspected medium risk:

- Description says the skill applies to every task, every question, or all scenarios

## Dimension 7: Frontmatter Compliance

Confirmed medium risk:

- Missing YAML frontmatter
- Missing `name`
- Missing `description`

Advisory:

- Non-standard fields outside `name` and `description`

## Scoring

| Finding type | Score behavior |
| --- | --- |
| Direct high-risk finding | Rating `F`, score `0` |
| Confirmed medium risk | `-30` per issue |
| Two or more confirmed medium-risk issues | Rating capped at `D` |
| Suspected medium risk | `-15` per issue, except `R3-N5` uses `-10` |
| Advisory | `-5` per issue, capped at `-10` total advisory penalty |

## Ratings

| Score | Rating | Meaning |
| --- | --- | --- |
| 100 | A | No findings |
| 85-99 | B | Light or advisory findings |
| 70-84 | C | Risk requires review or repair |
| 50-69 | D | Serious risk; fix before install |
| <50 or direct high-risk | F | Do not install directly |

## Fix Guidance

Safe to suggest as auto-fixable:

- Remove non-standard frontmatter fields
- Narrow over-broad description trigger text
- Add comments explaining necessary low-risk network/dependency behavior

Manual review required:

- Any direct high-risk finding
- Ambiguous prompt-injection intent
- Organization-specific compliance decisions
- Any finding where changing behavior could alter the skill's purpose
