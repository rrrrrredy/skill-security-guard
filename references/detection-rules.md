# Detection rules

The scanner uses the file path, physical line number and rule ID to identify a finding. Python calls are inspected using the standard-library AST. Other supported sources use bounded text rules.

| Rule ID | What produces a finding |
| --- | --- |
| `P1-PROMPT-INJECTION` | Instruction or role overrides in skill text |
| `P1-SAFETY-OVERRIDE` | Requests to override safety rules |
| `P1-ZERO-WIDTH` | Zero-width formatting characters or soft hyphens |
| `P1-BIDI-CONTROL` | Explicit Unicode direction marks, embedding, override or isolate controls |
| `P1-HIDDEN-INSTRUCTION` | Instruction-like content inside an HTML comment in `SKILL.md`, including multiline comments |
| `S2-SENSITIVE-READ` | Reads of credential directories, identity and memory files, or named credential environment variables |
| `S2-EXFILTRATION` | A network transfer command with a sensitive file operand |
| `S2-NETWORK-SINK` | Python HTTP requests with an outbound body, known HTTP write methods, or socket/mail/file-transfer send calls |
| `S2-SENSITIVE-CHAIN` | A sensitive read, encoding operation and network or execution sink in one production shell script or one Python lexical scope |
| `R3-N1` | Use of a tunneling tool |
| `R3-N2` | Access to restricted HR or performance systems |
| `R3-N3` | Handling highly classified data |
| `R3-N4` | Backing up or uploading private device or authentication config |
| `R3-N5` | An overly broad description trigger |
| `M4-DESTRUCTIVE-COMMAND` | Destructive filesystem commands |
| `M4-REMOTE-SCRIPT-EXEC` | Piping a remote download into a shell |
| `M4-REVERSE-SHELL` | Recognized reverse-shell commands |
| `M4-PRIVILEGED-OR-MINING` | Privileged shell or mining behavior |
| `M4-DYNAMIC-EXECUTION` | Dynamic evaluation, shell-backed Python process calls, or explicit command interpreters |
| `M4-HOST-CONFIG-WRITE` | A write targeting `.mcp.json`, `CLAUDE.md`, `AGENTS.md`, `.claude/`, `.codex/`, `.cursor/`, Git hooks or a hooks-path setting |
| `M4-LINE-LIMIT` | A physical line exceeds 4,096 characters. Rules analyze its prefix and continue at the next line |
| `M4-PYTHON-PARSE` | Syntax, encoding artifacts or excessive nesting prevented complete AST inspection |
| `D5-PIP-UNTRUSTED-SOURCE` | pip installs from a URL, Git or non-default index |
| `D5-NPM-UNTRUSTED-SOURCE` | npm installs from a URL, Git or non-default registry |
| `D5-TYPOSQUATTING` | Known misspellings of common dependency names |
| `D5-UNPINNED-RUNNER` | `npx -y`, `npx --yes`, `uvx` or `pipx run` resolves a package without an exact version |
| `D6-MISSING-DESCRIPTION` | Missing trigger description |
| `D6-SHORT-DESCRIPTION` | Trigger description shorter than 20 characters |
| `F7-MISSING-FRONTMATTER` | Missing YAML frontmatter |
| `F7-MISSING-NAME` | Frontmatter omits a name |
| `F7-MISSING-DESCRIPTION` | Frontmatter omits a description |
| `F7-NONSTANDARD-FIELDS` | Frontmatter contains additional fields |

## Scoring and evidence

A direct high finding sets the score to zero. Confirmed medium findings cost 30 points, probable medium findings cost 15, and the broad description trigger costs 10. Each rule contributes its strongest penalty once per package. Advisories cost 5 points each with a combined ceiling of 10. Fenced Markdown examples, files under `tests/` and included reference documents retain their evidence at 2 advisory points per rule. Every distinct hit remains visible.

A score of 100 is A, 85–99 is B, 70–84 is C, 50–69 is D, and 0–49 is F. Two occurrences of one pattern share its cap. Independent confirmed medium findings can drive the score below 50.

The chain rule reports co-occurrence and carries `probable` confidence. It groups Python calls by file and lexical scope, and shell operations by script. Examples, tests and references cannot complete a production chain. An isolated outbound call earns an advisory. Ignoring one component hides that finding; a reviewer can separately ignore the chain ID. Static co-occurrence does not establish runtime data flow.

The Python pass resolves common module, function and assignment aliases and recognizes literal path operations. Comments and docstrings do not produce call findings. A parse diagnostic records files that could not be analyzed. Unicode checks inspect the source characters themselves.

## Report binding and disclosure

Default JSON remains an array of `skill-security-scan.v1` reports. `input_sha256` binds the UTF-8 scan input. Stdin preserves the exact UTF-8 text, including line endings. Directory inputs retain the v1 file-marker serialization. Each report records the scanner version and the sorted per-run ignore list.

Census records also hash relative paths and raw file bytes. Their intent fields contain the declared name and description. Evidence windows contain the matching physical line and up to three lines on either side, within the same file. The census renderer masks common credential assignments, authorization headers, recognizable access tokens and private-key blocks, and removes URL, email and home-directory identifiers from excerpts. Redaction is pattern-based. See the README for the hash format, package boundaries and CLI exit codes.
