#!/usr/bin/env python3
"""Static security scanner for OpenClaw/Codex-style skill packages."""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import shutil
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterable


VERSION = "5.1.0"
MAX_ZIP_BYTES = 10 * 1024 * 1024
MAX_ZIP_FILES = 500
URL_TIMEOUT_SECONDS = 10
URL_MAX_BYTES = 2 * 1024 * 1024
FILE_MARKER = re.compile(r"^### FILE: (.+)$")
EXCLUDED_DIRS = {
    ".git",
    ".github",
    ".mypy_cache",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
    "tests",
    "venv",
    ".venv",
}


class ScanError(Exception):
    """Raised when input cannot be safely scanned."""


@dataclasses.dataclass(frozen=True)
class Evidence:
    file: str
    line: int
    text: str


@dataclasses.dataclass(frozen=True)
class Issue:
    rule_id: str
    dimension: str
    severity: str
    confidence: str
    title: str
    evidence: Evidence
    suggestion: str
    penalty: int
    direct_fail: bool = False
    auto_fix: bool = False

    def to_dict(self) -> dict:
        data = dataclasses.asdict(self)
        return data


@dataclasses.dataclass(frozen=True)
class Target:
    name: str
    source: str
    content: str


@dataclasses.dataclass(frozen=True)
class Report:
    target: str
    rating: str
    score: int
    issues: list[Issue]
    passed_dimensions: list[str]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "rating": self.rating,
            "score": self.score,
            "issues": [issue.to_dict() for issue in self.issues],
            "passed_dimensions": self.passed_dimensions,
        }


DIMENSIONS = {
    "prompt-injection": "Prompt injection",
    "sensitive-data": "Sensitive file access / data exfiltration",
    "compliance": "Compliance violations",
    "malicious-script": "Malicious scripts",
    "dependency": "Dependency safety",
    "description": "Description trigger reasonability",
    "frontmatter": "Frontmatter compliance",
}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan skill packages for static security risks."
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Skill file, skill directory, .zip package, URL, '-' for stdin, or omitted with --text.",
    )
    parser.add_argument("--text", help="Inline skill text to scan.")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format. Defaults to text.",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="Ignore a rule for this run. Can be repeated.",
    )
    parser.add_argument(
        "--include-references",
        action="store_true",
        help="Include references/ markdown files in directory and zip scans.",
    )
    parser.add_argument(
        "--max-zip-bytes",
        type=int,
        default=MAX_ZIP_BYTES,
        help=f"Reject zip files larger than this many bytes. Default: {MAX_ZIP_BYTES}.",
    )
    parser.add_argument(
        "--max-zip-files",
        type=int,
        default=MAX_ZIP_FILES,
        help=f"Reject zip files with more entries than this. Default: {MAX_ZIP_FILES}.",
    )
    parser.add_argument("--version", action="version", version=VERSION)
    return parser.parse_args(argv)


def scan_source(
    source: str | None,
    *,
    text: str | None = None,
    ignored_rules: set[str] | None = None,
    include_references: bool = False,
    max_zip_bytes: int = MAX_ZIP_BYTES,
    max_zip_files: int = MAX_ZIP_FILES,
) -> list[Report]:
    ignored_rules = ignored_rules or set()
    targets = collect_targets(
        source,
        text=text,
        include_references=include_references,
        max_zip_bytes=max_zip_bytes,
        max_zip_files=max_zip_files,
    )
    return [scan_target(target, ignored_rules=ignored_rules) for target in targets]


def collect_targets(
    source: str | None,
    *,
    text: str | None = None,
    include_references: bool = False,
    max_zip_bytes: int = MAX_ZIP_BYTES,
    max_zip_files: int = MAX_ZIP_FILES,
) -> list[Target]:
    if text is not None:
        return [Target(name="<inline-text>", source="<inline-text>", content=text)]

    if not source:
        raise ScanError("missing input: provide a path, URL, '-' for stdin, or --text")

    if source == "-":
        return [Target(name="<stdin>", source="<stdin>", content=sys.stdin.read())]

    if is_url(source):
        return [
            Target(
                name=source,
                source=source,
                content=fetch_url(source),
            )
        ]

    path = Path(source).expanduser()
    if not path.exists():
        raise ScanError(f"input does not exist: {source}")
    path = path.resolve()

    if path.is_dir():
        return collect_directory_targets(path, include_references=include_references)

    if path.suffix.lower() == ".zip":
        return collect_zip_targets(
            path,
            include_references=include_references,
            max_zip_bytes=max_zip_bytes,
            max_zip_files=max_zip_files,
        )

    return [
        Target(
            name=path.name,
            source=str(path),
            content=read_text(path),
        )
    ]


def collect_directory_targets(path: Path, *, include_references: bool) -> list[Target]:
    skill_files = find_skill_files(path)
    if not skill_files:
        return [
            Target(
                name=path.name,
                source=str(path),
                content=read_directory_bundle(path, include_references=include_references),
            )
        ]

    return [
        Target(
            name=target_name(path, skill_file),
            source=str(skill_file.parent),
            content=read_skill_bundle(skill_file, include_references=include_references),
        )
        for skill_file in skill_files
    ]


def find_skill_files(path: Path) -> list[Path]:
    return sorted(
        skill_file
        for skill_file in path.rglob("SKILL.md")
        if not is_excluded_path(skill_file, path)
    )


def target_name(root: Path, skill_file: Path) -> str:
    relative = skill_file.parent.relative_to(root).as_posix()
    if relative in {"", "."}:
        return root.name
    return relative


def collect_zip_targets(
    path: Path,
    *,
    include_references: bool,
    max_zip_bytes: int,
    max_zip_files: int,
) -> list[Target]:
    if path.stat().st_size > max_zip_bytes:
        raise ScanError(f"zip is too large: {path.stat().st_size} bytes > {max_zip_bytes}")

    tempdir = Path(tempfile.mkdtemp(prefix="skill-scan-"))
    try:
        safe_extract_zip(path, tempdir, max_files=max_zip_files)
        targets = collect_directory_targets(tempdir, include_references=include_references)
        if not targets:
            raise ScanError("zip contains no scannable files")
        return [
            Target(
                name=f"{path.name}:{target.name}",
                source=f"{path}:{target.source}",
                content=target.content,
            )
            for target in targets
        ]
    finally:
        shutil.rmtree(tempdir, ignore_errors=True)


def safe_extract_zip(path: Path, destination: Path, *, max_files: int) -> None:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > max_files:
            raise ScanError(f"zip has too many entries: {len(infos)} > {max_files}")

        for info in infos:
            normalized = PurePosixPath(info.filename.replace("\\", "/"))
            if info.filename.endswith("/") or info.is_dir():
                continue
            if normalized.is_absolute() or ".." in normalized.parts:
                raise ScanError(f"unsafe zip entry path: {info.filename}")
            if info.file_size > MAX_ZIP_BYTES:
                raise ScanError(f"zip entry is too large: {info.filename}")

        archive.extractall(destination)


def read_directory_bundle(path: Path, *, include_references: bool) -> str:
    parts: list[str] = []
    for child in sorted(path.rglob("*")):
        if not child.is_file():
            continue
        if should_scan_file(child, path, include_references=include_references):
            parts.append(format_file_content(child.relative_to(path).as_posix(), read_text(child)))
    return "\n".join(parts)


def read_skill_bundle(skill_file: Path, *, include_references: bool) -> str:
    root = skill_file.parent
    parts = [format_file_content("SKILL.md", read_text(skill_file))]

    for subdir in ("scripts",):
        candidate = root / subdir
        if not candidate.exists():
            continue
        for child in sorted(candidate.rglob("*")):
            if child.is_file() and should_scan_file(child, root, include_references=include_references):
                parts.append(format_file_content(child.relative_to(root).as_posix(), read_text(child)))

    if include_references:
        references = root / "references"
        if references.exists():
            for child in sorted(references.rglob("*.md")):
                if child.is_file():
                    parts.append(format_file_content(child.relative_to(root).as_posix(), read_text(child)))

    return "\n".join(parts)


def should_scan_file(path: Path, root: Path, *, include_references: bool) -> bool:
    if is_excluded_path(path, root):
        return False
    rel = path.relative_to(root).as_posix()
    suffixes = {".md", ".sh", ".bash", ".py", ".js", ".ts", ".json", ".yaml", ".yml"}
    if path.suffix.lower() not in suffixes:
        return False
    if rel.startswith("references/") and not include_references:
        return False
    return True


def is_excluded_path(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return False
    return any(part in EXCLUDED_DIRS for part in parts)


def format_file_content(relative_path: str, content: str) -> str:
    return f"### FILE: {relative_path}\n{content.rstrip()}\n"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def is_url(value: str) -> bool:
    return value.startswith("https://") or value.startswith("http://")


def fetch_url(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": f"skill-security-guard/{VERSION}"},
    )
    with urllib.request.urlopen(request, timeout=URL_TIMEOUT_SECONDS) as response:
        content_type = response.headers.get("content-type", "")
        if "text" not in content_type and "json" not in content_type and "markdown" not in content_type:
            raise ScanError(f"URL does not look text-like: {content_type or 'unknown content type'}")
        data = response.read(URL_MAX_BYTES + 1)
    if len(data) > URL_MAX_BYTES:
        raise ScanError(f"URL response is too large: > {URL_MAX_BYTES} bytes")
    return data.decode("utf-8", errors="replace")


def scan_target(target: Target, *, ignored_rules: set[str]) -> Report:
    issues = detect_issues(target.content)
    issues = [issue for issue in issues if issue.rule_id not in ignored_rules]
    score, rating = calculate_score(issues)
    issue_dimensions = {issue.dimension for issue in issues}
    passed = [
        title
        for key, title in DIMENSIONS.items()
        if key not in issue_dimensions
    ]
    return Report(
        target=target.name,
        rating=rating,
        score=score,
        issues=issues,
        passed_dimensions=passed,
    )


def detect_issues(content: str) -> list[Issue]:
    issues: list[Issue] = []
    seen: set[str] = set()

    def add(issue: Issue) -> None:
        key = f"{issue.rule_id}:{issue.evidence.file}:{issue.evidence.line}"
        if key not in seen:
            seen.add(key)
            issues.append(issue)

    primary_skill = extract_primary_skill_text(content)
    frontmatter = parse_frontmatter(primary_skill)
    description = clean_yaml_scalar(frontmatter.get("description", ""))

    detect_frontmatter(primary_skill, frontmatter, add)
    detect_description(description, add)
    detect_line_rules(content, add)

    return sorted(
        issues,
        key=lambda issue: (
            0 if issue.direct_fail else 1,
            severity_order(issue.severity),
            issue.rule_id,
            issue.evidence.file,
            issue.evidence.line,
        ),
    )


def detect_frontmatter(primary_skill: str, frontmatter: dict[str, str], add) -> None:
    evidence = Evidence("SKILL.md", 1, "---")
    if not primary_skill.lstrip().startswith("---"):
        add(
            Issue(
                rule_id="F7-MISSING-FRONTMATTER",
                dimension="frontmatter",
                severity="medium",
                confidence="confirmed",
                title="SKILL.md is missing YAML frontmatter",
                evidence=evidence,
                suggestion="Add standard frontmatter with name and description.",
                penalty=30,
            )
        )
        return

    allowed = {"name", "description"}
    extra = sorted(set(frontmatter) - allowed)
    if extra:
        add(
            Issue(
                rule_id="F7-NONSTANDARD-FIELDS",
                dimension="frontmatter",
                severity="low",
                confidence="advisory",
                title=f"Non-standard frontmatter fields: {', '.join(extra)}",
                evidence=evidence,
                suggestion="Keep only name and description unless your runtime explicitly supports extra fields.",
                penalty=5,
                auto_fix=True,
            )
        )

    for required in ("name", "description"):
        if not frontmatter.get(required, "").strip():
            add(
                Issue(
                    rule_id=f"F7-MISSING-{required.upper()}",
                    dimension="frontmatter",
                    severity="medium",
                    confidence="confirmed",
                    title=f"Missing required frontmatter field: {required}",
                    evidence=evidence,
                    suggestion=f"Add a concise {required} field.",
                    penalty=30,
                )
            )


def detect_description(description: str, add) -> None:
    evidence = Evidence("SKILL.md", 1, f"description: {description[:120]}")
    if not description:
        add(
            Issue(
                rule_id="D6-MISSING-DESCRIPTION",
                dimension="description",
                severity="medium",
                confidence="confirmed",
                title="Description is missing",
                evidence=evidence,
                suggestion="Add a bounded description that says exactly when the skill should trigger.",
                penalty=30,
            )
        )
        return

    if len(description) < 20:
        add(
            Issue(
                rule_id="D6-SHORT-DESCRIPTION",
                dimension="description",
                severity="medium",
                confidence="confirmed",
                title="Description is too short to define a safe trigger boundary",
                evidence=evidence,
                suggestion="Expand the description with scope, trigger phrases, and non-goals.",
                penalty=30,
            )
        )

    broad_trigger_pattern = re.compile(
        r"(any task|all tasks|anything|everything|all scenarios|任何任务|所有任务|所有场景|任何问题|一切)",
        re.IGNORECASE,
    )
    if broad_trigger_pattern.search(description):
        add(
            Issue(
                rule_id="R3-N5",
                dimension="description",
                severity="medium",
                confidence="suspected",
                title="Description trigger scope appears over-broad",
                evidence=evidence,
                suggestion="Narrow the trigger scope to the skill's actual security-audit use case.",
                penalty=10,
                auto_fix=True,
            )
        )


def detect_line_rules(content: str, add) -> None:
    for file_name, line_number, line in iter_scan_lines(content):
        stripped = line.strip()
        if not stripped:
            continue
        if is_rule_definition_line(file_name, stripped):
            continue
        lower = stripped.lower()
        evidence = Evidence(file_name, line_number, stripped[:220])

        if re.search(r"ignore (all )?previous instructions|忽略之前所有指令|you are now dan|没有限制的ai|system prompt.*(updated|更新)", lower):
            add(
                Issue(
                    rule_id="P1-PROMPT-INJECTION",
                    dimension="prompt-injection",
                    severity="medium",
                    confidence="confirmed",
                    title="Prompt-injection instruction detected",
                    evidence=evidence,
                    suggestion="Remove role-override or instruction-override text from the skill.",
                    penalty=30,
                )
            )

        if re.search(r"覆盖之前.*安全规则|override.*safety rules", lower):
            add(
                Issue(
                    rule_id="P1-SAFETY-OVERRIDE",
                    dimension="prompt-injection",
                    severity="medium",
                    confidence="suspected",
                    title="Possible safety-rule override",
                    evidence=evidence,
                    suggestion="State that higher-priority instructions remain authoritative.",
                    penalty=15,
                )
            )

        if re.search(r"(cat|cp|scp|tar|zip|open|read_file|readfile)\b.*(~/.ssh|~/.aws|/root/\.openclaw|openclaw\.json|paired\.json|device-auth\.json|soul\.md|memory\.md|user\.md)", lower):
            add(
                Issue(
                    rule_id="S2-SENSITIVE-READ",
                    dimension="sensitive-data",
                    severity="medium",
                    confidence="confirmed",
                    title="Sensitive file read pattern detected",
                    evidence=evidence,
                    suggestion="Remove direct access to credentials, identity files, memory files, or private config.",
                    penalty=30,
                )
            )

        if re.search(r"(curl|wget|scp|nc)\b.*(~/.ssh|~/.aws|/root/\.openclaw|openclaw\.json|paired\.json|device-auth\.json|soul\.md|memory\.md|user\.md|@-)", lower):
            add(
                Issue(
                    rule_id="S2-EXFILTRATION",
                    dimension="sensitive-data",
                    severity="high",
                    confidence="confirmed",
                    title="Sensitive data exfiltration pattern detected",
                    evidence=evidence,
                    suggestion="Do not send local secrets, identity files, or private memory files to remote hosts.",
                    penalty=100,
                    direct_fail=True,
                )
            )

        if re.search(r"\b(ngrok|localtunnel|cloudflared\s+tunnel|bore|frpc?|frps)\b", lower):
            add(
                Issue(
                    rule_id="R3-N1",
                    dimension="compliance",
                    severity="high",
                    confidence="confirmed",
                    title="Tunneling tool usage detected",
                    evidence=evidence,
                    suggestion="Remove tunneling tools unless a reviewer has explicitly approved them.",
                    penalty=100,
                    direct_fail=True,
                )
            )

        if re.search(r"(hr|okr|performance|绩效|人才|人事).*(internal|corp|内网|内部|系统)", lower):
            add(
                Issue(
                    rule_id="R3-N2",
                    dimension="compliance",
                    severity="high",
                    confidence="confirmed",
                    title="Restricted HR/OKR system access detected",
                    evidence=evidence,
                    suggestion="Remove access to restricted organizational systems.",
                    penalty=100,
                    direct_fail=True,
                )
            )

        if re.search(r"(c4|绝密|内部高密).*(input|upload|paste|输入|上传|粘贴|处理)", lower):
            add(
                Issue(
                    rule_id="R3-N3",
                    dimension="compliance",
                    severity="high",
                    confidence="suspected",
                    title="High-sensitivity data handling detected",
                    evidence=evidence,
                    suggestion="State that the skill must not process highly sensitive data.",
                    penalty=100,
                    direct_fail=True,
                )
            )

        if re.search(r"(cp|tar|zip|upload|curl|备份|上传).*(openclaw\.json|device\.json|device-auth\.json)", lower):
            add(
                Issue(
                    rule_id="R3-N4",
                    dimension="compliance",
                    severity="high",
                    confidence="confirmed",
                    title="Sensitive config backup or upload pattern detected",
                    evidence=evidence,
                    suggestion="Do not back up, upload, or duplicate sensitive device/auth config.",
                    penalty=100,
                    direct_fail=True,
                )
            )

        if re.search(r"rm\s+-rf\s+/(?:\s|$)|rm\s+-rf\s+~|dd\s+if=/dev/zero", lower):
            add(
                Issue(
                    rule_id="M4-DESTRUCTIVE-COMMAND",
                    dimension="malicious-script",
                    severity="high",
                    confidence="confirmed",
                    title="Destructive command detected",
                    evidence=evidence,
                    suggestion="Remove destructive shell commands.",
                    penalty=100,
                    direct_fail=True,
                )
            )

        if re.search(r"(curl|wget)\b.*\|\s*(bash|sh)\b", lower):
            add(
                Issue(
                    rule_id="M4-REMOTE-SCRIPT-EXEC",
                    dimension="malicious-script",
                    severity="high",
                    confidence="confirmed",
                    title="Remote script execution detected",
                    evidence=evidence,
                    suggestion="Download artifacts separately, verify integrity, and avoid piping remote code to a shell.",
                    penalty=100,
                    direct_fail=True,
                )
            )

        if re.search(r"bash\s+-i.*(/dev/tcp|>&)|nc\s+-e\s+(/bin/)?(bash|sh)", lower):
            add(
                Issue(
                    rule_id="M4-REVERSE-SHELL",
                    dimension="malicious-script",
                    severity="high",
                    confidence="confirmed",
                    title="Reverse shell pattern detected",
                    evidence=evidence,
                    suggestion="Remove reverse shell behavior.",
                    penalty=100,
                    direct_fail=True,
                )
            )

        if re.search(r"sudo\s+su\b|chmod\s+777\s+/etc|xmrig|minerd|\.mining", lower):
            add(
                Issue(
                    rule_id="M4-PRIVILEGED-OR-MINING",
                    dimension="malicious-script",
                    severity="high",
                    confidence="confirmed",
                    title="Privileged shell or mining behavior detected",
                    evidence=evidence,
                    suggestion="Remove privilege escalation or mining behavior.",
                    penalty=100,
                    direct_fail=True,
                )
            )

        if re.search(r"\beval\b|\bexec\(", lower):
            add(
                Issue(
                    rule_id="M4-DYNAMIC-EXECUTION",
                    dimension="malicious-script",
                    severity="medium",
                    confidence="suspected",
                    title="Dynamic code execution detected",
                    evidence=evidence,
                    suggestion="Avoid dynamic code execution, or document why it is necessary and constrained.",
                    penalty=15,
                )
            )

        if re.search(r"\bpip\s+install\b.*(--index-url|--extra-index-url|https?://|git\+)", lower):
            add(
                Issue(
                    rule_id="D5-PIP-UNTRUSTED-SOURCE",
                    dimension="dependency",
                    severity="low",
                    confidence="advisory",
                    title="pip install uses a non-default source",
                    evidence=evidence,
                    suggestion="Pin dependencies and prefer the default package index unless a trusted mirror is required.",
                    penalty=5,
                )
            )

        if re.search(r"\bnpm\s+install\b.*(https?://|git\+|--registry)", lower):
            add(
                Issue(
                    rule_id="D5-NPM-UNTRUSTED-SOURCE",
                    dimension="dependency",
                    severity="low",
                    confidence="advisory",
                    title="npm install uses a non-default source",
                    evidence=evidence,
                    suggestion="Pin dependencies and prefer the default npm registry unless a trusted mirror is required.",
                    penalty=5,
                )
            )

        if re.search(r"\b(requets|reqeusts|lodahs|expres)\b", lower):
            add(
                Issue(
                    rule_id="D5-TYPOSQUATTING",
                    dimension="dependency",
                    severity="low",
                    confidence="advisory",
                    title="Possible typosquatted dependency name",
                    evidence=evidence,
                    suggestion="Check dependency names against the intended package before installation.",
                    penalty=5,
                )
            )


def is_rule_definition_line(file_name: str, line: str) -> bool:
    suffix = Path(file_name).suffix.lower()
    if suffix not in {".py", ".js", ".ts"}:
        return False
    return "re.search(" in line or "re.compile(" in line


def parse_frontmatter(text: str) -> dict[str, str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}

    values: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        match = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if match:
            values[match.group(1).strip().lower()] = match.group(2).strip()
    return values


def clean_yaml_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    return value.strip()


def extract_primary_skill_text(content: str) -> str:
    if "### FILE: " not in content:
        return content

    lines = content.splitlines()
    capture = False
    selected: list[str] = []
    for line in lines:
        marker = FILE_MARKER.match(line)
        if marker:
            capture = marker.group(1).replace("\\", "/").endswith("SKILL.md")
            if selected and capture:
                break
            continue
        if capture:
            selected.append(line)
    return "\n".join(selected) if selected else content


def iter_scan_lines(content: str) -> Iterable[tuple[str, int, str]]:
    current_file = "<input>"
    current_line = 0
    for raw_line in content.splitlines():
        marker = FILE_MARKER.match(raw_line)
        if marker:
            current_file = marker.group(1)
            current_line = 0
            continue
        current_line += 1
        yield current_file, current_line, raw_line


def severity_order(severity: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(severity, 3)


def calculate_score(issues: list[Issue]) -> tuple[int, str]:
    if any(issue.direct_fail for issue in issues):
        return 0, "F"

    score = 100
    confirmed_medium_count = 0
    advisory_penalty = 0
    for issue in issues:
        if issue.confidence == "advisory":
            advisory_penalty += issue.penalty
            continue
        score -= issue.penalty
        if issue.severity == "medium" and issue.confidence == "confirmed":
            confirmed_medium_count += 1

    score = max(0, score - min(advisory_penalty, 10))
    if confirmed_medium_count >= 2:
        score = min(score, 69)

    if score == 100:
        return score, "A"
    if score >= 85:
        return score, "B"
    if score >= 70:
        return score, "C"
    if score >= 50:
        return score, "D"
    return score, "F"


def render_text(reports: list[Report]) -> str:
    chunks: list[str] = []
    for report in reports:
        chunks.append(f"Skill Security Report: {report.target}")
        chunks.append(f"Rating: {report.rating} ({report.score}/100)")
        chunks.append("")
        if report.issues:
            chunks.append(f"Issues ({len(report.issues)}):")
            for issue in report.issues:
                chunks.append(
                    f"- [{issue.severity}/{issue.confidence}] {issue.rule_id}: {issue.title}"
                )
                chunks.append(
                    f"  evidence: {issue.evidence.file}:{issue.evidence.line}: {issue.evidence.text}"
                )
                chunks.append(f"  fix: {issue.suggestion}")
        else:
            chunks.append("Issues: none")
        chunks.append("")
        chunks.append("Passed dimensions:")
        for dimension in report.passed_dimensions:
            chunks.append(f"- {dimension}")
        chunks.append("")
    return "\n".join(chunks).rstrip()


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        reports = scan_source(
            args.input,
            text=args.text,
            ignored_rules=set(args.ignore),
            include_references=args.include_references,
            max_zip_bytes=args.max_zip_bytes,
            max_zip_files=args.max_zip_files,
        )
    except (OSError, zipfile.BadZipFile, urllib.error.URLError, ScanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps([report.to_dict() for report in reports], indent=2, ensure_ascii=False))
    else:
        print(render_text(reports))

    return 1 if any(report.rating in {"D", "F"} for report in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())
