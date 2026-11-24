"""Data shared by the file protocol, scanner and census renderer."""
from __future__ import annotations

from dataclasses import asdict, dataclass

VERSION = "5.3.0"
REPORT_SCHEMA_VERSION = "skill-security-scan.v1"
CENSUS_SCHEMA_VERSION = "skill-security-scan.v2-census"
MAX_LINE = 4096

DIMENSIONS = {
    "prompt-injection": "Prompt injection",
    "sensitive-data": "Sensitive file access / data exfiltration",
    "compliance": "Compliance violations",
    "malicious-script": "Malicious scripts",
    "dependency": "Dependency safety",
    "description": "Description trigger reasonability",
    "frontmatter": "Frontmatter compliance",
}


class ScanError(Exception):
    """Input cannot be safely scanned."""


@dataclass(frozen=True)
class Document:
    path: str
    text: str


@dataclass(frozen=True)
class Target:
    name: str
    source: str
    files: tuple[Document, ...]
    tree_hash: str | None
    bundled: bool = False

    @property
    def content(self) -> str:
        # v1 hashes this exact UTF-8 protocol representation.
        if not self.bundled:
            return self.files[0].text
        return "\n".join(f"### FILE: {doc.path}\n{doc.text.rstrip()}\n" for doc in self.files)


@dataclass(frozen=True)
class Evidence:
    file: str
    line: int
    text: str


@dataclass(frozen=True)
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
        return asdict(self)


@dataclass(frozen=True)
class Report:
    target: str
    input_sha256: str
    rating: str
    score: int
    issues: list[Issue]
    passed_dimensions: list[str]
    ignored_rules: list[str]
    complete: bool = True

    def to_dict(self) -> dict:
        return {
            "schema_version": REPORT_SCHEMA_VERSION, "scanner_version": VERSION,
            **asdict(self),
        }
