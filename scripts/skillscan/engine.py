"""Apply rules to real file boundaries and score each skill independently."""
from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
import re

from .inputs import collect_targets
from .model import DIMENSIONS, MAX_LINE, Document, Evidence, Issue, Report, Target
from .python_rules import python_rules
from .rules import RULES
from .text_rules import ENCODING, SHELL_SINK, UPLOAD, hidden_comment, line_rules, parse_frontmatter, unicode_rules

FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
BROAD = re.compile(r"any task|all tasks|anything|everything|all scenarios|任何任务|所有任务|所有场景|任何问题|一切", re.I)


def physical_lines(doc: Document) -> list[str]:
    return doc.text.splitlines()


def metadata(target: Target):
    doc = next((doc for doc in target.files if doc.path == "SKILL.md"), None)
    if doc is None:
        doc = target.files[0] if len(target.files) == 1 else Document("SKILL.md", "")
    text = "\n".join(line[:MAX_LINE] for line in physical_lines(doc))
    return doc, text, parse_frontmatter(text)


def frontmatter_rules(text, fields):
    if not text.lstrip("\ufeff \r\n\t").startswith("---"):
        yield "F7-MISSING-FRONTMATTER"
    else:
        if set(fields) - {"name", "description"}:
            yield "F7-NONSTANDARD-FIELDS"
        if not fields.get("name"):
            yield "F7-MISSING-NAME"
        if not fields.get("description"):
            yield "F7-MISSING-DESCRIPTION"
    description = fields.get("description", "")
    if not description:
        yield "D6-MISSING-DESCRIPTION"
    elif len(description) < 20:
        yield "D6-SHORT-DESCRIPTION"
    if BROAD.search(description):
        yield "R3-N5"


def scan_document(doc: Document, record) -> None:
    source = physical_lines(doc)
    lines = [line[:MAX_LINE] for line in source]
    path = PurePosixPath(doc.path)
    is_python = path.suffix.lower() == ".py"
    is_markdown = path.suffix.lower() == ".md"
    shell = path.suffix.lower() in {".sh", ".bash", ".ps1"}
    example_file = bool({"tests", "references"}.intersection(path.parts[:-1]))
    fence = ""
    comment = False
    stages = {}

    def emit(rule, number, example=False):
        number = max(1, number)
        text = lines[number - 1].strip()[:220] if number <= len(lines) else ""
        record(rule, Evidence(doc.path, number, text), example_file or example)

    for number, line in enumerate(lines, 1):
        match = FENCE.match(line) if is_markdown else None
        example = bool(fence)
        if match:
            marker, info = match.groups()
            if not fence and (marker[0] != "`" or "`" not in info):
                fence = marker
                example = True
            elif fence and marker.startswith(fence) and not info.strip():
                fence = ""
        if len(source[number - 1]) > MAX_LINE:
            emit("M4-LINE-LIMIT", number, example)
        for rule in unicode_rules(line):
            emit(rule, number, example)
        if is_python:
            continue
        if path.name == "SKILL.md":
            comment, instruction = hidden_comment(line, comment)
            if instruction:
                emit("P1-HIDDEN-INSTRUCTION", number, example)
        if shell and line.lstrip().startswith("#"):
            continue
        rules = line_rules(line)
        for rule in rules:
            emit(rule, number, example)
        if shell and not example_file:
            if "S2-SENSITIVE-READ" in rules:
                stages.setdefault("source", number)
            if ENCODING.search(line):
                stages.setdefault("encoding", number)
            if UPLOAD.search(line) or SHELL_SINK.search(line):
                stages.setdefault("sink", number)
    if is_python:
        python_rules(lines, emit)
    elif stages.keys() >= {"source", "encoding", "sink"}:
        emit("S2-SENSITIVE-CHAIN", max(stages.values()))


def calculate_score(issues: list[Issue]) -> tuple[int, str]:
    if any(issue.direct_fail for issue in issues):
        return 0, "F"
    # Count the strongest instance of each class across this package.
    penalties = {}
    advisory = {}
    for issue in issues:
        if issue.confidence == "advisory":
            advisory[issue.rule_id] = max(advisory.get(issue.rule_id, 0), issue.penalty)
        else:
            penalties[issue.rule_id] = max(penalties.get(issue.rule_id, 0), issue.penalty)
    score = max(0, 100 - sum(penalties.values()) -
                min(10, sum(cost for rule, cost in advisory.items() if rule not in penalties)))
    if score == 100:
        return score, "A"
    if score >= 85:
        return score, "B"
    if score >= 70:
        return score, "C"
    return score, "D" if score >= 50 else "F"


def scan_target(target: Target, *, ignored_rules: set[str]) -> Report:
    found = {}

    def record(rule_id, evidence, example=False):
        if rule_id in ignored_rules:
            return
        rule = RULES[rule_id]
        if example and rule_id == "S2-SENSITIVE-CHAIN":
            return
        found[rule_id, evidence.file, evidence.line] = Issue(
            rule_id, rule.dimension, "low" if example else rule.severity,
            "advisory" if example else rule.confidence, rule.title, evidence, rule.suggestion,
            2 if example else rule.penalty, rule.direct_fail and not example, rule.auto_fix,
        )

    doc, text, fields = metadata(target)
    first = text.split("\n", 1)[0]
    for rule in frontmatter_rules(text, fields):
        record(rule, Evidence(doc.path, 1, first[:220]))
    for doc in target.files:
        scan_document(doc, record)
    issues = sorted(found.values(), key=lambda i: (
        not i.direct_fail, ("high", "medium", "low").index(i.severity),
        i.rule_id, i.evidence.file, i.evidence.line,
    ))
    score, rating = calculate_score(issues)
    dimensions = {issue.dimension for issue in issues}
    return Report(target.name, "sha256:" + hashlib.sha256(target.content.encode("utf-8")).hexdigest(),
                  rating, score, issues, [title for key, title in DIMENSIONS.items() if key not in dimensions],
                  sorted(ignored_rules))


def scan_source(source, *, ignored_rules=None, **options) -> list[Report]:
    return [scan_target(target, ignored_rules=ignored_rules or set()) for target in collect_targets(source, **options)]
