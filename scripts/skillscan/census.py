"""Portable, redacted census records and ordered, bounded batch execution."""
from __future__ import annotations

from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import unicodedata

from .archives import ARCHIVE_SUFFIXES
from .engine import metadata, physical_lines, scan_target
from .inputs import EXCLUDED, collect_targets
from .model import CENSUS_SCHEMA_VERSION, MAX_LINE, VERSION, ScanError

PRIVATE_KEY = re.compile(r"-----BEGIN [\w ]*PRIVATE KEY-----")
END_KEY = re.compile(r"-----END [\w ]*PRIVATE KEY-----")
CREDENTIAL_LINE = re.compile(
    r"""(?:authorization|cookie|password|passwd|secret|api[-_]?key|token|access[-_]?key|private[-_]?key)
        [\w.-]*['"]?\s*(?:[:=]|\s+['"]?\S)|\b(?:bearer|basic)\s+[a-z0-9+/=_-]+
        |(?:sk-(?:proj-)?|gh[pousr]_|github_pat_|AKIA|ASIA)[a-z0-9_-]{8,}
        |\beyJ[\w-]+\.[\w-]+\.[\w-]+""", re.I | re.X)
URL = re.compile(r"(?:https?|ssh|ftp)://[^\s'\"<>]+", re.I)
EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
HOME = re.compile(r"(/(?:home|Users)/|[a-z]:[\\/]Users[\\/])[^/\\\s\"']+", re.I)


def redact(line: str) -> str:
    if len(line) > MAX_LINE:
        return "[long line omitted]"
    if CREDENTIAL_LINE.search(line) or PRIVATE_KEY.search(line):
        return "[redacted]"
    line = EMAIL.sub("[email]", URL.sub("[url]", line))
    line = HOME.sub(lambda m: m[1] + "[user]", line)
    return "".join(f"\\u{ord(c):04x}" if unicodedata.category(c) in {"Cf", "Cc", "Cs"} and c != "\t" else c
                   for c in line)[:320]


def redacted_lines(doc) -> list[str]:
    result = []
    pem = False
    secret_indent = None
    for line in physical_lines(doc):
        prefix = line[:MAX_LINE]
        if PRIVATE_KEY.search(prefix):
            pem = True
        indent = len(line) - len(line.lstrip())
        if secret_indent is not None and line.strip() and indent <= secret_indent:
            secret_indent = None
        value = redact(line)
        if value == "[redacted]" and re.search(r":\s*[|>][-+]?\s*$", prefix):
            secret_indent = indent
        result.append("[redacted]" if pem or secret_indent is not None else value)
        if END_KEY.search(prefix):
            pem = False
    return result


def census_record(target, ignored, source):
    report = scan_target(target, ignored_rules=ignored).to_dict()
    _, _, fields = metadata(target)
    report.update(schema_version=CENSUS_SCHEMA_VERSION, source=source,
                  canonical_tree_sha256=target.tree_hash,
                  declared_intent={key: redact(fields.get(key, "")) for key in ("name", "description")})
    needed = {issue["evidence"]["file"] for issue in report["issues"]}
    safe = {doc.path: redacted_lines(doc) for doc in target.files if doc.path in needed}
    for issue in report["issues"]:
        evidence = issue["evidence"]
        lines = safe.get(evidence["file"], [])
        index = evidence["line"] - 1
        evidence["text"] = lines[index] if index < len(lines) else ""
        issue["context"] = [{"line": i + 1, "text": lines[i]}
                            for i in range(max(0, index - 3), min(len(lines), index + 4))]
    return report


def batch_sources(root: Path):
    if not root.is_dir():
        raise ScanError("--batch-dir must name a directory")
    if (root / "SKILL.md").is_file():
        return [root]
    sources = []

    def visit(directory):
        for child in sorted(directory.iterdir()):
            if child.name in EXCLUDED:
                continue
            if child.is_symlink():
                sources.append(child)
            elif child.is_dir():
                if (child / "SKILL.md").is_file():
                    sources.append(child)
                else:
                    start = len(sources)
                    visit(child)
                    if len(sources) == start:
                        sources.append(child)
            elif child.name.lower().endswith(ARCHIVE_SUFFIXES):
                sources.append(child)
    visit(root)
    return sorted(sources, key=lambda p: p.relative_to(root).as_posix())


def census_rows(inputs, *, root, workers, ignored, options):
    def scan(source):
        label = None
        if root is not None:
            relative = source.relative_to(root).as_posix()
            label = root.name if relative == "." else relative
        try:
            if root is not None and source.is_symlink():
                raise ScanError("symlink is not a batch package boundary")
            targets = collect_targets(str(source) if source is not None else None, census=True, **options)
            records = []
            for target in targets:
                name = label or target.source
                if label and target.name != source.name:
                    if source.is_dir():
                        name += "/" + target.name
                    else:
                        name += target.name[len(source.name):]
                if name.startswith(("http://", "https://")):
                    name = redact(name)
                row = census_record(target, ignored, name)
                row["target"] = name
                records.append(row)
            return records
        except (ScanError, OSError) as exc:
            name = label or (Path(source).name if source else "<inline-text>")
            reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
            return [{"schema_version": CENSUS_SCHEMA_VERSION, "scanner_version": VERSION,
                     "source": redact(name), "complete": False, "error": redact(reason)}]

    if workers == 1:
        for source in inputs:
            yield from scan(source)
        return
    sources = iter(inputs)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = deque()
        for _ in range(workers):
            source = next(sources, None)
            if source is None:
                break
            pending.append(pool.submit(scan, source))
        while pending:
            yield from pending.popleft().result()
            source = next(sources, None)
            if source is not None:
                pending.append(pool.submit(scan, source))
