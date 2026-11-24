#!/usr/bin/env python3
"""Command-line entry point for v1 scans and the v2 census."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import tempfile

# The v1 entry point also supports importlib.spec_from_file_location callers.
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from skillscan.archives import MAX_ZIP_BYTES, MAX_ZIP_FILES
from skillscan.census import batch_sources, census_rows
from skillscan.engine import scan_source
from skillscan.inputs import collect_targets
from skillscan.model import REPORT_SCHEMA_VERSION, VERSION, Report, ScanError
from skillscan.text_rules import parse_frontmatter


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return number


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Scan skill packages for static security risks.")
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("input", nargs="?", help="Skill file, directory, archive, URL or '-' for stdin.")
    inputs.add_argument("--text", help="Inline skill text.")
    inputs.add_argument("--batch-dir", type=Path, help="Census a collection of directories and archives.")
    parser.add_argument("--workers", type=positive, help="Number of packages to process concurrently.")
    parser.add_argument("--extract-intent-context", action="store_true",
                        help="Emit the census record with declared intent and redacted evidence windows.")
    parser.add_argument("--format", choices=("text", "json", "jsonl"))
    parser.add_argument("--output", type=Path, help="Write the report to this UTF-8 file.")
    parser.add_argument("--ignore", action="append", default=[], metavar="RULE_ID")
    parser.add_argument("--include-references", action="store_true")
    parser.add_argument("--max-zip-bytes", type=positive, default=MAX_ZIP_BYTES,
                        help="Maximum compressed and total expanded member bytes for ZIP or TAR.")
    parser.add_argument("--max-zip-files", type=positive, default=MAX_ZIP_FILES,
                        help="Maximum number of ZIP or TAR entries, including directories.")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    args.census = args.batch_dir is not None or args.extract_intent_context or args.format == "jsonl"
    if args.workers is not None and args.batch_dir is None:
        parser.error("--workers requires --batch-dir")
    if args.census and args.format == "text":
        parser.error("census records require --format json or jsonl")
    if any(not rule.strip() for rule in args.ignore):
        parser.error("--ignore requires a nonempty rule ID")
    return args


def render_text(reports: list[Report]) -> str:
    chunks: list[str] = []
    for report in reports:
        chunks.append(f"Skill Security Report: {report.target}")
        chunks.append(f"Scanner: {VERSION} ({REPORT_SCHEMA_VERSION})")
        chunks.append(f"Input SHA-256: {report.input_sha256}")
        chunks.append(f"Complete: {str(report.complete).lower()}")
        if report.ignored_rules:
            chunks.append(f"Ignored rules: {', '.join(report.ignored_rules)}")
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


def write_utf8(text: str) -> None:
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:
        sys.stdout.write(text)
    else:
        buffer.write(text.encode("utf-8"))


def write_stdout(text: str) -> None:
    write_utf8(text + "\n")


@contextmanager
def destination(output):
    if output is None:
        yield write_utf8
        return
    temp = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                       dir=output.parent, suffix=".tmp", delete=False)
    try:
        with temp:
            yield temp.write
        os.replace(temp.name, output)
    finally:
        Path(temp.name).unlink(missing_ok=True)


def write_rows(rows, write, fmt):
    status = 0
    first = True
    if fmt == "json":
        write("[")
    for row in rows:
        if not row["complete"]:
            status = 2
        elif row["rating"] in {"D", "F"}:
            status = max(status, 1)
        if fmt == "json" and not first:
            write(",\n")
        write(json.dumps(row, ensure_ascii=False))
        if fmt == "jsonl":
            write("\n")
        first = False
    if fmt == "json":
        write("]\n")
    return status


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    ignored = set(args.ignore)
    options = dict(text=args.text, include_references=args.include_references,
                   max_zip_bytes=args.max_zip_bytes, max_zip_files=args.max_zip_files)
    try:
        root = args.batch_dir.resolve() if args.batch_dir is not None else None
        inputs = batch_sources(root) if root else [args.input]
        if args.output:
            output = args.output.resolve()
            for source in inputs:
                if source is None or str(source).startswith(("http://", "https://")) or source == "-":
                    continue
                path = Path(source).resolve()
                if output == path or (path.is_dir() and output.is_relative_to(path)):
                    raise ScanError("--output would modify an input package; select a sibling report file")
        if args.census:
            rows = census_rows(inputs, root=root, workers=args.workers or 1, ignored=ignored, options=options)
            with destination(args.output) as write:
                return write_rows(rows, write, args.format or "jsonl")

        reports = scan_source(args.input, ignored_rules=ignored, **options)
        if args.format == "json":
            body = json.dumps([r.to_dict() for r in reports], indent=2, ensure_ascii=False)
        else:
            body = render_text(reports)
        if args.output:
            with destination(args.output) as write:
                write(body + "\n")
        else:
            write_stdout(body)
        return int(any(report.rating in {"D", "F"} for report in reports))
    except (OSError, ScanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
