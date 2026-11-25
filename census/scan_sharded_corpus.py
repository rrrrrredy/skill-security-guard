#!/usr/bin/env python3
"""Scan populated corpus buckets with the pinned scanner and publish one v2 JSONL."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from corpus_layout import buckets

SCANNER = Path(__file__).resolve().parents[1] / "scripts" / "scan.py"


def scan(packages, output, workers):
    if output.resolve().is_relative_to(packages.resolve()):
        raise ValueError("choose an output file outside the corpus packages directory")
    ordered = buckets(packages)
    output.parent.mkdir(parents=True, exist_ok=True)
    status = 0
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        merged = Path(tmp) / "merged.jsonl"
        part = Path(tmp) / "bucket.jsonl"
        with merged.open("w", encoding="utf-8", newline="\n") as dest:
            for bucket in ordered:
                with os.scandir(bucket) as entries:
                    if next(entries, None) is None:
                        continue
                result = subprocess.run([sys.executable, str(SCANNER), "--batch-dir", str(bucket),
                                         "--workers", str(workers), "--format", "jsonl", "--output", str(part)])
                # v5.3.0 atomically publishes its file even for D/F or individual bad packages.
                if result.returncode not in (0, 1, 2) or not part.is_file():
                    raise ValueError(f"scanner failed in bucket {bucket.name} (exit {result.returncode})")
                with part.open(encoding="utf-8") as stream:
                    for line in stream:
                        row = json.loads(line)
                        row["source"] = f"{bucket.name}/{row['source']}"
                        if row["complete"]:
                            row["target"] = row["source"]
                        dest.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
                part.unlink()
                status = max(status, result.returncode)
        os.replace(merged, output)
    return status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages-dir", type=Path, required=True, help="Collector's sharded packages/ directory.")
    parser.add_argument("--output", type=Path, required=True, help="Destination UTF-8 JSONL file.")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent packages within each bucket (default: 1).")
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be positive")
    try:
        return scan(args.packages_dir, args.output, args.workers)
    except (OSError, ValueError) as exc:
        print(f"sharded scan stopped: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
