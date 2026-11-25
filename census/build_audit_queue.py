#!/usr/bin/env python3
"""Build reproducible lineage and review queues from v5.3.0 scanner JSONL."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from collection_state import TIERS
from corpus_layout import tree_path

SCHEMA = Path(__file__).resolve().parents[1] / "schemas/skill-security-scan.v2-census.schema.json"
LIMIT = 12000
OUTPUTS = ("malformed_packages.jsonl", "lineage_map.jsonl", "stage2_audit_queue.jsonl")


def dump(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def error_type(message):
    text = message.lower()
    for category, words in (
        ("unsafe_path", ("unsafe", "symlink", "links,", "special file", "ambiguous", "conflicting")),
        ("entry_limit", ("too many entries",)), ("size_limit", ("size limit", "too large", "stream limit")),
        ("invalid_archive", ("invalid or unsupported", "archive", "zip", "tar ")),
        ("encoding", ("utf-8", "unicode")), ("missing_input", ("not exist", "no such file")),
        ("permission", ("permission", "access is denied")),
    ):
        if any(word in text for word in words):
            return category
    return "other"


def source_digest(state, source):
    parts = source.split("/")
    if len(parts) == 2 and re.fullmatch("[0-9a-f]{64}", parts[1]) and parts[0] == parts[1][:2]:
        return "sha256:" + parts[1]
    if len(parts) == 1 and re.fullmatch("[0-9a-f]{64}", source):
        # Flat v5.3.0 archives used occurrence IDs. Direct single-bucket scans use tree keys.
        record = state.execute("""SELECT p.canonical_tree_sha256 FROM packages p JOIN repos r ON r.name=p.repo
                                  WHERE p.source=? AND r.status='done'""", (source,)).fetchone()
        return record[0] if record else "sha256:" + source
    return None


def record_origins(state, scratch, digest):
    best = None
    rows = state.execute("""SELECT p.source,p.skill_path,r.name,r.commit_sha,r.stars,r.spdx_license,
                      (SELECT group_concat(tier) FROM repo_tiers WHERE repo=r.name) AS tiers
                      FROM packages p JOIN repos r ON r.name=p.repo
                      WHERE p.canonical_tree_sha256=? AND r.status='done' ORDER BY p.source""", (digest,))
    for row in rows:
        tiers = sorted(row["tiers"].split(","), key=TIERS.index)
        source = row["source"]
        origin = {"source": source, "repo_full_name": row["name"], "commit_sha": row["commit_sha"],
                  "skill_path": row["skill_path"], "stars": row["stars"], "spdx_license": row["spdx_license"],
                  "source_tier": tiers[0], "source_tiers": tiers}
        scratch.execute("INSERT INTO origins VALUES(?,?,?)", (source, digest, dump(origin)))
        candidate = (TIERS.index(tiers[0]), source)
        if best is None or candidate < best:
            best = candidate
    if best is None:
        raise ValueError(f"no eligible collector provenance for {digest}")
    return best


def check_coverage(state, scratch):
    with closing(scratch.execute("SELECT digest FROM trees UNION SELECT digest FROM failed ORDER BY 1")) as covered, \
            closing(state.execute("""SELECT DISTINCT p.canonical_tree_sha256 FROM packages p JOIN repos r
                       ON r.name=p.repo WHERE r.status='done' ORDER BY p.canonical_tree_sha256""")) as expected:
        current = covered.fetchone()
        for (digest,) in expected:
            while current is not None and current[0] < digest:
                current = covered.fetchone()
            if current is None or current[0] != digest:
                raise ValueError(f"scan is missing collector tree {digest} ({tree_path(digest).as_posix()})")


def ingest(scan, state, scratch, malformed, seed):
    validator = Draft202012Validator(json.loads(SCHEMA.read_bytes()))
    scratch.executescript("""
        CREATE TABLE origins (source TEXT PRIMARY KEY, digest TEXT NOT NULL, details TEXT NOT NULL);
        CREATE INDEX origins_by_tree ON origins(digest,source);
        CREATE TABLE trees (digest TEXT PRIMARY KEY, tier INTEGER NOT NULL, rating TEXT NOT NULL,
            rank TEXT NOT NULL, sample_key TEXT NOT NULL, source TEXT NOT NULL, report TEXT NOT NULL);
        CREATE INDEX sampling ON trees(rating,tier,sample_key,digest);
        CREATE TABLE failed (digest TEXT PRIMARY KEY);
    """)
    errors = Counter()
    with scan.open(encoding="utf-8") as stream, scratch:
        for number, line in enumerate(stream, 1):
            try:
                row = json.loads(line)
                validator.validate(row)
            except (ValueError, ValidationError) as exc:
                raise ValueError(f"line {number} is not a v2 census record") from exc
            if row["scanner_version"] != "5.3.0":
                raise ValueError(f"line {number}: expected scanner_version 5.3.0")
            if not row["complete"]:
                malformed.write(dump(row) + "\n")
                errors[error_type(row["error"])] += 1
                digest = source_digest(state, row["source"])
                if digest is not None:
                    scratch.execute("INSERT OR IGNORE INTO failed VALUES(?)", (digest,))
                continue
            digest, source = row["canonical_tree_sha256"], row["source"]
            if source_digest(state, source) != digest:
                raise ValueError(f"tree hash differs from the pinned collector source on line {number}: {source!r}")
            report = dump(row)
            rank = f"{'FDCBA'.index(row['rating'])}:{source}:{hashlib.sha256(report.encode()).hexdigest()}"
            existing = scratch.execute("SELECT rank FROM trees WHERE digest=?", (digest,)).fetchone()
            if existing is None:
                tier, representative = record_origins(state, scratch, digest)
                sort_key = hashlib.sha256(f"{seed}\0{digest}".encode()).hexdigest()
                scratch.execute("INSERT INTO trees VALUES(?,?,?,?,?,?,?)",
                                (digest, tier, row["rating"], rank, sort_key, representative, report))
            elif rank < existing["rank"]:
                scratch.execute("UPDATE trees SET rating=?,rank=?,report=? WHERE digest=?",
                                (row["rating"], rank, report, digest))
        if state.execute("SELECT 1 FROM meta WHERE key='package_layout'").fetchone():
            check_coverage(state, scratch)
    return errors


def allocations(counts, budget):
    """Proportional largest remainder, with one seat per stratum when feasible."""
    budget = min(budget, sum(counts.values()))
    initial = int(budget >= len(counts))
    seats = {key: initial for key in counts}
    remaining = budget - sum(seats.values())
    if not remaining:
        return seats
    available = {k: n - seats[k] for k, n in counts.items()}
    total = sum(available.values())
    remainder = {}
    for key, count in available.items():
        whole, remainder[key] = divmod(remaining * count, total)
        seats[key] += whole
    for key in sorted(seats, key=lambda k: (-remainder[k], k))[:budget - sum(seats.values())]:
        seats[key] += 1
    return seats


def clip(value, limit):
    return value if len(value) <= limit else value[:limit - 1] + "…"


def evidence(issue, text_limit=320):
    item = issue["evidence"]
    return {"rule_id": issue["rule_id"], "severity": issue["severity"], "confidence": issue["confidence"],
            "evidence": {"file": clip(item["file"], 400), "line": item["line"], "text": clip(item["text"], text_limit)},
            "context": [{"line": c["line"], "text": clip(c["text"], text_limit)} for c in issue["context"]]}


def dossier(tree, origin, files, selection):
    report = json.loads(tree["report"])
    issues = report["issues"]
    origin = dict(origin, skill_path=clip(origin["skill_path"], 500))
    row = {"canonical_tree_sha256": tree["digest"], "scanner_version": report["scanner_version"],
           "rating": tree["rating"], "score": report["score"], "selection": selection,
           "tier": TIERS[tree["tier"]], "origin": origin, "declared_intent": report["declared_intent"],
           "files": [], "issues": [], "omitted_files": len(files), "omitted_issues": len(issues)}
    room = LIMIT - 1 - len(dump(row))

    def append(field, value, budget):
        nonlocal room
        cost = len(dump(value)) + bool(row[field])
        if cost > min(room, budget):
            return False
        row[field].append(value)
        room -= cost
        return True

    # Reserve space for both inventory and the scanner's highest-priority evidence.
    file_budget = min(room, 2000)
    for name, _, _ in files:
        before = room
        if not append("files", clip(name, 500), file_budget):
            break
        file_budget -= before - room
    for issue in issues:
        if not append("issues", evidence(issue), room):
            if not row["issues"]:
                append("issues", evidence(issue, 96), room)
            break
    for index in range(len(row["files"]), len(files)):
        if not append("files", clip(files[index][0], 500), room):
            break
    row["omitted_files"] -= len(row["files"])
    row["omitted_issues"] -= len(row["issues"])
    line = dump(row) + "\n"
    if len(line) > LIMIT:
        raise ValueError("dossier identity and declared intent exceed the character budget")
    return line


def write_queues(state, scratch, output, full, budget):
    with (output / OUTPUTS[1]).open("w", encoding="utf-8", newline="\n") as lineage:
        for tree in scratch.execute("SELECT digest,tier FROM trees ORDER BY digest"):
            digest = tree["digest"]
            count = scratch.execute("SELECT count(*) FROM origins WHERE digest=?", (digest,)).fetchone()[0]
            header = {"canonical_tree_sha256": digest, "source_tier": TIERS[tree["tier"]],
                      "occurrence_count": count, "clone_count": count - 1}
            lineage.write(dump(header)[:-1] + ',"origins":[')
            for index, (details,) in enumerate(scratch.execute(
                    "SELECT details FROM origins WHERE digest=? ORDER BY source", (digest,))):
                if index:
                    lineage.write(",")
                lineage.write(details)
            lineage.write("]}\n")

    counts = {(r["rating"], r["tier"]): r["n"] for r in scratch.execute(
        "SELECT rating,tier,count(*) AS n FROM trees GROUP BY rating,tier")}
    sample = allocations({k: n for k, n in counts.items() if k[0] not in full}, budget)
    selected = Counter()
    with (output / OUTPUTS[2]).open("w", encoding="utf-8", newline="\n") as queue:
        order = sorted(counts, key=lambda pair: (pair[0] not in full, "FDCBA".index(pair[0]), pair[1]))
        for grade, tier in order:
            selection = "full" if grade in full else "sample"
            limit = counts[grade, tier] if selection == "full" else sample[grade, tier]
            for tree in scratch.execute("""SELECT * FROM trees WHERE rating=? AND tier=?
                                            ORDER BY sample_key,digest LIMIT ?""", (grade, tier, limit)):
                [origin] = scratch.execute("SELECT details FROM origins WHERE source=?", (tree["source"],)).fetchone()
                [files] = state.execute("SELECT files FROM packages WHERE source=?", (tree["source"],)).fetchone()
                queue.write(dossier(tree, json.loads(origin), json.loads(files), selection))
                selected[selection] += 1
    return {"unique_trees": sum(counts.values()), "full": selected["full"], "sampled": selected["sample"],
            "sample_by_stratum": {f"{grade}/{TIERS[tier]}": n for (grade, tier), n in sorted(sample.items())}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-jsonl", required=True, type=Path, help="v5.3.0 scanner JSONL.")
    parser.add_argument("--state-db", required=True, type=Path, help="Collector SQLite provenance database.")
    parser.add_argument("--output-dir", required=True, type=Path, help="Directory for the three JSONL outputs.")
    parser.add_argument("--full-grades", nargs="+", default=["C,D,F"], metavar="GRADE",
                        help="Full-review grades, comma or space separated. C/D/F always included; use B to add B.")
    parser.add_argument("--seed", type=int, default=20261124, help="Deterministic sampling seed (default: 20261124).")
    parser.add_argument("--ab-sample-size", type=int, default=1500, help="Total remaining A/B sample (default: 1500).")
    args = parser.parse_args(argv)
    full = set("CDF") | {g.strip().upper() for arg in args.full_grades for g in arg.split(",")}
    if full - set("BCDF") or args.ab_sample_size < 0:
        parser.error("use B/C/D/F for --full-grades and a nonnegative --ab-sample-size")
    try:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        if {args.scan_jsonl.resolve(), args.state_db.resolve()} & {
            (args.output_dir / name).resolve() for name in OUTPUTS
        }:
            raise ValueError("an output file would overwrite an input")
        with tempfile.TemporaryDirectory(dir=args.output_dir) as tmp:
            stage = Path(tmp)
            with closing(sqlite3.connect(args.state_db.resolve().as_uri() + "?mode=ro", uri=True)) as state, \
                    closing(sqlite3.connect(stage / "groups.sqlite3")) as scratch:
                state.row_factory = scratch.row_factory = sqlite3.Row
                state.execute("BEGIN")
                with (stage / OUTPUTS[0]).open("w", encoding="utf-8", newline="\n") as malformed:
                    errors = ingest(args.scan_jsonl, state, scratch, malformed, args.seed)
                summary = write_queues(state, scratch, stage, full, args.ab_sample_size)
            for filename in OUTPUTS:
                os.replace(stage / filename, args.output_dir / filename)
        print(dump({**summary, "malformed": sum(errors.values()), "error_types": dict(errors),
                    "seed": args.seed, "full_grades": sorted(full)}))
        return 0
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"queue build stopped: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
