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
import sqlite3
import sys
import tempfile

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from collection_state import TIERS

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


def origin_for(state, source, digest):
    row = state.execute("""SELECT p.skill_path,p.canonical_tree_sha256,r.name,r.commit_sha,r.stars,r.spdx_license
        FROM packages p JOIN repos r ON r.name=p.repo WHERE p.source=?""", (source,)).fetchone()
    if row is None:
        raise ValueError(f"no collector provenance for {source!r}; scan the collector's packages/ directory")
    if row["canonical_tree_sha256"] != digest:
        raise ValueError(f"tree hash differs from the pinned collector inventory for {source!r}")
    tiers = sorted((r[0] for r in state.execute("SELECT tier FROM repo_tiers WHERE repo=?", (row["name"],))),
                   key=TIERS.index)
    return {"source": source, "repo_full_name": row["name"], "commit_sha": row["commit_sha"],
            "skill_path": row["skill_path"], "stars": row["stars"], "spdx_license": row["spdx_license"],
            "source_tier": tiers[0], "source_tiers": tiers}


def ingest(scan, state, scratch, malformed, seed):
    validator = Draft202012Validator(json.loads(SCHEMA.read_bytes()))
    scratch.executescript("""
        CREATE TABLE origins (source TEXT PRIMARY KEY, digest TEXT NOT NULL, details TEXT NOT NULL);
        CREATE INDEX origins_by_tree ON origins(digest,source);
        CREATE TABLE trees (digest TEXT PRIMARY KEY, tier INTEGER NOT NULL, rating TEXT NOT NULL,
            rank TEXT NOT NULL, sample_key TEXT NOT NULL, source TEXT NOT NULL, report TEXT NOT NULL);
        CREATE INDEX sampling ON trees(rating,tier,sample_key,digest);
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
                continue
            digest, source = row["canonical_tree_sha256"], row["source"]
            origin = origin_for(state, source, digest)
            tier = TIERS.index(origin["source_tier"])
            scratch.execute("INSERT OR IGNORE INTO origins VALUES(?,?,?)", (source, digest, dump(origin)))
            report = dump(row)
            # Worst observed grade wins. Tier, origin and report bytes break ties deterministically.
            rank = f"{'FDCBA'.index(row['rating'])}{tier}:{source}:{hashlib.sha256(report.encode()).hexdigest()}"
            sort_key = hashlib.sha256(f"{seed}\0{digest}".encode()).hexdigest()
            scratch.execute("""INSERT INTO trees VALUES(?,?,?,?,?,?,?) ON CONFLICT(digest) DO UPDATE SET
                tier=min(trees.tier, excluded.tier)""", (digest, tier, row["rating"], rank, sort_key, source, report))
            scratch.execute("""UPDATE trees SET rating=?,rank=?,source=?,report=? WHERE digest=? AND rank>?""",
                            (row["rating"], rank, source, report, digest, rank))
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
            origins = [json.loads(r[0]) for r in scratch.execute(
                "SELECT details FROM origins WHERE digest=? ORDER BY source", (tree["digest"],))]
            lineage.write(dump({"canonical_tree_sha256": tree["digest"], "source_tier": TIERS[tree["tier"]],
                                "occurrence_count": len(origins), "clone_count": len(origins) - 1,
                                "origins": origins}) + "\n")

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
