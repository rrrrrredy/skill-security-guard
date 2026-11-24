#!/usr/bin/env python3
"""Discover, pin and collect public skill packages into a resumable census corpus."""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import sys
from urllib.error import HTTPError
from urllib.parse import quote
from zipfile import BadZipFile

from collection_state import (TIERS, Checkpoints, add_repo, add_shard, canonicalize, initialize,
                              progress, save_snapshot)
from github_source import GitHub, repository_name
from package_store import InvalidPackage, capture

DEFAULT_MANIFEST = Path(__file__).with_name("sources_manifest.json")


def read_manifest(path):
    data = json.loads(path.read_bytes())
    for name in data[TIERS[0]]:
        repository_name(name)
    for entry in data[TIERS[1]]:
        repository_name(entry["repo"])
        for path in [*entry["indexes"], *entry["directories"]]:
            if PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts or "\\" in path:
                raise ValueError("registry selectors must be repository-relative POSIX paths")
    wild = data[TIERS[2]]
    if not 0 <= wild["min_bytes"] <= wild["max_bytes"]:
        raise ValueError("invalid search byte range")
    for query in wild["queries"]:
        if "filename:skill.md" not in query.lower().split() or re.search(r"\b(?:path|size):", query, re.I):
            raise ValueError("queries must use filename:SKILL.md; size and path are supplied by the collector")
    if any(not re.fullmatch(r"[\w./-]+", prefix) or not prefix.strip("/") for prefix in wild["path_prefixes"]):
        raise ValueError("invalid search path prefix")
    return data


def collect_page(db, github, shard, prefixes):
    lo, hi, page = shard["lo"], shard["hi"], shard["page"]
    sizes = str(lo) if lo == hi else f"{lo}..{hi}"
    query = f"{shard['query']} size:{sizes}"
    if shard["prefix"]:
        query += " path:" + shard["prefix"]
    result = github.json("/search/code", {"q": query, "page": page, "per_page": 100})
    total, items = result["total_count"], result["items"]
    incomplete = bool(shard["incomplete"] or result["incomplete_results"])
    if not isinstance(total, int) or total < 0 or not isinstance(items, list) or len(items) > 100:
        raise ValueError("invalid code search response")
    total = max(total, shard["total"])
    with db:
        for item in items:
            repo = item["repository"]
            if repo.get("private") is False and PurePosixPath(item["path"]).name == "SKILL.md":
                add_repo(db, repository_name(repo["full_name"]), TIERS[2])
        received = shard["received"] + len(items)
        crowded = total > 900 or incomplete
        reason = None
        if crowded and lo < hi:
            middle = (lo + hi) // 2
            for left, right in ((lo, middle), (middle + 1, hi)):
                add_shard(db, shard["query"], left, right, shard["prefix"])
            status = "split"
        else:
            if crowded and not shard["prefix"]:
                for prefix in prefixes:
                    add_shard(db, shard["query"], lo, hi, prefix.rstrip("/"))
            if page < 10 and len(items) == 100 and received < min(total, 1000):
                status = "pending"
            elif incomplete or received < total:
                status = "partial"
                reason = "1000-result cap" if total > 1000 else ("incomplete_results" if incomplete else "short page")
            else:
                status = "done"
        db.execute("""UPDATE shards SET status=?,page=?,received=?,total=?,incomplete=?,reason=? WHERE id=?""",
                   (status, page + 1, received, total, incomplete, reason, shard["id"]))
        progress(db)


def mark(db, name, status, reason):
    with db:
        db.execute("UPDATE repos SET status=?,reason=? WHERE name=?", (status, reason, name))
        progress(db)


def collect_repo(db, github, row, registry, output):
    name = row["name"]
    sha = row["commit_sha"]
    try:
        if sha is None:
            meta = github.json("/repos/" + name)
            if meta.get("private") is not False or meta.get("visibility", "public") != "public":
                mark(db, name, "excluded", "repository is not public")
                return
            canonical = repository_name(meta["full_name"])
            if canonical.casefold() != name.casefold():
                with db:
                    canonicalize(db, name, canonical)
                return
            branch = quote(meta["default_branch"], safe="")
            sha = github.json(f"/repos/{name}/commits/{branch}")["sha"]
            if not re.fullmatch("[0-9a-f]{40}", sha):
                raise ValueError(f"invalid pinned commit for {name}")
            with db:
                db.execute("UPDATE repos SET name=?,commit_sha=?,stars=?,spdx_license=? WHERE name=?",
                           (canonical, sha, meta["stargazers_count"], (meta.get("license") or {}).get("spdx_id"), name))
            name = canonical
        with github.archive(name, sha, output) as archive:
            result = capture(archive, name, sha, registry, output)
        save_snapshot(db, name, *result)
    except HTTPError as exc:
        if exc.code not in (404, 409, 410, 451):
            raise
        mark(db, name, "unavailable", f"GitHub HTTP {exc.code}")
    except InvalidPackage as exc:
        mark(db, name, "rejected", str(exc))


def args_for(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST, help="Three-tier JSON source manifest.")
    parser.add_argument("--output-dir", type=Path, required=True, help="Corpus root. Skills go under packages/.")
    parser.add_argument("--state-db", type=Path, help="Live SQLite state (default: OUTPUT_DIR/state.sqlite3).")
    parser.add_argument("--checkpoint-dir", type=Path, help="Publish an atomic latest.sqlite3 backup here.")
    parser.add_argument("--checkpoint-every", type=int, default=500,
                        help="Backup interval in committed search pages and package outcomes (default: 500).")
    args = parser.parse_args(argv)
    if args.checkpoint_every < 1:
        parser.error("--checkpoint-every must be positive")
    return args


def main(argv=None, *, github=None):
    args = args_for(argv)
    try:
        manifest = read_manifest(args.manifest)
        fingerprint = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
        registries = {entry["repo"].casefold(): entry for entry in manifest[TIERS[1]]}
        output = args.output_dir.resolve()
        packages = output / "packages"
        state = args.state_db or (output / "state.sqlite3")
        if packages.is_symlink() or state.resolve().is_relative_to(packages) or (
                args.checkpoint_dir and args.checkpoint_dir.resolve().is_relative_to(packages)):
            raise ValueError("keep packages/, the state database and checkpoint storage separate")
        packages.mkdir(parents=True, exist_ok=True)
        state.parent.mkdir(parents=True, exist_ok=True)
        snapshots = Checkpoints(args.checkpoint_dir, args.checkpoint_every, state)
        github = github or GitHub(token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
        with closing(sqlite3.connect(state)) as db:
            initialize(db, manifest, fingerprint, packages)
            try:
                while True:
                    repo = db.execute("SELECT * FROM repos WHERE status='pending' ORDER BY name LIMIT 1").fetchone()
                    if repo:
                        catalog = registries.get(repo["name"].casefold())
                        if catalog is None:
                            for alias in db.execute("SELECT alias FROM aliases WHERE name=?", (repo["name"],)):
                                if alias[0].casefold() in registries:
                                    catalog = registries[alias[0].casefold()]
                                    break
                        collect_repo(db, github, repo, catalog or {}, output)
                    else:
                        shard = db.execute("SELECT * FROM shards WHERE status='pending' ORDER BY id LIMIT 1").fetchone()
                        if not shard:
                            break
                        collect_page(db, github, shard, manifest[TIERS[2]]["path_prefixes"])
                    snapshots.save(db)
            finally:
                snapshots.save(db, final=True)
            partial = db.execute("SELECT count(*) FROM shards WHERE status='partial'").fetchone()[0]
            print(json.dumps({"repos": dict(db.execute("SELECT status,count(*) FROM repos GROUP BY status")),
                              "packages": db.execute("SELECT count(*) FROM packages").fetchone()[0],
                              "rejected_packages": db.execute("SELECT count(*) FROM rejections").fetchone()[0],
                              "partial_shards": partial}))
            return 2 if partial else 0
    except (OSError, http.client.HTTPException, BadZipFile, ValueError, sqlite3.Error) as exc:
        print(f"collection stopped: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
