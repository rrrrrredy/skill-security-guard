"""Durable discovery, pinned repository and provenance records for one manifest."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import tempfile

TIERS = ("tier1_official", "tier2_registry", "tier3_wild_github")
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS repos (
    name TEXT COLLATE NOCASE PRIMARY KEY, commit_sha TEXT, stars INTEGER, spdx_license TEXT,
    status TEXT NOT NULL DEFAULT 'pending', reason TEXT
);
CREATE INDEX IF NOT EXISTS repos_by_status ON repos(status, name);
CREATE TABLE IF NOT EXISTS aliases (alias TEXT COLLATE NOCASE PRIMARY KEY, name TEXT COLLATE NOCASE NOT NULL);
CREATE TABLE IF NOT EXISTS repo_tiers (
    repo TEXT COLLATE NOCASE NOT NULL, tier TEXT NOT NULL, PRIMARY KEY(repo,tier)
);
CREATE TABLE IF NOT EXISTS packages (
    source TEXT PRIMARY KEY, repo TEXT COLLATE NOCASE NOT NULL, skill_path TEXT NOT NULL,
    files TEXT NOT NULL, canonical_tree_sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS packages_by_repo ON packages(repo);
CREATE TABLE IF NOT EXISTS rejections (
    repo TEXT COLLATE NOCASE NOT NULL, skill_path TEXT NOT NULL, reason TEXT NOT NULL,
    PRIMARY KEY(repo,skill_path)
);
CREATE TABLE IF NOT EXISTS shards (
    id INTEGER PRIMARY KEY, query TEXT NOT NULL, lo INTEGER NOT NULL, hi INTEGER NOT NULL,
    prefix TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', page INTEGER NOT NULL DEFAULT 1,
    received INTEGER NOT NULL DEFAULT 0, total INTEGER NOT NULL DEFAULT 0,
    incomplete INTEGER NOT NULL DEFAULT 0, reason TEXT, UNIQUE(query,lo,hi,prefix)
);
CREATE INDEX IF NOT EXISTS shards_by_status ON shards(status,id);
"""


def add_repo(db, name, tier):
    alias = db.execute("SELECT name FROM aliases WHERE alias=?", (name,)).fetchone()
    name = alias[0] if alias else name
    db.execute("INSERT OR IGNORE INTO repos(name) VALUES(?)", (name,))
    db.execute("INSERT OR IGNORE INTO repo_tiers VALUES(?,?)", (name, tier))


def canonicalize(db, old, new):
    if old.casefold() == new.casefold():
        return
    for row in db.execute("SELECT tier FROM repo_tiers WHERE repo=?", (old,)).fetchall():
        add_repo(db, new, row[0])
    db.execute("INSERT OR REPLACE INTO aliases VALUES(?,?)", (old, new))
    db.execute("DELETE FROM repo_tiers WHERE repo=?", (old,))
    db.execute("DELETE FROM repos WHERE name=?", (old,))


def add_shard(db, query, lo, hi, prefix=""):
    db.execute("INSERT OR IGNORE INTO shards(query,lo,hi,prefix) VALUES(?,?,?,?)", (query, lo, hi, prefix))


def initialize(db, manifest, fingerprint, packages):
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    with db:
        previous = db.execute("SELECT value FROM meta WHERE key='manifest_sha256'").fetchone()
        if previous and previous[0] != fingerprint:
            raise ValueError("state database belongs to a different manifest")
        db.execute("INSERT OR IGNORE INTO meta VALUES('manifest_sha256', ?)", (fingerprint,))
        db.execute("INSERT OR IGNORE INTO meta VALUES('progress', '0')")
        for name in manifest[TIERS[0]]:
            add_repo(db, name, TIERS[0])
        for entry in manifest[TIERS[1]]:
            add_repo(db, entry["repo"], TIERS[1])
        wild = manifest[TIERS[2]]
        for query in wild["queries"]:
            add_shard(db, query, wild["min_bytes"], wild["max_bytes"])
        db.execute("""UPDATE shards SET status='pending',page=1,received=0,total=0,incomplete=0,reason=NULL
                      WHERE status='partial' AND reason IN ('incomplete_results','short page')""")
        # A restored SQLite backup may outlive Colab's package directory.
        for row in db.execute("SELECT source,repo FROM packages"):
            if not (packages / row["source"] / "SKILL.md").is_file():
                db.execute("UPDATE repos SET status='pending' WHERE name=?", (row["repo"],))


def progress(db, amount=1):
    db.execute("UPDATE meta SET value=CAST(value AS INTEGER)+? WHERE key='progress'", (amount,))


class Checkpoints:
    def __init__(self, directory, interval, live):
        self.latest = directory / "latest.sqlite3" if directory else None
        self.interval = interval
        self.last = None
        if self.latest:
            if self.latest.resolve() == live.resolve():
                raise ValueError("restore latest.sqlite3 to a separate live --state-db")
            directory.mkdir(parents=True, exist_ok=True)

    def save(self, db, final=False):
        if self.latest is None:
            return
        value = int(db.execute("SELECT value FROM meta WHERE key='progress'").fetchone()[0])
        if self.last is None:
            self.last = 0
        if not final and value - self.last < self.interval:
            return
        fd, tmp = tempfile.mkstemp(dir=self.latest.parent, suffix=".sqlite3")
        os.close(fd)
        try:
            dest = sqlite3.connect(tmp)
            try:
                db.backup(dest)
            finally:
                dest.close()
            os.replace(tmp, self.latest)
            self.last = value
        finally:
            Path(tmp).unlink(missing_ok=True)


def save_snapshot(db, repo, packages, rejected, linked):
    with db:
        for name in sorted(linked):
            add_repo(db, name, TIERS[1])
        for key, path, files, digest in packages:
            db.execute("INSERT OR REPLACE INTO packages VALUES(?,?,?,?,?)",
                       (key, repo, path, json.dumps(files, ensure_ascii=False), digest))
        for path, reason in rejected:
            db.execute("INSERT OR REPLACE INTO rejections VALUES(?,?,?)", (repo, path, reason))
        db.execute("UPDATE repos SET status='done',reason=NULL WHERE name=?", (repo,))
        progress(db, max(1, len(packages) + len(rejected)))
