"""Publish complete, portable skill directories from one immutable GitHub snapshot."""
from __future__ import annotations

from collections import defaultdict
import errno
import hashlib
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import tempfile
import unicodedata
from zipfile import ZipInfo

from github_source import repository_name
from corpus_layout import tree_path

MAX_SKILL_BYTES = 10 * 1024 * 1024
# The v5.3.0 canonical tree excludes these directories.
EXCLUDED = {".git", ".mypy_cache", ".pytest_cache", "__pycache__", "node_modules", "venv", ".venv"}
LINK = re.compile(r"\]\(\s*<?https://github\.com/([A-Za-z0-9-]+/[A-Za-z0-9._-]+)"
                  r"(?=(?:/(?:tree|blob)/|/?[#)> \t]))", re.I)


class InvalidPackage(ValueError):
    """An unsafe, oversized or nonportable archive member."""


class BulkMirror(Exception):
    def __init__(self, skill_count):
        super().__init__(f"{skill_count} skill roots in wild repository")
        self.skill_count = skill_count


def wild_skill_count(archive):
    # Only inspect central-directory names. A Git tree has one entry per path.
    roots = set()
    for info in archive.infolist():
        name = info.orig_filename
        if name.endswith("/SKILL.md") and not EXCLUDED.intersection(name.split("/")[1:-1]):
            roots.add(name)
    return len(roots)


def members(archive):
    result = {}
    wrapper = None
    for info in archive.infolist():
        name = info.orig_filename
        parts = name.removesuffix("/").split("/")
        if ("\\" in name or "\0" in name or PureWindowsPath(name).drive or
                any(part in {"", ".", ".."} for part in parts)):
            raise InvalidPackage("unsafe repository archive path")
        if wrapper is None:
            wrapper = parts[0]
        if parts[0] != wrapper or (len(parts) == 1 and not info.is_dir()):
            raise InvalidPackage("expected one GitHub archive wrapper")
        if info.is_dir():
            continue
        if EXCLUDED.intersection(parts[1:]):
            continue
        path = PurePosixPath(*parts[1:])
        if path in result:
            raise InvalidPackage("duplicate repository archive member")
        result[path] = info
    return result


def regular(info: ZipInfo):
    return not (info.flag_bits & 1) and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG)


def inventory(archive, files):
    if sum(info.file_size for _, info in files) > MAX_SKILL_BYTES:
        raise InvalidPackage("skill exceeds 10 MiB")
    seen = {}
    records = []
    payloads = []
    total = 0
    tree = hashlib.sha256()
    for rel, info in sorted(files, key=lambda pair: pair[0].as_posix()):
        if not regular(info):
            raise InvalidPackage("skill contains a link, encrypted entry or special file")
        parents = []
        for part in rel.parts:
            if (PureWindowsPath(part).is_reserved() or part.endswith((" ", ".")) or
                    any(ord(c) < 32 or c in '<>:"|?*' for c in part)):
                raise InvalidPackage("nonportable member name")
            parents.append(part)
            spelling = "/".join(parents)
            identity = unicodedata.normalize("NFC", spelling).casefold()
            kind = "file" if len(parents) == len(rel.parts) else "directory"
            if seen.setdefault(identity, (spelling, kind)) != (spelling, kind):
                raise InvalidPackage("case, Unicode or file/directory path collision")
        with archive.open(info) as source:
            data = source.read(MAX_SKILL_BYTES - total + 1)
        size = len(data)
        total += size
        if total > MAX_SKILL_BYTES:
            raise InvalidPackage("skill exceeds 10 MiB")
        if size != info.file_size:
            raise InvalidPackage("member length mismatch")
        name = rel.as_posix()
        digest = hashlib.sha256(data)
        encoded = name.encode("utf-8")
        tree.update(len(encoded).to_bytes(8, "big") + encoded + size.to_bytes(8, "big") + digest.digest())
        records.append([name, size, digest.hexdigest()])
        payloads.append((rel, data))
    return records, "sha256:" + tree.hexdigest(), payloads


def same_publication(dest, files):
    if dest.is_symlink() or not dest.is_dir():
        return False
    expected = {name: (size, digest) for name, size, digest in files}
    for path in dest.rglob("*"):
        if path.is_symlink():
            return False
        if path.is_dir():
            continue
        item = expected.pop(path.relative_to(dest).as_posix(), None)
        if not item or path.stat().st_size != item[0] or hashlib.sha256(path.read_bytes()).hexdigest() != item[1]:
            return False
    return not expected


def publish(output, digest, files, payloads):
    dest = output / "packages" / tree_path(digest)
    bucket = dest.parent
    bucket.mkdir(exist_ok=True)
    if bucket.is_symlink():
        raise OSError(f"symlink at corpus bucket {bucket}")
    if not os.path.lexists(dest):
        with tempfile.TemporaryDirectory(prefix=".skill-", dir=output) as scratch:
            stage = Path(scratch) / "package"
            stage.mkdir()
            for rel, data in payloads:
                target = stage.joinpath(*rel.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            try:
                stage.rename(dest)
                return
            except OSError as exc:
                if exc.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                    raise
    if not same_publication(dest, files):
        raise OSError(f"existing corpus tree differs from its digest: {digest}")


def capture(archive, repo, sha, registry, output, wild_limit=None):
    if wild_limit is not None:
        count = wild_skill_count(archive)
        if count > wild_limit:
            raise BulkMirror(count)
    by_path = members(archive)
    roots = {path.parent for path in by_path if path.name == "SKILL.md"}
    grouped = defaultdict(list)
    linked = set()
    indexes = set(registry.get("indexes", []))
    directories = {PurePosixPath(d) for d in registry.get("directories", [])}
    for path, info in by_path.items():
        root = next((p for p in path.parents if p in roots), None)
        if root is not None:
            grouped[root].append((path.relative_to(root), info))
        if path.as_posix() in indexes or (path.parent in directories and path.suffix.lower() == ".md"
                                          and path.name != "SKILL.md"):
            if not regular(info) or info.file_size > MAX_SKILL_BYTES:
                raise InvalidPackage("invalid registry index")
            for match in LINK.finditer(archive.read(info).decode("utf-8", "replace")):
                linked.add(repository_name(match[1].removesuffix(".git")))
    packages = []
    rejected = []
    published = set()
    for root in sorted(roots):
        skill_path = root.as_posix()
        key = hashlib.sha256(f"{repo.casefold()}\0{sha}\0{skill_path}".encode()).hexdigest()
        try:
            files, digest, payloads = inventory(archive, grouped[root])
        except InvalidPackage as exc:
            rejected.append((skill_path, str(exc)))
            continue
        if digest not in published:
            publish(output, digest, files, payloads)
            published.add(digest)
        packages.append((key, skill_path, files, digest))
    return packages, rejected, linked
