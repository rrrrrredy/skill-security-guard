"""Discover package boundaries and take one snapshot for analysis and both hashes."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import urllib.request

from .archives import ARCHIVE_SUFFIXES, MAX_ZIP_BYTES, MAX_ZIP_FILES, read_archive
from .model import Document, ScanError, Target, VERSION

EXCLUDED = {".git", ".mypy_cache", ".pytest_cache", "__pycache__", "node_modules", "venv", ".venv"}
EXTENSIONS = {".md", ".sh", ".bash", ".ps1", ".py", ".js", ".mjs", ".ts", ".json", ".yaml", ".yml"}
URL_MAX_BYTES = 2 * 1024 * 1024


def read_stdin_utf8() -> str:
    stream = getattr(sys.stdin, "buffer", None)
    try:
        if stream is not None:
            return stream.read().decode("utf-8")
        text = sys.stdin.read()
        text.encode("utf-8")
        return text
    except UnicodeError as exc:
        raise ScanError("stdin is not valid UTF-8") from exc


def fetch_url(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": f"skill-security-guard/{VERSION}"})
    with urllib.request.urlopen(request, timeout=10) as response:
        kind = response.headers.get("content-type", "")
        if not any(word in kind for word in ("text", "json", "markdown")):
            raise ScanError(f"URL does not look text-like: {kind or 'unknown content type'}")
        data = response.read(URL_MAX_BYTES + 1)
    if len(data) > URL_MAX_BYTES:
        raise ScanError("URL response is too large")
    return data


def decode_file(data: bytes) -> str:
    encoding = "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
    return data.decode(encoding, errors="replace").replace("\r\n", "\n").replace("\r", "\n")


def tree_record(tree, name: str, size: int, digest: bytes) -> None:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ScanError("file name is not valid UTF-8") from exc
    tree.update(len(encoded).to_bytes(8, "big"))
    tree.update(encoded)
    tree.update(size.to_bytes(8, "big"))
    tree.update(digest)


def single_target(name: str, source: str, filename: str, text: str, raw: bytes, census: bool) -> Target:
    tree = hashlib.sha256()
    if census:
        tree_record(tree, filename, len(raw), hashlib.sha256(raw).digest())
    return Target(name, source, (Document(filename, text),), "sha256:" + tree.hexdigest() if census else None)


def checked_link(path: Path, root: Path) -> Path:
    try:
        dest = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ScanError(f"broken or cyclic symlink: {path.name!r}") from exc
    if not dest.is_relative_to(root):
        raise ScanError(f"symlink leaves skill root: {path.name!r}")
    return dest


def directory_entries(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}

    def walk_error(exc):
        raise exc

    for directory, dirs, leaves in os.walk(root, onerror=walk_error):
        parent = Path(directory)
        dirs[:] = sorted(name for name in dirs if name not in EXCLUDED)
        for name in dirs:
            child = parent / name
            if child.is_symlink() or child.resolve() != child:
                checked_link(child, root)
                raise ScanError(f"directory symlink is unsupported: {name!r}")
        for name in leaves:
            child = parent / name
            if child.is_symlink():
                checked_link(child, root)
            if not stat.S_ISREG(child.stat().st_mode):
                raise ScanError(f"special file is unsupported: {name!r}")
            files[child.relative_to(root).as_posix()] = child
    return files


def scan_priority(name: str, has_skill: bool, references: bool) -> int | None:
    path = PurePosixPath(name)
    top = path.parts[0]
    if name == "SKILL.md":
        return 0
    if top == "references":
        return 2 if references and path.suffix.lower() == ".md" else None
    if path.suffix.lower() not in EXTENSIONS or top == ".github":
        return None
    if top == "tests":
        return 3
    if top == "scripts" or not has_skill or path.suffix.lower() in {
        ".sh", ".bash", ".ps1", ".py", ".js", ".mjs", ".ts"
    }:
        return 1
    return None


def make_package(name, source, entries, *, has_skill, census, references, disk_root) -> Target:
    docs = []
    tree = hashlib.sha256()
    for rel, value in sorted(entries):
        priority = scan_priority(rel, has_skill, references)
        if isinstance(value, Path) and value.is_symlink():
            value = checked_link(value, disk_root)
        if priority is None and not census:
            continue
        if isinstance(value, Path):
            if priority is None:
                digest = hashlib.sha256()
                size = 0
                with value.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(65536), b""):
                        size += len(chunk)
                        digest.update(chunk)
                tree_record(tree, rel, size, digest.digest())
                continue
            with value.open("rb") as stream:
                raw = stream.read(MAX_ZIP_BYTES + 1)
            if len(raw) > MAX_ZIP_BYTES:
                raise ScanError(f"scannable file exceeds size limit: {rel!r}")
        else:
            raw = value
        if census:
            tree_record(tree, rel, len(raw), hashlib.sha256(raw).digest())
        if priority is not None:
            docs.append((priority, rel, Document(rel, decode_file(raw))))
    return Target(name, source, tuple(doc for _, _, doc in sorted(docs)),
                  "sha256:" + tree.hexdigest() if census else None, bundled=True)


def package_targets(entries: dict, path: Path, *, archive: bool, census: bool, references: bool):
    roots = {PurePosixPath(key).parent for key in entries if PurePosixPath(key).name == "SKILL.md"}
    # A nested fixture is a separate package, never executable code of its parent.
    visible = {root for root in roots if "tests" not in root.parts and ".github" not in root.parts}
    if not visible:
        visible = {PurePosixPath(".")}
    groups = {root: [] for root in visible}
    for key, value in entries.items():
        rel = PurePosixPath(key)
        if EXCLUDED.intersection(rel.parts):
            continue
        owner = next((parent for parent in rel.parents if parent in roots), PurePosixPath("."))
        if owner in groups:
            groups[owner].append((rel.relative_to(owner).as_posix(), value))
    for root in sorted(visible):
        local = root.as_posix()
        if archive:
            name = path.name if local == "." else f"{path.name}:{local}"
        else:
            name = path.name if local == "." else local
        yield make_package(name, name, groups[root], has_skill=root in roots, census=census,
                           references=references, disk_root=path / root)


def collect_targets(source: str | None, *, text: str | None = None, include_references: bool = False,
                    max_zip_bytes: int = MAX_ZIP_BYTES, max_zip_files: int = MAX_ZIP_FILES,
                    census: bool = False) -> list[Target]:
    if text is not None or source == "-":
        name = "<inline-text>" if text is not None else "<stdin>"
        content = text if text is not None else read_stdin_utf8()
        return [single_target(name, name, "SKILL.md", content, content.encode("utf-8"), census)]
    if not source:
        raise ScanError("missing input: provide a path, URL, '-' for stdin, or --text")
    if source.startswith(("https://", "http://")):
        raw = fetch_url(source)
        return [single_target(source, source, "SKILL.md", raw.decode("utf-8", errors="replace"), raw, census)]

    path = Path(source).expanduser()
    if not path.exists():
        raise ScanError(f"input does not exist: {source}")
    if path.is_symlink():
        checked_link(path, path.parent.resolve())
    path = path.resolve()
    if path.is_dir():
        entries = directory_entries(path)
        archive = False
    elif not path.is_file():
        raise ScanError("input must be a regular file or directory")
    elif path.name.lower().endswith(ARCHIVE_SUFFIXES):
        entries = read_archive(path, max_zip_bytes, max_zip_files)
        archive = True
    else:
        with path.open("rb") as stream:
            raw = stream.read(MAX_ZIP_BYTES + 1)
        if len(raw) > MAX_ZIP_BYTES:
            raise ScanError("scannable file exceeds size limit")
        return [single_target(path.name, path.name, path.name, decode_file(raw), raw, census)]
    return list(package_targets(entries, path, archive=archive, census=census, references=include_references))
