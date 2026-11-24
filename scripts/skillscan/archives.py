"""Read bounded archive members as data. Archive names never become disk paths."""
from __future__ import annotations

import gzip
import io
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import tarfile
import zipfile
import zlib

from .model import ScanError

MAX_ZIP_BYTES = 10 * 1024 * 1024
MAX_ZIP_FILES = 500
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz")


def member_path(value: str, kind: str) -> str:
    path = PurePosixPath(value.replace("\\", "/"))
    if (path.is_absolute() or PureWindowsPath(value).drive or ".." in path.parts
            or "\0" in value or any(":" in part for part in path.parts)):
        raise ScanError(f"unsafe {kind} entry path: {value!r}")
    return path.as_posix()


def read_archive(path: Path, max_bytes: int, max_files: int) -> dict[str, bytes]:
    if path.stat().st_size > max_bytes:
        raise ScanError("archive exceeds compressed input size limit")
    kind = "zip" if path.suffix.lower() == ".zip" else "tar"
    files: dict[str, bytes] = {}
    names: set[str] = set()
    expanded = 0
    count = 0

    def reserve(name: str, size: int, directory: bool) -> str:
        nonlocal expanded, count
        count += 1
        expanded += size
        if count > max_files:
            raise ScanError(f"{kind} has too many entries")
        if size < 0 or expanded > max_bytes:
            raise ScanError(f"{kind} exceeds expanded size limit")
        key = member_path(name, kind)
        if (key == "." and not directory) or key in names:
            raise ScanError(f"ambiguous {kind} member: {name!r}")
        names.add(key)
        return key

    try:
        if kind == "zip":
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    key = reserve(info.orig_filename, info.file_size, info.is_dir())
                    mode = stat.S_IFMT(info.external_attr >> 16)
                    if mode not in (0, stat.S_IFREG, stat.S_IFDIR) or info.flag_bits & 1:
                        raise ScanError("zip links, special files and encrypted entries are unsupported")
                    if info.is_dir():
                        continue
                    with archive.open(info) as stream:
                        data = stream.read(info.file_size + 1)
                    if len(data) != info.file_size:
                        raise ScanError("zip member size mismatch")
                    files[key] = data
        else:
            # Bound even PAX/GNU headers, padding and bytes after end-of-archive.
            # tarfile may consume those before yielding the next member.
            envelope = max_bytes + (max_files + 2) * 1024 + tarfile.RECORDSIZE
            opener = gzip.open if path.name.lower().endswith((".tar.gz", ".tgz")) else open
            with opener(path, "rb") as stream:
                raw = stream.read(envelope + 1)
            if len(raw) > envelope:
                raise ScanError("tar exceeds expanded stream limit")
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                for member in archive:
                    key = reserve(member.name, member.size, member.isdir())
                    if member.isdir():
                        continue
                    if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or member.sparse is not None:
                        raise ScanError("tar links, special files and sparse members are unsupported")
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ScanError("unreadable tar member")
                    with stream:
                        data = stream.read(member.size + 1)
                    if len(data) != member.size:
                        raise ScanError("tar member size mismatch")
                    files[key] = data
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, gzip.BadGzipFile, zlib.error,
            NotImplementedError, UnicodeDecodeError, ValueError) as exc:
        raise ScanError(f"invalid or unsupported {kind} archive") from exc

    if not files:
        raise ScanError(f"{kind} contains no files")
    if any(parent.as_posix() in files for name in names for parent in PurePosixPath(name).parents):
        raise ScanError(f"conflicting file and directory in {kind}")
    return files
