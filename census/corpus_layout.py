"""Paths shared by the collector, sharded scanner and provenance join."""
import os
from pathlib import Path
import re


def tree_path(digest):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError(f"invalid canonical tree digest {digest!r}")
    key = digest[7:]
    return Path(key[:2], key)


def buckets(packages):
    if packages.is_symlink():
        raise ValueError(f"expected a real packages directory: {packages}")
    found = []
    with os.scandir(packages) as entries:
        for entry in entries:
            if not re.fullmatch("[0-9a-f]{2}", entry.name) or not entry.is_dir(follow_symlinks=False):
                raise ValueError(f"expected hex buckets under {packages}; for a flat corpus, restore "
                                 "a copy of the checkpoint with a new --output-dir")
            found.append(Path(entry.path))
    return sorted(found)
