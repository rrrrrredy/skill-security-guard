"""Read-only GitHub REST client for public code search and pinned repository archives."""
from __future__ import annotations

from contextlib import contextmanager
from email.utils import parsedate_to_datetime
import json
from pathlib import Path
import re
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from zipfile import ZipFile

REPO = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+\Z")


def repository_name(value):
    if not isinstance(value, str) or not REPO.fullmatch(value) or value.split("/")[1] in {".", ".."}:
        raise ValueError(f"invalid GitHub repository name: {value!r}")
    return value


class GitHub:
    def __init__(self, base_url="https://api.github.com", token=None, *, sleep=time.sleep, now=time.time):
        self.base = base_url.rstrip("/")
        self.token = token
        self.sleep = sleep
        self.now = now
        self.available = {}

    def _wait(self, until):
        delay = until - self.now()
        if delay > 0:
            self.sleep(delay)

    def _open(self, path, params=None):
        bucket = "code_search" if path == "/search/code" else "core"
        self._wait(self.available.get(bucket, 0))
        url = self.base + path + ("?" + urlencode(params) if params else "")
        request = Request(url, headers={"Accept": "application/vnd.github+json",
                                        "User-Agent": "skill-security-guard-census/5.3.0",
                                        "X-GitHub-Api-Version": "2022-11-28"})
        # GitHub redirects zipball downloads to codeload. Never forward the bearer token.
        if self.token:
            request.add_unredirected_header("Authorization", "Bearer " + self.token)
        for attempt in range(6):
            try:
                response = urlopen(request, timeout=90)
            except HTTPError as exc:
                if exc.code not in (403, 429) or attempt == 5:
                    raise
                with exc:
                    message = exc.read(8192).decode("utf-8", "replace").lower()
                h = exc.headers
                exhausted = h.get("X-RateLimit-Remaining") == "0"
                retry = h.get("Retry-After")
                if exc.code == 403 and not (exhausted or retry or "rate limit" in message or "abuse detection" in message):
                    raise
                now = self.now()
                if retry is not None:
                    until = now + int(retry) if retry.strip().isdigit() else parsedate_to_datetime(retry).timestamp()
                elif exhausted and h.get("X-RateLimit-Reset"):
                    until = now
                else:
                    until = now + 60 * 2**attempt
                if exhausted and h.get("X-RateLimit-Reset"):
                    until = max(until, float(h["X-RateLimit-Reset"]) + 1)
                self._wait(until)
                continue
            if response.headers.get("X-RateLimit-Remaining") == "0":
                reset = response.headers.get("X-RateLimit-Reset")
                self.available[bucket] = float(reset) + 1 if reset else self.now() + 60
            return response

    def json(self, path, params=None):
        with self._open(path, params) as response:
            return json.load(response)

    @contextmanager
    def archive(self, repo: str, sha: str, scratch: Path):
        # GitHub supplies the ZIP wrapper. Spool the repository once, independently of skill count.
        with tempfile.TemporaryFile(dir=scratch) as spool:
            with self._open(f"/repos/{repo}/zipball/{sha}") as response:
                copied = 0
                while chunk := response.read(1024 * 1024):
                    spool.write(chunk)
                    copied += len(chunk)
                length = response.headers.get("Content-Length")
                if length is not None and copied != int(length):
                    raise OSError("incomplete repository archive download")
            spool.seek(0)
            with ZipFile(spool) as archive:
                yield archive
