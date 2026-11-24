#!/bin/sh
set -eu
git diff --check
git diff --cached --check
git ls-files -- AGENTS.md CLAUDE.md .mcp.json .claude/ .codex/ .cursor/
git config --get core.hooksPath || test "$?" -eq 1
