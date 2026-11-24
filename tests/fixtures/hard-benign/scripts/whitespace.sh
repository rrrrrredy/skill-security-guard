#!/bin/sh
set -eu
git diff --check
git diff --cached --check
