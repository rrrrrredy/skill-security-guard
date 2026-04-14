#!/bin/bash
# skill-security-guard: 静态扫描入口脚本
# 用法: bash scan.sh <skill.md 文件路径或 zip 包路径>
# 实际扫描由 Claude agent 根据 SKILL.md 中的 7 大维度执行
# 此脚本用于从命令行预解析输入文件
set -euo pipefail

INPUT="${1:-}"
if [ -z "$INPUT" ]; then
  echo "用法: bash scan.sh <skill.md 或 .zip 路径>"
  exit 1
fi

if [[ "$INPUT" == *.zip ]]; then
  TMPDIR=$(mktemp -d /tmp/skill-scan-XXXXXX)
  unzip -q "$INPUT" -d "$TMPDIR" || python3 -m zipfile -e "$INPUT" "$TMPDIR"
  echo "解压到: $TMPDIR"
  find "$TMPDIR" -name "SKILL.md" | sort
else
  echo "输入文件: $INPUT"
  wc -l "$INPUT"
fi
