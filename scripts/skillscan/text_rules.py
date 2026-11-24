"""Bounded text, shell and Markdown rules."""
from __future__ import annotations

import re
import shlex
import unicodedata


PROMPT = re.compile(r"ignore (?:all )?previous instructions|忽略之前所有指令|you are now dan|没有限制的ai|system prompt.*(?:updated|更新)", re.I)
OVERRIDE = re.compile(r"覆盖之前.*安全规则|override.*safety rules", re.I)
INSTRUCTION = re.compile(r"\b(?:you must|always|never|please|run|execute|upload|send|invoke|read|write|install|ignore|override|follow these)\b|忽略|执行|运行|上传|读取|遵循|必须", re.I)
SENSITIVE = re.compile(r"(?:^|[/~\\])\.(?:ssh|aws)(?:[/\\]|$)|/root/\.openclaw\b|\b(?:openclaw|paired|device-auth)\.json\b|\b(?:soul|memory|user)\.md\b", re.I)
HOST = re.compile(r"(?:^|[/\\])(?:\.mcp\.json|CLAUDE\.md|AGENTS\.md|(?:\.claude|\.codex|\.cursor)(?:[/\\].*)?|\.git[/\\]hooks(?:[/\\].*)?)$", re.I)
ENCODING = re.compile(r"\b(?:base64|xxd\s+-[pr]|openssl\s+(?:base64|enc))\b", re.I)
UPLOAD = re.compile(r"\b(?:curl\b.*(?:--data(?:-\w+)?\b|--json\b|--form\b|--upload-file\b|-[dFT](?:\s|@))|wget\b.*--post-(?:data|file)|scp\b|nc\b)", re.I)
SHELL_SINK = re.compile(r"\b(?:eval|exec)\s+|\|\s*(?:ba)?sh\b", re.I)

LINE_RULES = {
    "P1-PROMPT-INJECTION": PROMPT,
    "P1-SAFETY-OVERRIDE": OVERRIDE,
    "R3-N1": re.compile(r"\b(?:ngrok|localtunnel|cloudflared\s+tunnel|bore|frpc?|frps)\b", re.I),
    "R3-N2": re.compile(r"(?:\bhr\b|\bokr\b|performance|绩效|人才|人事).*(?:internal|corp|内网|内部|系统)", re.I),
    "R3-N3": re.compile(r"(?:\bc4\b|绝密|内部高密).*(?:input|upload|paste|输入|上传|粘贴|处理)", re.I),
    "R3-N4": re.compile(r"(?:\b(?:cp|tar|zip|upload|curl)\b|备份|上传).*(?:openclaw|device|device-auth)\.json", re.I),
    "M4-DESTRUCTIVE-COMMAND": re.compile(r"\brm\s+-rf\s+/(?:\s|$)|\brm\s+-rf\s+~|\bdd\s+if=/dev/zero", re.I),
    "M4-REMOTE-SCRIPT-EXEC": re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:bash|sh)\b", re.I),
    "M4-REVERSE-SHELL": re.compile(r"\bbash\s+-i.*(?:/dev/tcp|>&)|\bnc\s+-e\s+(?:/bin/)?(?:bash|sh)\b", re.I),
    "M4-PRIVILEGED-OR-MINING": re.compile(r"\bsudo\s+su\b|\bchmod\s+777\s+/etc|\bxmrig\b|\bminerd\b|\.mining\b", re.I),
    "M4-DYNAMIC-EXECUTION": re.compile(r"\beval\b|(?<![\w.])exec\(|\bchild_process\.exec\(", re.I),
    "D5-PIP-UNTRUSTED-SOURCE": re.compile(r"\bpip\s+install\b.*(?:--(?:extra-)?index-url|https?://|git\+)", re.I),
    "D5-NPM-UNTRUSTED-SOURCE": re.compile(r"\bnpm\s+install\b.*(?:https?://|git\+|--registry)", re.I),
    "D5-TYPOSQUATTING": re.compile(r"\b(?:requets|reqeusts|lodahs|expres)\b", re.I),
}

RUNNER = re.compile(r"\b(?:npx|uvx|pipx)\b", re.I)
PINNED = re.compile(r"(?:@|==)\d+(?:\.\d+)+(?:[-+.]?[a-z][\w.-]*)?(?:\+[a-z0-9.-]+)?$", re.I)


def unpinned(words: list[str]) -> bool:
    tool, *args = words
    if tool == "npx" and not any(flag in args for flag in ("-y", "--yes")):
        return False
    if tool == "pipx":
        if not args or args[0] != "run":
            return False
        args = args[1:]
    for i, word in enumerate(args):
        if word in ("--from", "--spec", "--package", "-p") and i + 1 < len(args):
            return not PINNED.search(args[i + 1])
        if word.startswith(("--from=", "--spec=", "--package=")):
            return not PINNED.search(word.split("=", 1)[1])
        if not word.startswith("-"):
            return not PINNED.search(word)
    return False


def shell_rules(line: str) -> set[str]:
    ids = set()
    if not (RUNNER.search(line) or any(s in line.lower() for s in (
        ".md", ".json", ".claude", ".codex", ".cursor", "hooks", "hookspath"
    ))):
        return ids
    lexer = shlex.shlex(line, posix=True, punctuation_chars="|;&<>")
    lexer.whitespace_split = True
    lexer.escape = ""
    try:
        words = list(lexer)
    except ValueError:
        return ids
    group = []
    for word in [*words, ";"]:
        if word not in {"|", "||", "&&", ";", "&"}:
            group.append(word)
            continue
        if group:
            command_rules(group, ids)
            group = []
    return ids


def command_rules(words: list[str], ids: set[str]) -> None:
    for index, word in enumerate(words):
        if word in ("npx", "uvx", "pipx") and unpinned(words[index:]):
            ids.add("D5-UNPINNED-RUNNER")
        if word in (">", ">>") and index + 1 < len(words) and HOST.search(words[index + 1]):
            ids.add("M4-HOST-CONFIG-WRITE")
    cmd, *args = words
    cmd = cmd.lower()
    paths = [arg for arg in args if not arg.startswith("-")]
    if cmd in {"cp", "mv", "install", "copy-item", "move-item"}:
        paths = paths[-1:]
    elif cmd == "git" and "config" in args and "core.hookspath" in (arg.lower() for arg in args):
        if len(paths) > 2:
            ids.add("M4-HOST-CONFIG-WRITE")
        return
    elif cmd not in {"tee", "touch", "mkdir", "rm", "chmod", "set-content", "add-content",
                     "new-item", "out-file", "remove-item"}:
        return
    if any(HOST.search(arg) for arg in paths):
        ids.add("M4-HOST-CONFIG-WRITE")


def line_rules(line: str) -> set[str]:
    ids = {rule for rule, pattern in LINE_RULES.items() if pattern.search(line)}
    if SENSITIVE.search(line):
        if re.search(r"\b(?:cat|cp|scp|tar|zip|open|read_file|readfile)\b", line, re.I):
            ids.add("S2-SENSITIVE-READ")
        if UPLOAD.search(line):
            ids.add("S2-EXFILTRATION")
    ids.update(shell_rules(line.strip()))
    return ids


def unicode_rules(line: str) -> set[str]:
    ids = set()
    for char in line:
        if ord(char) < 128 or unicodedata.category(char) != "Cf":
            continue
        if unicodedata.bidirectional(char) in {"RLO", "LRO", "RLE", "LRE", "PDF", "LRI", "RLI", "FSI", "PDI"} or char in "\u061c\u200e\u200f":
            ids.add("P1-BIDI-CONTROL")
        elif char in "\u00ad\u180e\u200b\u200c\u200d\u2060\ufeff":
            ids.add("P1-ZERO-WIDTH")
    return ids


def hidden_comment(line: str, opened: bool) -> tuple[bool, bool]:
    found = False
    while line:
        if not opened:
            _, start, line = line.partition("<!--")
            if not start:
                break
            opened = True
        content, end, line = line.partition("-->")
        found |= bool(INSTRUCTION.search(content) or PROMPT.search(content) or OVERRIDE.search(content))
        opened = not bool(end)
    return opened, found


def parse_frontmatter(text: str) -> dict[str, str]:
    lines = iter(text.splitlines())
    if next(lines, "").lstrip("\ufeff").strip() != "---":
        return {}
    values = {}
    block_key = None
    for line in lines:
        if line.strip() == "---":
            break
        if block_key and (not line.strip() or line[:1].isspace()):
            if line.strip():
                values[block_key] += (separator if values[block_key] else "") + line.strip()
            continue
        match = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        block_key = None
        if match:
            key, value = match[1].lower(), match[2].strip()
            if value in {">", ">-", ">+", "|", "|-", "|+"}:
                block_key, separator = key, ("\n" if value.startswith("|") else " ")
                values[key] = ""
            else:
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                values[key] = value.strip()
    return values
