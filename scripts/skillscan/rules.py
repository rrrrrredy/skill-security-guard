"""The public rule IDs and their production-zone findings."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    dimension: str
    title: str
    suggestion: str
    severity: str = "medium"
    confidence: str = "confirmed"
    penalty: int = 30
    direct_fail: bool = False
    auto_fix: bool = False


def high(dimension, title, suggestion, confidence="confirmed"):
    return Rule(dimension, title, suggestion, "high", confidence, 100, True)


def advisory(dimension, title, suggestion, auto_fix=False):
    return Rule(dimension, title, suggestion, "low", "advisory", 5, auto_fix=auto_fix)


def probable(dimension, title, suggestion):
    return Rule(dimension, title, suggestion, confidence="probable", penalty=15)


RULES = {
    "P1-PROMPT-INJECTION": Rule("prompt-injection", "Instruction override detected",
                                "Remove role and instruction overrides."),
    "P1-SAFETY-OVERRIDE": probable("prompt-injection", "Possible safety-rule override",
                                   "Keep higher-priority instructions authoritative."),
    "P1-ZERO-WIDTH": advisory("prompt-injection", "Invisible formatting character",
                              "Inspect the marked text and use visible spelling in commands."),
    "P1-BIDI-CONTROL": probable("prompt-injection", "Bidirectional display control",
                                "Inspect the logical order and remove unexpected direction controls."),
    "P1-HIDDEN-INSTRUCTION": Rule("prompt-injection", "Instruction in an HTML comment",
                                  "Move intended instructions into visible prose for review."),
    "S2-SENSITIVE-READ": Rule("sensitive-data", "Sensitive file read pattern detected",
                              "Limit access to credentials, identity and private memory files."),
    "S2-EXFILTRATION": high("sensitive-data", "Sensitive file passed to a network command",
                            "Keep private files out of network transfers."),
    "S2-NETWORK-SINK": advisory("sensitive-data", "Outbound data operation",
                                "Review the destination and the data passed to this call."),
    "S2-SENSITIVE-CHAIN": high("sensitive-data", "Sensitive read, encoding and outbound or execution sink",
                               "Inspect the related operations and constrain the data flow.", "probable"),
    "R3-N1": high("compliance", "Tunneling tool usage detected", "Review and remove unapproved tunnels."),
    "R3-N2": high("compliance", "Restricted HR/OKR system access detected", "Remove restricted system access."),
    "R3-N3": high("compliance", "High-sensitivity data handling detected",
                  "Exclude highly sensitive data from the skill.", "probable"),
    "R3-N4": high("compliance", "Sensitive config backup or upload pattern detected",
                  "Do not copy private device or authentication configuration."),
    "R3-N5": Rule("description", "Description trigger scope appears over-broad",
                  "Narrow the trigger to the skill's purpose.", confidence="probable", penalty=10, auto_fix=True),
    "M4-DESTRUCTIVE-COMMAND": high("malicious-script", "Destructive command detected",
                                   "Remove destructive commands."),
    "M4-REMOTE-SCRIPT-EXEC": high("malicious-script", "Remote script execution detected",
                                  "Verify artifacts before execution."),
    "M4-REVERSE-SHELL": high("malicious-script", "Reverse shell pattern detected",
                             "Remove reverse shell behavior."),
    "M4-PRIVILEGED-OR-MINING": high("malicious-script", "Privileged shell or mining behavior detected",
                                    "Remove privilege escalation or mining behavior."),
    "M4-DYNAMIC-EXECUTION": probable("malicious-script", "Dynamic execution detected",
                                     "Use a fixed command with explicit arguments."),
    "M4-HOST-CONFIG-WRITE": probable("malicious-script", "Write to host instructions, config or Git hooks",
                                     "Review the destination and require an explicit change request."),
    "M4-LINE-LIMIT": advisory("malicious-script", "Line exceeds the analysis limit",
                              "Inspect the full line in the original file."),
    "M4-PYTHON-PARSE": probable("malicious-script", "Python syntax could not be fully analyzed",
                                "Inspect the indicated source and verify its encoding and syntax."),
    "D5-PIP-UNTRUSTED-SOURCE": advisory("dependency", "pip install uses a non-default source",
                                        "Pin dependencies and verify the package source."),
    "D5-NPM-UNTRUSTED-SOURCE": advisory("dependency", "npm install uses a non-default source",
                                        "Pin dependencies and verify the package source."),
    "D5-TYPOSQUATTING": advisory("dependency", "Possible typosquatted dependency name",
                                 "Check the package name against its intended source."),
    "D5-UNPINNED-RUNNER": probable("dependency", "Remote package runner without an exact version",
                                   "Pin the package to an exact version before execution."),
    "D6-MISSING-DESCRIPTION": Rule("description", "Description is missing", "Add a bounded trigger description."),
    "D6-SHORT-DESCRIPTION": Rule("description", "Description is too short", "Describe the intended scope and trigger."),
    "F7-MISSING-FRONTMATTER": Rule("frontmatter", "SKILL.md is missing YAML frontmatter",
                                   "Add frontmatter with name and description."),
    "F7-NONSTANDARD-FIELDS": advisory("frontmatter", "Non-standard frontmatter fields",
                                     "Keep only name and description unless the runtime requires more.", True),
    "F7-MISSING-NAME": Rule("frontmatter", "Missing required frontmatter field: name", "Add a name."),
    "F7-MISSING-DESCRIPTION": Rule("frontmatter", "Missing required frontmatter field: description",
                                   "Add a description."),
}
