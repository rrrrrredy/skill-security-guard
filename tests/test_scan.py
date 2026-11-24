from __future__ import annotations

import importlib.util
import builtins
import hashlib
import io
import json
import gzip
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCAN_PATH = ROOT / "scripts" / "scan.py"
FIXTURES = ROOT / "tests" / "fixtures"

spec = importlib.util.spec_from_file_location("skill_security_scan", SCAN_PATH)
scanner = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = scanner
spec.loader.exec_module(scanner)


class ScanTests(unittest.TestCase):
    def test_safe_skill_rates_a(self):
        reports = scanner.scan_source(str(FIXTURES / "safe-skill"))

        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].rating, "A")
        self.assertEqual(reports[0].issues, [])
        report = reports[0].to_dict()
        self.assertEqual(report["schema_version"], "skill-security-scan.v1")
        self.assertEqual(report["scanner_version"], scanner.VERSION)
        self.assertTrue(report["complete"])
        self.assertEqual(report["ignored_rules"], [])
        content = scanner.collect_targets(str(FIXTURES / "safe-skill"))[0].content
        self.assertEqual(
            report["input_sha256"],
            "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest(),
        )

    def test_attestation_records_ignored_rules_in_stable_order(self):
        report = scanner.scan_source(
            str(FIXTURES / "high-risk-skill"),
            ignored_rules={"S2-EXFILTRATION", "P1-PROMPT-INJECTION"},
        )[0].to_dict()

        self.assertEqual(report["ignored_rules"], ["P1-PROMPT-INJECTION", "S2-EXFILTRATION"])
        self.assertTrue(report["complete"])

    def test_high_risk_skill_rates_f_and_reports_exfiltration(self):
        reports = scanner.scan_source(str(FIXTURES / "high-risk-skill"))
        rule_ids = {issue.rule_id for issue in reports[0].issues}

        self.assertEqual(reports[0].rating, "F")
        self.assertIn("P1-PROMPT-INJECTION", rule_ids)
        self.assertIn("S2-EXFILTRATION", rule_ids)
        self.assertIn("M4-REMOTE-SCRIPT-EXEC", rule_ids)

    def test_nonstandard_frontmatter_is_advisory_and_autofixable(self):
        reports = scanner.scan_source(str(FIXTURES / "nonstandard-frontmatter"))
        issues = reports[0].issues

        self.assertEqual(reports[0].rating, "B")
        self.assertEqual([issue.rule_id for issue in issues], ["F7-NONSTANDARD-FIELDS"])
        self.assertIs(issues[0].auto_fix, True)

    def test_folded_yaml_description_is_parsed_as_full_text(self):
        skill_text = """---
name: folded-description
description: >
  Use when reviewing a skill with a long multi-line trigger description.
  This should be parsed as one description, not as the literal greater-than marker.
---

# Folded Description

Do the task.
"""

        reports = scanner.scan_source(None, text=skill_text)
        rule_ids = {issue.rule_id for issue in reports[0].issues}

        self.assertNotIn("D6-SHORT-DESCRIPTION", rule_ids)
        self.assertNotIn("D6-MISSING-DESCRIPTION", rule_ids)

    def test_folded_yaml_description_falls_back_without_pyyaml(self):
        skill_text = """---
name: folded-description
description: >
  Use when reviewing a skill with a long multi-line trigger description.
  This should still be parsed when PyYAML is unavailable.
---

# Folded Description
"""
        original_import = builtins.__import__

        def import_without_yaml(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("no yaml")
            return original_import(name, *args, **kwargs)

        try:
            builtins.__import__ = import_without_yaml
            frontmatter = scanner.parse_frontmatter(skill_text)
        finally:
            builtins.__import__ = original_import

        self.assertEqual(frontmatter["name"], "folded-description")
        self.assertIn("long multi-line trigger description", frontmatter["description"])

    def test_write_stdout_uses_utf8_buffer_on_unicode_error(self):
        class NarrowStdout:
            def __init__(self):
                self.buffer = io.BytesIO()

            def write(self, text):
                raise UnicodeEncodeError("gbk", text, 0, 1, "blocked")

        original_stdout = scanner.sys.stdout
        fake_stdout = NarrowStdout()
        try:
            scanner.sys.stdout = fake_stdout
            scanner.write_stdout("报告 ✅")
        finally:
            scanner.sys.stdout = original_stdout

        self.assertEqual(fake_stdout.buffer.getvalue(), "报告 ✅\n".encode("utf-8"))

    def test_cli_stdin_is_strict_utf8_and_preserves_unicode_bytes(self):
        skill_text = """---
name: unicode-stdin
description: Scan a UTF-8 Skill containing punctuation from real optimizer output.
---

# Unicode stdin

Treat “whatever looks like cache” as an ambiguous target.
"""

        completed = subprocess.run(
            [sys.executable, str(SCAN_PATH), "-", "--format", "json"],
            input=skill_text.encode("utf-8"),
            capture_output=True,
            cwd=ROOT,
            check=False,
        )

        self.assertIn(completed.returncode, {0, 1}, completed.stderr.decode("utf-8", errors="replace"))
        reports = json.loads(completed.stdout.decode("utf-8"))
        self.assertEqual(len(reports), 1)
        self.assertEqual(
            reports[0]["input_sha256"],
            "sha256:" + hashlib.sha256(skill_text.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(reports[0]["scanner_version"], scanner.VERSION)

    def test_missing_file_is_a_clear_scan_error(self):
        missing = FIXTURES / "does-not-exist.md"

        with self.assertRaisesRegex(scanner.ScanError, "input does not exist"):
            scanner.collect_targets(str(missing))

    def test_zip_slip_entry_is_rejected(self):
        with tempfile_directory() as tmp_path:
            archive = tmp_path / "bad.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../evil/SKILL.md", "---\nname: bad\ndescription: bad\n---\n")

            with self.assertRaisesRegex(scanner.ScanError, "unsafe zip entry path"):
                scanner.collect_targets(str(archive))

    def test_zip_with_skill_is_scanned(self):
        with tempfile_directory() as tmp_path:
            archive = tmp_path / "safe.zip"
            skill_text = (FIXTURES / "safe-skill" / "SKILL.md").read_text(encoding="utf-8")
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("safe-skill/SKILL.md", skill_text)

            reports = scanner.scan_source(str(archive))

        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].rating, "A")


def cli(*args):
    return subprocess.run(
        [sys.executable, "-S", str(SCAN_PATH), *map(str, args)],
        cwd=ROOT, capture_output=True, timeout=30,
    )


class CensusTests(unittest.TestCase):
    def test_runtime_imports_and_documented_rules(self):
        import ast
        scripts = SCAN_PATH.parent
        defined = set()
        pattern = r"(?:[A-Z]\d-)[A-Z0-9]+(?:-[A-Z0-9]+)*"
        for path in scripts.rglob("*.py"):
            tree = ast.parse(path.read_bytes())
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if re.fullmatch(pattern, node.value):
                        defined.add(node.value)
                if isinstance(node, ast.Import):
                    modules = [item.name for item in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    modules = [node.module]
                else:
                    continue
                for module in modules:
                    self.assertIn(module.split(".")[0], sys.stdlib_module_names | {"skillscan"}, path)
        docs = (ROOT / "references/detection-rules.md").read_text(encoding="utf8")
        self.assertGreater(len(defined), 20)
        self.assertEqual(defined, set(re.findall(r"`(" + pattern + r")`", docs)))

    def test_real_files_and_python_aliases(self):
        benign = json.loads(cli(FIXTURES / "hard-benign", "--format", "json").stdout)[0]
        self.assertEqual((benign["rating"], benign["score"]), ("A", 100))
        alias = FIXTURES / "ast-alias" / "scripts" / "sample.py"
        for source in (alias, alias.parents[1]):
            report = json.loads(cli(source, "--format", "json").stdout)[0]
            hits = [(i["rule_id"], i["evidence"]["line"]) for i in report["issues"]]
            self.assertEqual([n for rule, n in hits if rule == "M4-DYNAMIC-EXECUTION"], [8])
            self.assertIn(("S2-NETWORK-SINK", 9), hits)

    def test_hidden_unicode_and_multiline_html_comment(self):
        report = json.loads(cli(FIXTURES / "hidden-text", "--format", "json").stdout)[0]
        hits = {i["rule_id"]: i["evidence"]["line"] for i in report["issues"]}
        self.assertEqual(hits["P1-ZERO-WIDTH"], 6)
        self.assertEqual(hits["P1-BIDI-CONTROL"], 7)
        self.assertEqual(hits["P1-HIDDEN-INSTRUCTION"], 9)
        self.assertEqual(sum(i["rule_id"] == "P1-HIDDEN-INSTRUCTION" for i in report["issues"]), 1)

    def test_zones_caps_and_script_chain(self):
        with tempfile_directory() as root:
            package = root / "pkg"
            shutil.copytree(FIXTURES / "safe-skill", package)
            skill = package / "SKILL.md"
            with skill.open("a", encoding="utf8") as out:
                out.write("\n~~~sh\n" + "eval 'true'\n" * 10 + "~~~\n")
            (package / "tests").mkdir()
            (package / "tests/sample.sh").write_text("eval 'true'\n", encoding="utf8")
            review = json.loads(cli(package, "--format", "json").stdout)[0]
            self.assertGreaterEqual(review["score"], 90)
            self.assertEqual(len([i for i in review["issues"] if i["rule_id"] == "M4-DYNAMIC-EXECUTION"]), 11)
            scripts = package / "scripts"
            scripts.mkdir()
            source = scripts / "audit.py"
            source.write_text(
                "from base64 import b64encode as encode\n"
                "def inspect_sample():\n"
                "    open('fixture/.ssh/example')\n"
                "    encode(b'public sample')\n"
                "def unrelated():\n"
                "    eval('1 + 1')\n", encoding="utf8")
            separate = json.loads(cli(package, "--format", "json").stdout)[0]
            self.assertNotIn("S2-SENSITIVE-CHAIN", [i["rule_id"] for i in separate["issues"]])
            source.write_text(source.read_text(encoding="utf8").replace("def unrelated():\n", ""), encoding="utf8")
            combined = json.loads(cli(package, "--format", "json").stdout)[0]
            self.assertEqual(combined["rating"], "F")
            self.assertIn("S2-SENSITIVE-CHAIN", [i["rule_id"] for i in combined["issues"] if i["direct_fail"]])

    def test_package_runners_and_host_write_targets(self):
        with tempfile_directory() as root:
            script = root / "sample.sh"
            script.write_text("\n".join([
                "npx -y demo", "uvx demo", "pipx run demo",
                "npx -y @scope/demo@1.2.3", "uvx --from demo==1.2.3 demo",
                "pipx run --spec demo==1.2.3 demo",
                "cat AGENTS.md", "cp AGENTS.md scratch.txt",
                "printf note >> CLAUDE.md", "touch .mcp.json", "cp sample AGENTS.md",
                "touch .claude/settings.json", "touch .codex/config.toml",
                "touch .cursor/rules/example", "touch .git/hooks/pre-commit",
            ]), encoding="utf8")
            issues = json.loads(cli(script, "--format", "json").stdout)[0]["issues"]
            def lines(rule):
                return {i["evidence"]["line"] for i in issues if i["rule_id"] == rule}
            self.assertEqual(lines("D5-UNPINNED-RUNNER"), {1, 2, 3})
            self.assertEqual(lines("M4-HOST-CONFIG-WRITE"), set(range(9, 16)))

    def test_equivalent_tree_hashes_context_and_raw_bytes(self):
        with tempfile_directory() as root:
            package = root / "pkg"
            shutil.copytree(FIXTURES / "ast-alias", package)
            script = package / "scripts/sample.py"
            script.write_bytes(b"# api_key = 'fixture-secret-material'\n" + script.read_bytes()
                               + b"# Authorization: Bearer fixture-bearer-value\n# end\n# eof\n")
            (package / "notes.bin").write_bytes(b"\xff")
            archive = root / "pkg.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                for file in sorted(package.rglob("*"), reverse=True):
                    if file.is_file():
                        zf.write(file, "wrapper/" + file.relative_to(package).as_posix())
            tgz = root / "pkg.tgz"
            with tarfile.open(tgz, "w:gz") as tf:
                tf.add(package, "another-wrapper")
            records = [json.loads(cli(path, "--extract-intent-context", "--format", "jsonl").stdout)
                       for path in (package, archive, tgz)]
            self.assertEqual(len({r["canonical_tree_sha256"] for r in records}), 1)
            self.assertEqual(records[0]["declared_intent"]["name"], "syntax-fixture")
            record = records[0]
            sink = next(i for i in record["issues"] if i["rule_id"] == "S2-NETWORK-SINK")
            self.assertEqual(sink["evidence"]["file"], "scripts/sample.py")
            self.assertEqual([line["line"] for line in sink["context"]], list(range(7, 14)))
            self.assertNotIn("fixture-bearer-value", json.dumps(record))
            (package / "notes.bin").write_bytes(b"\xfe")
            self.assertNotEqual(json.loads(cli(package, "--format", "jsonl").stdout)["canonical_tree_sha256"],
                                record["canonical_tree_sha256"])

    def test_batch_order_failures_and_output(self):
        with tempfile_directory() as root:
            collection = root / "collection"
            collection.mkdir()
            shutil.copytree(FIXTURES / "safe-skill", collection / "a-safe")
            (collection / "b-invalid.tar").write_bytes(b"invalid tar")
            shutil.copytree(FIXTURES / "high-risk-skill", collection / "c-high")
            results = []
            for workers in (1, 3):
                output = root / f"results-{workers}.jsonl"
                result = cli("--batch-dir", collection, "--workers", workers, "--output", output)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, b"")
                results.append(output.read_bytes())
            self.assertEqual(results[0], results[1])
            records = [json.loads(line) for line in results[0].splitlines()]
            self.assertEqual([r["source"] for r in records], ["a-safe", "b-invalid.tar", "c-high"])
            self.assertEqual([r["complete"] for r in records], [True, False, True])
            self.assertEqual([r.get("rating") for r in records], ["A", None, "F"])

    def test_archive_paths_links_and_expansion_budget(self):
        with tempfile_directory() as root:
            for kind in ("zip", "tar"):
                archive = root / f"fixture.{kind}"
                for name in ("../outside", "/absolute", "C:/outside", r"..\outside", "//host/share"):
                    if kind == "zip":
                        with zipfile.ZipFile(archive, "w") as zf:
                            zf.writestr(name, b"")
                    else:
                        with tarfile.open(archive, "w") as tf:
                            tf.addfile(tarfile.TarInfo(name))
                    self.assertEqual(cli(archive).returncode, 2, name)
            link = zipfile.ZipInfo("leaf")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(root / "link.zip", "w") as zf:
                zf.writestr(link, "outside")
            self.assertEqual(cli(root / "link.zip").returncode, 2)
            with tarfile.open(root / "link.tar", "w") as tf:
                link = tarfile.TarInfo("leaf")
                link.type = tarfile.LNKTYPE
                link.linkname = "outside"
                tf.addfile(link)
            self.assertEqual(cli(root / "link.tar").returncode, 2)
            with zipfile.ZipFile(root / "size.zip", "w", zipfile.ZIP_DEFLATED) as zf:
                for name in ("first", "second"):
                    zf.writestr(name, b"x" * 800)
            self.assertEqual(cli(root / "size.zip", "--max-zip-bytes", "1024").returncode, 2)
            tarball = root / "size.tgz"
            with tarfile.open(tarball, "w:gz") as tf:
                for name in ("first", "second"):
                    item = tarfile.TarInfo(name)
                    item.size = 800
                    tf.addfile(item, io.BytesIO(b"x" * 800))
            self.assertEqual(cli(tarball, "--max-zip-bytes", "1024").returncode, 2)
            padded = root / "padding.tgz"
            padded.write_bytes(gzip.compress(b"\0" * 65536))
            self.assertEqual(cli(padded, "--max-zip-bytes", "1024", "--max-zip-files", "2").returncode, 2)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink semantics")
    def test_symlink_cannot_cross_individual_skill_root(self):
        with tempfile_directory() as root:
            skill = root / "skill"
            shutil.copytree(FIXTURES / "safe-skill", skill)
            (skill / "scripts").mkdir()
            outside = root / "sibling.py"
            outside.write_text("print('external marker')", encoding="utf8")
            (skill / "scripts/linked.py").symlink_to(outside)
            result = cli(root)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b"symlink", result.stderr)
            self.assertNotIn(b"external marker", result.stdout + result.stderr)

    def test_invalid_bytes_and_long_lines_do_not_hide_later_lines(self):
        with tempfile_directory() as root:
            script = root / "sample.sh"
            script.write_bytes(b"# \xff\n" + b"x" * 200000 + b"\neval true\n")
            result = cli(script, "--format", "jsonl")
            report = json.loads(result.stdout)
            matches = {i["rule_id"]: i["evidence"]["line"] for i in report["issues"]}
            self.assertEqual(matches["M4-LINE-LIMIT"], 2)
            self.assertEqual(matches["M4-DYNAMIC-EXECUTION"], 3)
            self.assertLess(len(result.stdout), 12000)


class tempfile_directory:
    def __enter__(self):
        import tempfile

        self._manager = tempfile.TemporaryDirectory()
        return Path(self._manager.__enter__())

    def __exit__(self, exc_type, exc, tb):
        return self._manager.__exit__(exc_type, exc, tb)


if __name__ == "__main__":
    unittest.main()
