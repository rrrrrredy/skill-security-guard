from __future__ import annotations

import importlib.util
import builtins
import io
import sys
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


class tempfile_directory:
    def __enter__(self):
        import tempfile

        self._manager = tempfile.TemporaryDirectory()
        return Path(self._manager.__enter__())

    def __exit__(self, exc_type, exc, tb):
        return self._manager.__exit__(exc_type, exc, tb)


if __name__ == "__main__":
    unittest.main()
