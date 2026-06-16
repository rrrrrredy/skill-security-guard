from __future__ import annotations

import importlib.util
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
