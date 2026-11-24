"""CI-only Draft 2020-12 validation against records from the public CLI."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


def validator(version):
    schema = json.loads((ROOT / "schemas" / f"skill-security-scan.{version}.schema.json").read_bytes())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def scan(*args, expected):
    run = subprocess.run([sys.executable, "-S", str(ROOT / "scripts/scan.py"), *map(str, args)],
                         capture_output=True, check=False)
    if run.returncode != expected:
        raise RuntimeError(f"CLI returned {run.returncode}: {run.stderr.decode(errors='replace')}")
    return run.stdout


def main():
    v1, census = validator("v1"), validator("v2-census")
    fixtures = ROOT / "tests/fixtures"
    for skill in sorted(fixtures.iterdir()):
        result = subprocess.run([sys.executable, "-S", str(ROOT / "scripts/scan.py"),
                                 str(skill), "--format", "json"], capture_output=True)
        if result.returncode not in (0, 1):
            raise RuntimeError(result.stderr)
        [report] = json.loads(result.stdout)
        v1.validate(report)
    with tempfile.TemporaryDirectory() as scratch:
        # Include an actual refused package and a successful scan in the same stream.
        root = Path(scratch)
        (root / "broken.tar").write_bytes(b"not a tar")
        (root / "skill").mkdir()
        (root / "skill/SKILL.md").write_bytes((fixtures / "hidden-text/SKILL.md").read_bytes())
        rows = scan("--batch-dir", root, "--workers", 2, expected=2).splitlines()
        assert len(rows) == 2
        for row in rows:
            census.validate(json.loads(row))


if __name__ == "__main__":
    main()
