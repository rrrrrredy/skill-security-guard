# Contributing

Thanks for helping improve `skill-security-guard`.

## Local Setup

The scanner uses only the Python standard library.

```bash
git clone https://github.com/rrrrrredy/skill-security-guard.git
cd skill-security-guard
python -m unittest discover -s tests -p "test_*.py"
```

## Rule Changes

When adding or changing detection rules:

1. Add or update a fixture under `tests/fixtures/`.
2. Add an assertion in `tests/test_scan.py`.
3. Update `references/detection-rules.md`.
4. Run `python scripts/scan.py .` and confirm the repository still rates `A`.

Rules should be conservative. Direct `F` findings should be limited to patterns that are clearly dangerous, such as exfiltration, tunneling, destructive commands, reverse shells, or remote script execution.

## Pull Requests

Please keep pull requests focused. Good PRs usually include:

- a clear rule or scanner behavior change
- a fixture showing the expected behavior
- updated documentation when scoring or output changes
- local test results
