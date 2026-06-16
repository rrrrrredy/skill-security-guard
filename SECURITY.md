# Security Policy

## Reporting a Vulnerability

Please do not open a public issue for a vulnerability that could help attackers abuse skill packages.

Report security issues through GitHub private vulnerability reporting if it is available on this repository. If private reporting is unavailable, open a minimal public issue that says a security report is available without including exploit details.

Useful report details include:

- affected rule or input path
- sample input that triggers the issue
- expected vs actual scanner behavior
- whether the issue causes a false negative, false positive, crash, or unsafe extraction

## Scope

In scope:

- unsafe zip handling
- false negatives for high-risk patterns
- crashes on reasonable skill inputs
- output that could mislead users into installing a clearly unsafe skill

Out of scope:

- requests to classify organization-specific policy without sample rules
- runtime behavior of third-party skills after installation
- vulnerabilities in external tools that are not bundled by this project
