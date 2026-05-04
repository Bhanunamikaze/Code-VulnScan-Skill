# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (main) | ✅ Yes |
| older releases | ❌ No — please upgrade |

## Scope

This repository contains a **security scanning skill** — static analysis patterns, scripts, and AI agent instructions. The scope of this policy covers:

**In scope:**
- Vulnerabilities in the Python scripts (`scripts/`) that could allow code execution, path traversal, or information disclosure when scanning untrusted codebases
- False negatives in critical vulnerability patterns (e.g. SQLi, CMDi) that would cause dangerous code to be classified as safe
- Supply-chain risks in `requirements.txt` dependencies
- Install scripts (`install.sh`, `install.ps1`) that write to unintended locations

**Out of scope:**
- Intentionally vulnerable test fixtures in `tests/fixtures/` — these contain real vulnerability patterns by design
- False positives (missed detections are tracked in `docs/tasks.md`, not as security issues)
- Vulnerabilities in IDEs or AI assistants that consume this skill

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately to: **bhanu.chintalapudi@newfold.com**

Please include:
1. A description of the vulnerability and its potential impact
2. Steps to reproduce (proof-of-concept script or command sequence)
3. Affected files and line numbers
4. Suggested fix if you have one

### What to expect

| Timeframe | Action |
|-----------|--------|
| 48 hours | Acknowledgement of your report |
| 7 days | Initial triage and severity assessment |
| 30 days | Fix published (critical/high severity) |
| 90 days | Fix published (medium/low severity) |

After a fix is released, you will be credited in the release notes unless you prefer to remain anonymous.

## Known Security Considerations for Operators

### Scanning untrusted code

`scan.py` and `taint.py` parse and analyze source files from a target directory. They do **not** execute the target code. However:

- Regex patterns are compiled at runtime — malformed pattern files could cause `re.error` exceptions (not exploitable)
- `dependency.py` reads manifest files — crafted manifests with extremely long lines could cause memory pressure
- `secrets.py --git-history` runs `git log` as a subprocess — ensure the scanned directory is not a symlink to a privileged git repo

### Install scripts

`install.sh` and `install.ps1` write files into your project directory and home directory. Review them before running with elevated privileges. The `--online` flag downloads from GitHub releases — verify the SHA-256 checksum before running.

### Hardcoded test secrets

The files `tests/fixtures/vuln_python.py`, `tests/fixtures/vuln_javascript.js`, and `tests/fixtures/vuln_go.go` contain fake API keys and passwords for testing the secret detector. These are intentionally included and are not real credentials.

## CVE Reporting for Detected Vulnerabilities

If you discover that a CVE entry in `scripts/dependency.py` has an incorrect version range (causing either false positives or false negatives), please open a regular GitHub issue with the label `cve-data` rather than a security report. Incorrect version ranges in a scanner are a data quality issue, not a security vulnerability in the scanner itself.
