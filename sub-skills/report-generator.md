# report-generator

Read this when generating the final vulnerability report.

## Goal

Produce a clear, actionable security report that developers and security teams can use immediately. The report must tell readers: what is wrong, where it is, how bad it is, and exactly how to fix it.

## Report structure

### Executive summary

Lead with three numbers:
- Critical findings: N
- High findings: N
- Medium findings: N (+ Low: N, Informational: N)

Follow with 2–3 sentences on the most significant risk: the top finding and its potential impact in plain language.

### Finding sections

Each finding gets its own section with:

```
## [SEVERITY] Finding Title

**File:** relative/path/to/file.py:42
**CWE:** CWE-89 — SQL Injection
**OWASP:** A03:2021 — Injection
**CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Confidence:** Confirmed

### Description

[What the vulnerability is. 2–3 sentences max. No jargon without explanation.]

### Evidence

```python
# File: app/routes/search.py, line 42
query = f"SELECT * FROM items WHERE name = '{user_input}'"
cursor.execute(query)
```

### Taint Path

1. `user_input = request.args.get('q')` — line 38, HTTP GET parameter (SOURCE)
2. `query = f"SELECT ... '{user_input}'"` — line 42, unsanitized interpolation (PROPAGATION)
3. `cursor.execute(query)` — line 43, raw SQL execution (SINK)

### Impact

[What an attacker can do if this is exploited. Concrete, specific — not "may lead to unauthorized access".]

### Remediation

[Exact fix with code example in the same language as the vulnerable code.]

```python
# Fix: use parameterized query
cursor.execute("SELECT * FROM items WHERE name = %s", (user_input,))
```
```

## Report quality rules

### Writing rules

- Write `an attacker can read all database records` — not `this may result in unauthorized data access`
- Write `line 42 in app/routes/search.py` — not `in the search functionality`
- Write the exact fix in the same language as the vulnerable code
- Write the taint path as numbered steps — do not just describe it in prose
- Use severity labels: Critical / High / Medium / Low / Informational — never "very high" or "moderate"

### Code snippets

- Include the exact vulnerable code, not paraphrased
- Show the surrounding context (2–3 lines before and after)
- Include the fix in the same snippet style, same language
- Mark sensitive values (credentials found): show masked version, not the real value

### Severity labels in headings

Use emoji-free prefixes for immediate visual scanning:

```
## [CRITICAL] SQL Injection in login endpoint
## [HIGH] IDOR — document retrieval without ownership check
## [MEDIUM] Missing rate limiting on password reset
## [LOW] Username enumeration via differential error messages
## [INFO] HTTP security header missing: X-Content-Type-Options
```

### Grouping

Group findings by severity descending. Within each severity, group by category:
- Injection (SQL, Command, Path, XSS, SSRF, SSTI, XXE)
- Access Control (Auth bypass, IDOR, privilege escalation)
- Cryptography and Secrets
- Business Logic
- Configuration
- Dependencies
- Informational

## SARIF output

When `--format sarif` is requested, generate valid SARIF 2.1.0 JSON. Key fields:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Code-VulnScan",
        "version": "1.0.0",
        "rules": [/* one entry per unique finding type with CWE + description */]
      }
    },
    "results": [/* one entry per confirmed finding */]
  }]
}
```

SARIF output enables direct integration with GitHub Advanced Security, VS Code Security extensions, and CI/CD pipelines.

## JSON output

When `--format json`, output a structured summary:

```json
{
  "scan_id": "...",
  "target": "/path/to/codebase",
  "timestamp": "2024-01-15T10:30:00Z",
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 3,
    "informational": 4,
    "total": 22
  },
  "findings": [...]
}
```

## Dependency finding format

Dependency findings get a separate section:

```
## Dependency Vulnerabilities

| Package | Current | Safe Version | CVE | Severity | Exploitable |
|---------|---------|-------------|-----|---------|------------|
| log4j-core | 2.14.1 | 2.17.1 | CVE-2021-44228 | Critical | Yes |
| lodash | 4.17.20 | 4.17.21 | CVE-2021-23337 | High | Yes |
```

## Remediation priority matrix

End the report with a prioritized remediation checklist:

```
### Immediate Action Required (Critical)
- [ ] Fix SQL injection in app/routes/search.py:42
- [ ] Rotate exposed AWS key in config/production.py:8

### Fix Within 1 Sprint (High)
- [ ] Add authorization check to GET /api/documents/:id
- [ ] Upgrade log4j-core to 2.17.1

### Fix Within This Quarter (Medium)
- [ ] Add rate limiting to /auth/login and /auth/reset-password
- [ ] Replace MD5 password hashing with bcrypt
```

## What not to include

- Do not include findings that did not pass the false-positive filter
- Do not include raw candidate findings or uncertain pattern matches
- Do not include PII or real credentials — mask all sensitive values
- Do not speculate about vulnerabilities without evidence — if not confirmed, do not report
- Do not include generic security advice unrelated to specific findings (no "use a WAF" in the finding body — that belongs in a separate recommendations section)

## Workspace output files

After running report.py, the workspace should contain:
- `workspace/report_<run_id>.md` — full Markdown report
- `workspace/report_<run_id>.sarif` — SARIF output
- `workspace/report_<run_id>.json` — JSON summary
- `workspace/confirmed_findings.json` — machine-readable confirmed findings

## Required: save to Vulnscan_results.md

**Always write the final Markdown report to `Vulnscan_results.md` in the root of the scanned project directory.** This is the primary deliverable.

```bash
cp workspace/report_<run_id>.md <scanned_project_path>/Vulnscan_results.md
```

If the report path is not known, write the Markdown content directly to `<scanned_project_path>/Vulnscan_results.md` using the Write tool. The file must exist in the scanned project after every full scan — it is the artifact the user reviews.
