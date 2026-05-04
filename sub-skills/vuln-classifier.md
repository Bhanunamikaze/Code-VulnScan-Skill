# vuln-classifier

Read this after false-positive filtering, before report generation. Assign consistent scoring to every confirmed finding.

## Goal

Assign a CWE, OWASP category, CVSS v3.1 base score, and severity label to every confirmed finding so the final report is actionable and comparable.

## CWE assignment

Map each vulnerability type to its primary CWE:

| Vulnerability | CWE |
|--------------|-----|
| SQL Injection | CWE-89 |
| OS Command Injection | CWE-78 |
| Path Traversal | CWE-22 |
| Reflected XSS | CWE-79 |
| Stored XSS | CWE-79 |
| DOM XSS | CWE-79 |
| SSRF | CWE-918 |
| Insecure Deserialization | CWE-502 |
| Server-Side Template Injection | CWE-94 |
| Open Redirect | CWE-601 |
| XXE | CWE-611 |
| LDAP Injection | CWE-90 |
| XPath Injection | CWE-643 |
| Header Injection | CWE-113 |
| Authentication Bypass | CWE-287 |
| Broken Access Control / IDOR | CWE-284 / CWE-639 |
| Session Fixation | CWE-384 |
| Missing Authentication | CWE-306 |
| Privilege Escalation | CWE-269 |
| Mass Assignment | CWE-915 |
| Business Logic Flaw | CWE-840 |
| Race Condition | CWE-362 |
| TOCTOU | CWE-367 |
| Weak Cryptographic Algorithm | CWE-327 |
| Insufficient Key Length | CWE-326 |
| Use of Broken Hash (MD5/SHA1) | CWE-328 |
| Hardcoded Credentials | CWE-798 |
| Hardcoded Password | CWE-259 |
| Insecure Randomness | CWE-338 |
| Dependency CVE | CWE-1035 |
| Information Exposure (errors) | CWE-209 |
| Sensitive Data in Logs | CWE-532 |
| Security Misconfiguration | CWE-16 |
| Missing Security Headers | CWE-693 |
| Buffer Overflow | CWE-120 |
| Heap Buffer Overflow | CWE-122 |
| Use-After-Free | CWE-416 |
| Format String | CWE-134 |
| Integer Overflow | CWE-190 |
| Null Pointer Dereference | CWE-476 |
| ReDoS | CWE-1333 |

## OWASP Top 10 (2021) mapping

| OWASP Category | Vulnerabilities |
|---------------|----------------|
| A01 - Broken Access Control | IDOR, privilege escalation, missing auth checks, insecure direct object reference |
| A02 - Cryptographic Failures | Weak algorithms, hardcoded keys, cleartext transmission, insecure random |
| A03 - Injection | SQLi, CMDi, LDAP injection, XPath injection, SSTI, header injection |
| A04 - Insecure Design | Business logic flaws, TOCTOU, race conditions, missing rate limiting |
| A05 - Security Misconfiguration | Debug mode, missing headers, verbose errors, insecure defaults |
| A06 - Vulnerable Components | Dependency CVEs |
| A07 - Identification and Auth Failures | Auth bypass, session fixation, missing MFA enforcement, weak passwords |
| A08 - Software and Data Integrity Failures | Insecure deserialization, untrusted update mechanisms, CI/CD tampering |
| A09 - Security Logging Failures | Sensitive data in logs, missing audit trails, log injection |
| A10 - SSRF | SSRF |

Also map API-specific findings to OWASP API Security Top 10 (2023) where applicable:
- API1: BOLA/IDOR
- API2: Broken Authentication
- API3: Broken Object Property Level Authorization (mass assignment)
- API4: Unrestricted Resource Consumption (no rate limiting)
- API5: Broken Function Level Authorization
- API8: Security Misconfiguration
- API9: Improper Inventory Management

## CVSS v3.1 scoring guidance

Use these base metric defaults as a starting point, then adjust for the specific finding:

### Attack Vector (AV)
- `N` (Network): Exploitable remotely over the network — most web vulns
- `A` (Adjacent): Requires access to the same network/VLAN
- `L` (Local): Requires local account access
- `P` (Physical): Requires physical access

### Attack Complexity (AC)
- `L` (Low): No special conditions — most injection vulns, XSS, IDOR
- `H` (High): Requires specific conditions — race conditions, some second-order vulns

### Privileges Required (PR)
- `N` (None): Unauthenticated — login page injection, reflected XSS
- `L` (Low): Authenticated regular user — stored XSS, IDOR between users
- `H` (High): Admin access required — rarely critical as standalone

### User Interaction (UI)
- `N` (None): No victim interaction needed — SQLi, CMDi, SSRF, IDOR
- `R` (Required): Victim must click a link — reflected XSS, CSRF, open redirect

### Scope (S)
- `U` (Unchanged): Exploiting only the vulnerable component
- `C` (Changed): Impact extends beyond the vulnerable component — stored XSS affecting other users, SQLi leading to full DB access

### Impact: Confidentiality (C), Integrity (I), Availability (A)
- `H` (High): Complete loss
- `L` (Low): Some loss
- `N` (None): No impact

### Severity thresholds

| CVSS Score | Severity |
|-----------|---------|
| 9.0–10.0 | Critical |
| 7.0–8.9 | High |
| 4.0–6.9 | Medium |
| 0.1–3.9 | Low |
| 0.0 | Informational |

### Default vectors by vulnerability type

| Vulnerability | Typical CVSS Vector | Score |
|--------------|-------------------|-------|
| Unauthenticated SQLi (full DB) | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 10.0 |
| Auth SQLi (own account) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| Stored XSS | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | 5.4 |
| Reflected XSS | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |
| Unauthenticated RCE (CMDi) | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 10.0 |
| Path Traversal (read) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 |
| SSRF (internal network) | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 10.0 |
| IDOR (read another user's data) | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| Hardcoded Secret | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| Insecure Deserialization (RCE) | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 10.0 |
| Weak Cryptography (data at rest) | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N | 5.9 |
| Missing rate limiting | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L | 5.3 |

Always compute the actual CVSS score. Do not just use the default — adjust for authentication requirements, access level, and actual impact in context.

## Output format per classified finding

```json
{
  "id": "finding_001",
  "cwe": "CWE-89",
  "owasp_top10": "A03:2021 - Injection",
  "owasp_api": null,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "cvss_score": 10.0,
  "severity": "critical",
  "severity_rationale": "Unauthenticated attacker can read and modify all database records via SQL injection in the login endpoint."
}
```

## Severity adjustment rules

**Upgrade severity when:**
- The vulnerability is on an unauthenticated endpoint
- Exploitation leads to remote code execution
- Exploitation leads to full database read/write
- Chaining with another finding produces a higher impact (note the chain)

**Downgrade severity when:**
- Exploitation requires a specific non-default configuration that is documented as insecure
- The finding is in test or development code not deployed to production (note separately)
- A compensating control significantly reduces exploitability (note the control; do not remove the finding)

Never downgrade because "the developer probably checks this elsewhere."
