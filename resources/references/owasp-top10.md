# OWASP Top 10 (2021) Quick Reference

For use by `vuln-classifier` when assigning OWASP categories.

| ID | Category | Key Vulnerabilities Covered |
|----|----------|---------------------------|
| A01:2021 | Broken Access Control | IDOR, missing auth checks, privilege escalation, CORS misconfiguration, CSRF |
| A02:2021 | Cryptographic Failures | Cleartext data, weak algorithms (MD5/SHA1), hardcoded keys, insecure random, missing TLS |
| A03:2021 | Injection | SQL injection, command injection, LDAP injection, XPath, SSTI, header injection |
| A04:2021 | Insecure Design | Missing rate limiting, business logic flaws, security design gaps, TOCTOU |
| A05:2021 | Security Misconfiguration | Debug mode, default creds, verbose errors, missing headers, open cloud storage |
| A06:2021 | Vulnerable & Outdated Components | CVEs in dependencies, unsupported versions, outdated frameworks |
| A07:2021 | ID and Auth Failures | Weak passwords, no MFA, bad session management, JWT flaws, credential stuffing |
| A08:2021 | Software and Data Integrity | Insecure deserialization, CI/CD pipeline attacks, untrusted CDN/package sources |
| A09:2021 | Security Logging Failures | No audit logging, PII in logs, no alerting on security events, log injection |
| A10:2021 | SSRF | Server-side request forgery to internal services, cloud metadata, port scanning |

# OWASP API Security Top 10 (2023) Quick Reference

| ID | Category | Key Vulnerabilities |
|----|----------|-------------------|
| API1:2023 | Broken Object Level Authorization | IDOR — missing per-object ownership check |
| API2:2023 | Broken Authentication | Weak tokens, no expiry, credential stuffing on API |
| API3:2023 | Broken Object Property Level Authorization | Mass assignment, over-exposure of sensitive fields |
| API4:2023 | Unrestricted Resource Consumption | Missing rate limiting, no pagination limits, large payload DoS |
| API5:2023 | Broken Function Level Authorization | Horizontal/vertical access control between API functions |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | Abuse of business logic through API (e.g., infinite coupon use) |
| API7:2023 | Server Side Request Forgery | SSRF via API parameters |
| API8:2023 | Security Misconfiguration | Unnecessary HTTP methods, insecure defaults, verbose errors |
| API9:2023 | Improper Inventory Management | Shadow APIs, undocumented endpoints, outdated versions still running |
| API10:2023 | Unsafe Consumption of APIs | Trusting third-party API responses without validation |
