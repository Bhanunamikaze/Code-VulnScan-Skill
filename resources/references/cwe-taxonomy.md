# CWE Vulnerability Taxonomy — Quick Reference

For use by `vuln-classifier` when assigning CWE identifiers and severity estimates to findings.

---

## Severity to CVSS reference

| Severity Label | CVSS v3.1 Score Range | Typical SLA |
|---------------|----------------------|-------------|
| **Critical** | 9.0 – 10.0 | Immediate / same day |
| **High** | 7.0 – 8.9 | 7 days |
| **Medium** | 4.0 – 6.9 | 30 days |
| **Low** | 0.1 – 3.9 | 90 days |
| **Informational** | 0.0 | Best effort / next sprint |

CVSS base score is determined by Attack Vector, Complexity, Privileges Required, User Interaction, Scope, Confidentiality/Integrity/Availability impact. The ranges below are typical for each CWE when exploited with no authentication required and high impact. Actual scores will vary by deployment context.

---

## CWE Quick Reference Table

| CWE ID | Name | Typical CVSS Range | OWASP 2021 | Description |
|--------|------|--------------------|------------|-------------|
| **CWE-89** | SQL Injection | 7.5 – 9.8 | A03 Injection | User-controlled data is concatenated into a SQL query without parameterization. Enables data exfiltration, authentication bypass, data destruction, and (on some DBs) OS command execution via `xp_cmdshell` or `LOAD_FILE`. |
| **CWE-78** | OS Command Injection | 9.0 – 10.0 | A03 Injection | Unsanitized user input is passed to a shell interpreter (`system()`, `exec()`, `subprocess` with `shell=True`). Enables arbitrary command execution with the privileges of the web server process. |
| **CWE-79** | Cross-Site Scripting (XSS) | 4.3 – 8.8 | A03 Injection | Untrusted data is rendered in an HTML page without encoding. Reflected XSS executes script in the victim's browser in the request/response cycle; Stored XSS persists and targets all users who view the stored content; DOM-based XSS executes via client-side script. |
| **CWE-22** | Path Traversal | 5.3 – 9.1 | A01 Broken Access Control | User-controlled path components (e.g., `../`) allow reading or writing files outside the intended directory. Can expose source code, configuration files, private keys, or OS files like `/etc/passwd`. |
| **CWE-611** | XML External Entity (XXE) | 7.5 – 9.1 | A05 Security Misconfiguration | XML parsers that resolve external entity references allow attackers to read local files, perform SSRF, or cause DoS (via entity expansion — Billion Laughs). Triggered when parsing untrusted XML with DTD processing enabled. |
| **CWE-502** | Deserialization of Untrusted Data | 7.5 – 9.8 | A08 Software & Data Integrity | Deserializing attacker-controlled data using native serialization formats (Java `ObjectInputStream`, Python `pickle`, PHP `unserialize`, Ruby `Marshal`) can lead to remote code execution via gadget chains. |
| **CWE-327** | Use of Broken or Risky Cryptographic Algorithm | 5.3 – 7.5 | A02 Cryptographic Failures | Using deprecated algorithms (MD5, SHA-1, DES, RC4, ECB mode AES) for security-sensitive operations. Broken hash functions allow collision attacks; broken ciphers allow decryption. |
| **CWE-328** | Use of Weak Hash | 4.0 – 7.5 | A02 Cryptographic Failures | Passwords hashed with fast algorithms (MD5, SHA-1, SHA-256 without salt/stretching) are brute-forceable. Proper password hashing requires bcrypt, scrypt, Argon2, or PBKDF2 with high work factor. |
| **CWE-798** | Use of Hard-coded Credentials | 7.5 – 9.8 | A07 ID and Auth Failures | Credentials (passwords, API keys, tokens, private keys) embedded in source code or compiled binaries. Discovered via source code access, decompilation, or repository history mining. |
| **CWE-287** | Improper Authentication | 6.5 – 9.8 | A07 ID and Auth Failures | Authentication checks that can be bypassed: skipping signature verification (JWT `none` algorithm), trusting client-supplied session data, accepting any value for a token parameter. |
| **CWE-918** | Server-Side Request Forgery (SSRF) | 5.8 – 9.8 | A10 SSRF | Server makes HTTP/network requests to a URL supplied by the attacker. Enables access to internal services, cloud metadata endpoints (169.254.169.254), localhost-bound services, and internal network port scanning. |
| **CWE-352** | Cross-Site Request Forgery (CSRF) | 4.3 – 8.8 | A01 Broken Access Control | State-changing requests that rely solely on session cookies for authentication can be forged by tricking an authenticated user into visiting a malicious page. Mitigated by CSRF tokens, `SameSite=Strict` cookies, or double-submit cookie pattern. |
| **CWE-601** | Open Redirect | 4.7 – 6.1 | A01 Broken Access Control | Application redirects users to a URL from request parameters without validation. Used in phishing attacks to create trusted-looking URLs pointing to malicious sites (e.g., `https://bank.com/logout?redirect=https://evil.com`). |
| **CWE-400** | Uncontrolled Resource Consumption (DoS) | 5.3 – 7.5 | A04 Insecure Design | Missing rate limiting, unbounded loops, or operations proportional to attacker-controlled input size cause excessive CPU, memory, or disk consumption. Enables denial of service. Includes regex-related DoS when not classified as CWE-1333. |
| **CWE-119** | Buffer Overflow (generic) | 7.5 – 10.0 | A03 Injection | Writing data beyond the bounds of a fixed-size buffer in memory-unsafe languages (C, C++). Can overwrite adjacent memory, corrupt program state, or enable code execution. |
| **CWE-120** | Buffer Copy without Checking Size (`strcpy`) | 7.5 – 9.8 | A03 Injection | Classic buffer overflow via `strcpy`, `strcat`, `gets`, `sprintf` without length bounds. Input longer than the buffer overwrites return addresses, function pointers, or heap metadata. |
| **CWE-125** | Out-of-bounds Read | 5.3 – 7.5 | A03 Injection | Reading memory beyond allocated buffer boundaries. May leak sensitive heap/stack contents (including keys, credentials, or pointers) or cause crashes. |
| **CWE-416** | Use After Free (UAF) | 7.5 – 9.8 | A03 Injection | Memory accessed after it has been freed. Freed memory may be reallocated and controlled by the attacker, enabling data corruption or code execution. Common in C/C++ and Objective-C without ARC. |
| **CWE-134** | Use of Externally-Controlled Format String | 7.5 – 9.8 | A03 Injection | Attacker-controlled format string passed to `printf`, `sprintf`, `syslog`, or similar. Enables reading from arbitrary memory addresses (`%x`), writing to arbitrary addresses (`%n`), or crashing. |
| **CWE-362** | Race Condition / TOCTOU | 4.7 – 8.1 | A04 Insecure Design | Time-of-Check to Time-of-Use: a resource state checked at time T₁ may differ at time T₂ when used. Allows privilege escalation (symlink attacks on files), double-spend logic flaws, or authentication bypass. |
| **CWE-330** | Use of Insufficiently Random Values | 5.3 – 7.5 | A02 Cryptographic Failures | Using non-cryptographic PRNGs (`Math.random()`, `random.random()`, `java.util.Random`) for security-sensitive values (session tokens, CSRF tokens, password reset codes, OTPs). Predictable output enables token forgery. |
| **CWE-693** | Protection Mechanism Failure (Prototype Pollution) | 5.3 – 9.8 | A03 Injection | JavaScript-specific: attacker modifies `Object.prototype` by injecting `__proto__` or `constructor.prototype` keys into user-controlled objects merged with application objects. Can override application behavior, bypass security checks, or achieve RCE in some frameworks. |
| **CWE-915** | Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment) | 5.3 – 8.8 | API3:2023 Broken Object Property | Framework auto-binds all request fields to model objects. Allows setting privileged fields (e.g., `is_admin`, `role`, `account_balance`) not intended to be user-settable. |
| **CWE-1333** | Inefficient Regular Expression Complexity (ReDoS) | 5.3 – 7.5 | A04 Insecure Design | Regular expressions with catastrophic backtracking behavior (nested quantifiers, overlapping alternations) can be exploited to cause denial of service by supplying crafted inputs that trigger exponential matching time. |
| **CWE-284** | Improper Access Control / IDOR | 5.3 – 9.1 | A01 Broken Access Control | Resource access is not restricted to authorized users. Includes IDOR (Insecure Direct Object Reference) where changing an ID in a URL/body gives access to another user's data. Also covers BOLA in API context. |
| **CWE-306** | Missing Authentication for Critical Function | 7.5 – 9.8 | A07 ID and Auth Failures | Critical operations (admin actions, password reset, data export, account deletion) lack any authentication check. Any unauthenticated client can invoke them. |
| **CWE-521** | Weak Password Requirements | 3.7 – 6.5 | A07 ID and Auth Failures | Application imposes insufficient constraints on user passwords: no minimum length, no complexity requirements, or accepting common passwords. Makes accounts susceptible to brute force, credential stuffing, and dictionary attacks. |
| **CWE-614** | Insecure Cookie Attributes | 4.3 – 7.5 | A05 Security Misconfiguration | Session cookies missing `Secure` flag (sent over HTTP), `HttpOnly` flag (accessible via JavaScript — XSS exfiltration), or `SameSite` attribute (CSRF vector). |
| **CWE-776** | Improper Restriction of Recursive Entity References in DTDs (Billion Laughs) | 7.5 – 7.5 | A05 Security Misconfiguration | A specially crafted XML document uses recursive entity expansion to cause exponential memory and CPU consumption (e.g., one entity expanding to billions of bytes). A variant of XXE/DoS. Prevented by disabling DTD processing or using a hardened XML parser. |

---

## OWASP Category Cross-Reference

| OWASP 2021 | Related CWEs |
|-----------|-------------|
| A01 Broken Access Control | CWE-284, CWE-352, CWE-601, CWE-22 |
| A02 Cryptographic Failures | CWE-327, CWE-328, CWE-330, CWE-614 |
| A03 Injection | CWE-89, CWE-78, CWE-79, CWE-119, CWE-120, CWE-125, CWE-134, CWE-416 |
| A04 Insecure Design | CWE-400, CWE-1333, CWE-362 |
| A05 Security Misconfiguration | CWE-611, CWE-776, CWE-614 |
| A07 ID and Auth Failures | CWE-287, CWE-798, CWE-306, CWE-521 |
| A08 Software & Data Integrity | CWE-502 |
| A10 SSRF | CWE-918 |
| API3:2023 Object Property | CWE-915 |
| JS-specific | CWE-693 |

---

## Notes on CVSS scoring for code review findings

- **Base score** is theoretical maximum. Actual exploitability depends on network accessibility, authentication requirements, and environmental context.
- A SQL injection in a publicly accessible, unauthenticated endpoint scores higher than one requiring admin auth.
- Use the ranges above as a starting point; adjust downward when: (a) authentication is required, (b) the endpoint is internal-only, or (c) exploitability requires non-trivial prerequisites.
- For `vuln-classifier`, prefer the higher end of the range when the code path is directly reachable from user input with no auth. Use the lower end for second-order or authenticated-only paths.
