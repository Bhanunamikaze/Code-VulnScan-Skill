# dependency-auditor

Read this after running `python3 scripts/dependency.py --path <target>` to interpret and triage dependency findings.

## Goal

Assess which vulnerable dependencies are actually exploitable in this codebase, assign correct severity based on how the package is used, and provide actionable upgrade guidance.

## Phase 1: Understand the output

The dependency script outputs JSON with:
- Package name, current version, vulnerable version range
- Known CVE IDs
- Vulnerability type (e.g., RCE, XSS, SQLi, path traversal)
- Package ecosystem

Start by sorting findings by severity: critical and high first.

## Phase 2: Exploitability triage

Not all vulnerable dependency versions are exploitable. Triage each finding:

### Confirm the vulnerable code path is used

```python
# Example: requests library CVE for SSRF via scheme confusion
# Before reporting high severity, check:
# 1. Does this app use requests to make HTTP calls?
# 2. Are any of those calls using user-controlled URLs?
# 3. If requests is only used for fixed internal API calls, SSRF via CVE may be unexploitable
```

**Questions for each finding:**
1. Is the package imported/required anywhere in the active codebase?
2. Is the vulnerable function/API specifically called?
3. Is the vulnerable call path reachable from user input?

If the answer to any is "no", downgrade to informational but still recommend upgrade.

### Dev vs production dependencies

Separate findings by dependency type:
- `devDependencies` (package.json), `[dev]` packages (Python), test dependencies → lower urgency, but note if they have RCE (supply chain risk even in CI)
- Production dependencies → full severity applies

### Transitive vs direct dependencies

- Direct dependency: the package is explicitly listed in the manifest → fix by upgrading the package
- Transitive dependency: pulled in by another package → may require upgrading the parent package or adding a resolution override

Always note which direct package pulls in a vulnerable transitive dependency.

## Phase 3: Package ecosystem patterns

### Python (pip)

Check `requirements.txt`, `Pipfile`, `Pipfile.lock`, `pyproject.toml`, `setup.py`, `setup.cfg`.

High-value packages to examine closely when flagged:
- `Django < 4.x.y` — many historical SQLi, XSS, CSRF bypass CVEs
- `Flask < 2.x.y` — cookie tampering, redirect issues
- `Pillow < 9.x.y` — image parsing RCE, DoS
- `PyYAML < 6.0` without `Loader=yaml.SafeLoader` — arbitrary code execution via `yaml.load()`
- `cryptography < X` — padding oracle attacks, weak defaults
- `requests < 2.x.y` — SSRF, cert validation bypass
- `paramiko < X` — auth bypass, key injection
- `lxml < X` — XXE
- `sqlalchemy < X` — SQLi in specific query patterns
- `jinja2 < 3.x` — sandbox escape SSTI

### JavaScript/Node.js (npm/yarn/pnpm)

Check `package.json`, `package-lock.json`, `yarn.lock`.

High-value packages:
- `lodash < 4.17.21` — prototype pollution (CVE-2021-23337)
- `express < 4.x` — various including open redirect, header injection
- `jsonwebtoken` — algorithm confusion, blank secret acceptance
- `axios < 1.6.0` — SSRF, CSRF
- `path-traversal` related: `send < X`, `st < X`, `serve-static < X`
- `qs < 6.7.3` — prototype pollution
- `node-fetch < 3.x` — various
- `minimist < 1.2.6` — prototype pollution
- `async < 2.6.4` — prototype pollution

### Java (Maven/Gradle)

Check `pom.xml`, `build.gradle`, `build.gradle.kts`.

High-value packages:
- `log4j < 2.17.1` — Log4Shell RCE (CVE-2021-44228) — critical
- `spring-framework < 5.3.18` — Spring4Shell RCE
- `struts2 < X` — multiple historical RCE CVEs
- `jackson-databind < 2.13.x` — deserialization gadget chains
- `commons-collections < 3.2.2` / `< 4.1` — deserialization RCE
- `xmlbeans, xstream < X` — XXE, deserialization RCE
- `netty < X` — HTTP response splitting, path traversal

### Go

Check `go.mod`, `go.sum`.

High-value modules:
- `golang.org/x/net` — HTTP/2 DoS, various
- `golang.org/x/crypto` — SSH issues
- Web framework versions (gin, echo, fiber)

### PHP (Composer)

Check `composer.json`, `composer.lock`.

High-value packages:
- `laravel/framework < X` — mass assignment, SQL injection
- `symfony/http-foundation < X` — various
- `guzzlehttp/guzzle < 7.x` — SSRF, header injection
- `phpmailer/phpmailer < 6.x` — header injection, RCE

### Ruby (Bundler)

Check `Gemfile`, `Gemfile.lock`.

High-value gems:
- `rails < 7.x.y` — many historical CVEs (mass assignment, SQLi, XSS)
- `nokogiri < 1.x.y` — libxml2 XXE, libxslt issues
- `devise < X` — timing attacks, enumeration

## Phase 4: Severity adjustment

Adjust the base CVSS score from the CVE based on your exploitability analysis:

| Factor | Adjustment |
|--------|-----------|
| Vulnerable function not called | Downgrade to informational |
| User input cannot reach vulnerable code path | Downgrade by 2 severity levels |
| Package is only a dev dependency | Note: dev/CI risk, not production |
| Transitive dep, can be forced to safe version | Note complexity of fix |
| Known exploit public (PoC/Metasploit) | Maintain or upgrade severity |
| Used in authentication/authorization context | Maintain critical/high |

## Phase 5: Remediation guidance

For each finding, provide:
1. The minimum safe version to upgrade to
2. Whether upgrading is likely to be a breaking change
3. Any workaround if immediate upgrade is not possible

```json
{
  "package": "log4j-core",
  "ecosystem": "java/maven",
  "current_version": "2.14.1",
  "vulnerable_range": "< 2.17.1",
  "safe_version": "2.17.1",
  "cve": "CVE-2021-44228",
  "cvss": 10.0,
  "vuln_type": "remote_code_execution",
  "title": "Log4Shell — Remote Code Execution via JNDI injection",
  "exploitable_in_codebase": true,
  "exploitability_note": "App uses log4j to log HTTP request parameters including user-agent. JNDI lookup triggered by malicious user-agent header.",
  "remediation": "Upgrade to log4j-core 2.17.1. Workaround: set log4j2.formatMsgNoLookups=true or remove JndiLookup class from classpath.",
  "breaking_change": false,
  "severity": "critical"
}
```
