# False Positive Guide

Reference for common false positive scenarios that the `false-positive-filter` sub-skill should recognize.

## SQL Injection False Positives

| Scenario | Why it's a FP | Signal |
|---------|--------------|--------|
| ORM query builder used correctly | Django ORM, SQLAlchemy ORM generate parameterized queries automatically | `User.objects.filter(name=val)` not `.raw(query_string)` |
| Parameterized query with user input | Placeholder `%s`/`?`/`:name` used | `execute("SELECT ... WHERE id = %s", (user_id,))` |
| Input validated as integer before use | `int(user_id)` — no string injection possible in integer | `WHERE id = {int(user_id)}` |
| Test files with hardcoded SQL strings | Constant test data, not user input | File in `tests/`, string has no variable interpolation |

## Command Injection False Positives

| Scenario | Why it's a FP | Signal |
|---------|--------------|--------|
| subprocess with list args, shell=False | Each arg is a separate list element, not shell-interpreted | `subprocess.run(["git", "clone", url], shell=False)` |
| Hardcoded command | No user input reaches the command | `os.system("ls /tmp")` with no variables |
| shlex.quote used | Properly escapes shell metacharacters | `os.system(f"cmd {shlex.quote(user_input)}")` |

## Path Traversal False Positives

| Scenario | Why it's a FP | Signal |
|---------|--------------|--------|
| os.path.realpath + prefix check | Canonicalization + strict prefix check | `abs_path = os.path.realpath(os.path.join(BASE, input)); assert abs_path.startswith(BASE)` |
| werkzeug secure_filename | Strips path separators | `secure_filename(filename)` + `os.path.join(UPLOAD_DIR, safe_name)` |
| Hardcoded path components | User input only provides a filename, not path traversal chars | `os.path.join("/fixed/dir/", filename)` where filename is validated as alphanumeric |

## XSS False Positives

| Scenario | Why it's a FP | Signal |
|---------|--------------|--------|
| Auto-escaping template engine | Jinja2 default, Django templates, React JSX all auto-escape | `{{ variable }}` in Jinja2 (not `{{ variable|safe }}`) |
| html.escape applied | Explicit escaping before HTML output | `html.escape(user_input)` |
| JSON response, not HTML | XSS requires HTML context | `Content-Type: application/json` response |
| Static string in innerHTML | No variable, no user data | `el.innerHTML = "<b>static text</b>"` |

## Hardcoded Secret False Positives

| Scenario | Why it's a FP | Signal |
|---------|--------------|--------|
| Placeholder/example value | Obviously fake | `"your-api-key-here"`, `"<INSERT_KEY>"`, `"TODO"` |
| Test/fixture value | In test directory, clearly fake | `tests/` dir, `"test-secret-key-for-testing"` |
| Environment variable reference | Key comes from env at runtime | `os.environ.get('SECRET_KEY')` |
| Low-entropy/common word | Not a real credential | `"debug"`, `"test"`, `"example"` < 20 chars |
| Public key or certificate | Not secret | `-----BEGIN PUBLIC KEY-----`, `-----BEGIN CERTIFICATE-----` |

## Crypto False Positives

| Scenario | Why it's a FP | Signal |
|---------|--------------|--------|
| MD5 for non-security purpose | Checksums for file deduplication, cache keys, ETags | Comment/context says "checksum" not "password" or "signature" |
| Math.random for non-security purpose | Random color, UI element ID, non-security shuffle | Not used for tokens, OTPs, session IDs, or keys |
| SHA1 for git hash compatibility | Git uses SHA1 internally | Context is git commit hash handling |

## SSRF False Positives

| Scenario | Why it's a FP | Signal |
|---------|--------------|--------|
| URL is hardcoded | No user control possible | `requests.get("https://api.fixed-service.com/v1/data")` |
| URL allowlisted | Strict allowlist with exact match | `if url not in ALLOWED_URLS: raise ValueError` |
| Internal service call with fixed URL | Configuration-defined URL, not user input | URL comes from app config, not request |

## Auth False Positives

| Scenario | Why it's a FP | Signal |
|---------|--------------|--------|
| Admin check is present but in middleware | Auth check in middleware applied before handler | Verify middleware IS applied to this route |
| Resource not sensitive | Public resource, no authorization needed | Route serves public static content |
| Rate limiting via middleware | Applied globally | Verify middleware covers the endpoint in question |
