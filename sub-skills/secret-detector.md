# secret-detector

Read this when scanning for hardcoded secrets, credentials, and private keys in source code and configuration files.

## Goal

Find credentials, API keys, private keys, tokens, passwords, and connection strings hardcoded in source code, config files, scripts, or committed to version control. These represent immediate, critical exposure.

## Phase 1: Run the entropy scanner

Always start with the script:

```bash
python3 scripts/secrets.py --path <target>
```

The script uses Shannon entropy scoring + pattern matching to identify candidate strings. Review all high-entropy hits (entropy ≥ 4.5 in non-test files) and all pattern matches.

## Phase 2: Manual pattern review

After reviewing script output, manually check these high-value locations:

### Files to always inspect

- `.env`, `.env.local`, `.env.production`, `.env.staging`, `.env.example` (check example too — sometimes real values)
- `config/*.py`, `config/*.json`, `config/*.yaml`, `config/*.xml`, `config/*.ini`, `config/*.toml`
- `settings.py`, `settings_prod.py`, `config.py`, `configuration.py`
- `application.properties`, `application.yml` (Spring Boot)
- `appsettings.json`, `appsettings.Production.json` (.NET)
- `Dockerfile`, `docker-compose.yml`, `docker-compose.prod.yml`
- `*.sh`, `*.bash`, `*.zsh` shell scripts
- `Makefile`, `Jenkinsfile`, `*.gitlab-ci.yml`, `*.github/workflows/*.yml`
- `terraform/*.tf`, `terraform/*.tfvars`
- `*.pem`, `*.key`, `*.p12`, `*.jks`, `*.pfx` — private key files committed to repo
- `README.md`, `docs/*.md` — developers sometimes paste real credentials in examples

### Pattern categories

**Database connection strings:**
```
postgresql://user:PASSWORD@host:5432/db
mysql://user:PASSWORD@localhost/db
mongodb://user:PASSWORD@host:27017
Server=host;Database=db;User Id=user;Password=PASSWORD
```

**Cloud credentials:**
```
AKIA[0-9A-Z]{16}                    # AWS Access Key ID
aws_secret_access_key = [A-Za-z0-9/+=]{40}
AIza[0-9A-Za-z\-_]{35}             # Google API Key
[0-9a-f]{32}-us[0-9]{1,2}          # Mailchimp API key
sk-[A-Za-z0-9]{48}                 # OpenAI API key
xoxb-[0-9]+-[A-Za-z0-9]+           # Slack Bot token
ghp_[A-Za-z0-9]{36}                # GitHub Personal Access Token
ghs_[A-Za-z0-9]{36}                # GitHub Actions token
```

**Authentication secrets:**
```python
SECRET_KEY = "[non-trivial-string]"       # Django/Flask secret key
JWT_SECRET = "[non-trivial-string]"
SESSION_SECRET = "[non-trivial-string]"
API_KEY = "[non-trivial-string]"
PASSWORD = "[non-trivial-string]"
PASSWD = "[non-trivial-string]"
TOKEN = "[non-trivial-string]"
```

**Private keys:**
```
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
-----BEGIN DSA PRIVATE KEY-----
```

**Weak / obviously insecure defaults:**
These are still findings even if entropy is low:
- `password = "password"`, `"admin"`, `"secret"`, `"changeme"`, `"12345"`, `"test"`
- `SECRET_KEY = "development"`, `"dev"`, `"insecure"`, `"unsafe"`
- `api_key = "your-api-key-here"` used literally in non-example code
- `debug_password = "debug"`

## Phase 3: Git history check

Secrets deleted from current code may still exist in git history. Instruct the user to run:

```bash
git log --all --full-history --diff-filter=D -- "*.env" "*.pem" "*.key"
git log -p --all -S "password" --source --remotes
```

Note this as a manual follow-up if the codebase is a git repository. Do not run git commands against the user's repo yourself unless explicitly asked.

## Phase 4: Context verification

Before reporting each hit, verify it is a real secret:

**Do not report:**
- Placeholder examples: `"your-api-key"`, `"<YOUR_SECRET>"`, `"TODO: set this"`
- Test fixtures with obviously fake values: `"test-password-123"` in `tests/` directories
- Documentation examples with fake-looking data
- Non-sensitive high-entropy strings (base64-encoded icons, minified JS, generated CSS hashes)
- Public keys, certificates, and certificate fingerprints (not secret)
- Environment variable references: `os.environ.get('API_KEY')` — this is correct, not a finding

**Do report:**
- Real-looking credentials: sufficient entropy, structured like real API keys for known services
- Any private key material regardless of whether it looks "fake"
- Connection strings with passwords that are not obviously placeholders
- Secrets in CI/CD YAML files (even if they reference `${{ secrets.X }}` — check the value isn't hardcoded elsewhere)
- `.env.example` files with real values (they get committed; the real file does not)

## Phase 5: Severity classification

| Finding | Severity |
|---------|---------|
| Production database password | Critical |
| Cloud provider access key (AWS/GCP/Azure) | Critical |
| Private key (.pem, RSA, EC) | Critical |
| JWT signing secret | Critical |
| OAuth client secret | High |
| Stripe/payment processor key | Critical |
| Internal API key (other services) | High |
| GitHub/GitLab token | High |
| SMTP password | High |
| Slack/webhook URL with token | Medium-High |
| Dev/test credential (if same in prod) | High |
| Dev/test credential (clearly dev-only) | Medium |
| Weak default password | Medium-High |

## Output format

```json
{
  "file": "config/production.py",
  "line": 14,
  "category": "hardcoded_secret",
  "secret_type": "database_password",
  "title": "Hardcoded PostgreSQL password in production config",
  "evidence": "DATABASE_URL = 'postgresql://appuser:Secr3tP@ss!@prod-db.internal:5432/appdb'",
  "masked_evidence": "DATABASE_URL = 'postgresql://appuser:***@prod-db.internal:5432/appdb'",
  "entropy": 4.8,
  "confirmed": true,
  "remediation": "Move to environment variable: DATABASE_URL = os.environ['DATABASE_URL']. Rotate the exposed credential immediately.",
  "cwe": "CWE-798",
  "severity": "critical"
}
```

Always mask the actual secret value in `masked_evidence` — never include raw credentials in the final report.
