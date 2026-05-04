# config-security-reviewer

Read this when reviewing application configuration, environment settings, and HTTP security headers.

## Goal

Find security misconfigurations: debug mode, insecure defaults, missing security headers, overly permissive CORS, absent CSP, and TLS weaknesses that leave the application exposed even when the code itself is correct.

## Part 1: Debug and development mode in production

Debug mode active in production is a critical finding in most frameworks:

**Python / Django:**
```python
# Flag: production with DEBUG=True
DEBUG = True
# Reveals: full stack traces to users, source code snippets, SQL queries, system paths
```

**Python / Flask:**
```python
# Flag
app.run(debug=True)
app.config['DEBUG'] = True
app.config['TESTING'] = True
```

**Node.js / Express:**
```javascript
// Flag
app.set('env', 'development');
// Or: NODE_ENV !== 'production' in production deploy
```

**Spring Boot:**
```yaml
# application.properties / application.yml
spring.jpa.show-sql: true               # SQL in logs
management.endpoints.web.exposure.include: "*"  # all actuator endpoints
management.endpoint.env.enabled: true   # exposes environment variables
management.endpoint.heapdump.enabled: true  # memory dump
```

Also check for exposed framework-specific debug endpoints:
- Django: `/admin/` without IP restriction, `/__debug__/` (Django Debug Toolbar)
- Flask: `/console` (Werkzeug debugger — RCE if exposed)
- Laravel: `APP_DEBUG=true` in `.env`
- Rails: config exceptions shown in browser in development but not production
- Spring Boot Actuator: `/actuator/env`, `/actuator/heapdump`, `/actuator/trace` exposed without auth

## Part 2: HTTP security headers

For web applications, check all HTTP response headers. Missing security headers are medium findings; some are high depending on context.

### Required headers and their purpose

| Header | Required Value | Severity if missing |
|--------|----------------|-------------------|
| `Content-Security-Policy` | Restrictive policy | High |
| `X-Content-Type-Options` | `nosniff` | Medium |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Medium |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | High (HTTPS apps) |
| `Referrer-Policy` | `no-referrer` or `strict-origin-when-cross-origin` | Low |
| `Permissions-Policy` | restrict unneeded browser features | Low |

### Content Security Policy (CSP)

A missing CSP is a high finding for apps that serve HTML. A weak CSP is medium.

**Weak CSP patterns to flag:**
```
Content-Security-Policy: default-src *                  # wildcard — useless
Content-Security-Policy: default-src 'unsafe-inline'   # allows all inline scripts
Content-Security-Policy: default-src 'unsafe-eval'     # allows eval()
Content-Security-Policy: script-src 'nonce-...' 'unsafe-inline'  # nonce + unsafe-inline = nonce ignored
```

**Check CSP implementation in code:**
```python
# Flag: CSP header set with unsafe-inline
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
```

### CORS configuration

Overly permissive CORS allows any website to make credentialed requests to the API.

**Flag — wildcard with credentials:**
```python
# Flask-CORS
CORS(app, origins="*", supports_credentials=True)  # critical: wildcard + credentials
```

```javascript
// Express
app.use(cors({ origin: '*', credentials: true }))  // critical
```

```python
# Django
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True   # critical combination
```

**Flag — overly broad origins:**
```python
# Allows any attacker.com subdomain if attacker controls trusted.com
CORS_ALLOWED_ORIGIN_REGEXES = [r'https://.*\.trusted\.com']  # attacker can register evil.trusted.com
```

**Flag — user-supplied Origin reflected:**
```python
# Dynamically reflects Origin header without validation
response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin')
response.headers['Access-Control-Allow-Credentials'] = 'true'
```

## Part 3: TLS / HTTPS configuration

**Application-level TLS issues:**

```python
# Flag: HTTP redirect not enforced
# Missing: FORCE_HTTPS = True, SECURE_SSL_REDIRECT = True (Django)

# Flag: mixed content — HTTP resources loaded in HTTPS page
# Check templates for hardcoded http:// URLs

# Flag: cookie not marked Secure
response.set_cookie('session', value, secure=False)

# Flag: HSTS not set or too short
# Strict-Transport-Security: max-age=300  — too short
```

**Proxy / load balancer trust:**
```python
# Flag: trusting X-Forwarded-Proto without configuring trusted proxies
# Django: SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https') without ALLOWED_HOSTS/proxy restriction
```

## Part 4: Framework-specific hardening

### Django settings audit

```python
# Flag these insecure settings
SECRET_KEY = 'django-insecure-...'     # never use the default insecure key
ALLOWED_HOSTS = ['*']                   # too broad in production
DEBUG = True                            # see Part 1
CSRF_COOKIE_SECURE = False              # should be True in production
SESSION_COOKIE_SECURE = False           # should be True in production
SESSION_COOKIE_HTTPONLY = False         # should be True
X_FRAME_OPTIONS = 'ALLOWALL'           # should be DENY or SAMEORIGIN
SECURE_CONTENT_TYPE_NOSNIFF = False    # should be True
SECURE_BROWSER_XSS_FILTER = False      # should be True
```

### Flask configuration audit

```python
# Flag
app.config['WTF_CSRF_ENABLED'] = False          # disables CSRF protection
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = None
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)  # too long
```

### Express / Node.js

```javascript
// Flag: helmet not used
// or helmet used but with permissive options
app.use(helmet({
  contentSecurityPolicy: false,        // CSP disabled
  frameguard: false,                   // clickjacking protection disabled
}));

// Flag: express-session misconfiguration
app.use(session({
  secret: 'keyboard cat',              # weak secret
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: false }
}));
```

## Part 5: File and directory exposure

- `.git/` directory accessible over HTTP → source code and secrets exposure → critical
- `.env` file accessible over HTTP → all environment variables exposed → critical
- Directory listing enabled → lists all files → medium
- Backup files accessible: `config.php.bak`, `database.sql`, `backup.tar.gz` → high
- Admin interfaces publicly accessible without IP restriction

Check web server configuration files:
- `nginx.conf`, `sites-available/*.conf`
- `apache2.conf`, `.htaccess`
- `web.config` (.NET)

## Part 6: Database and service configuration

- Database admin interfaces publicly accessible: phpMyAdmin, pgAdmin, MongoDB Express
- Redis with no authentication (`requirepass` not set) and public bind address
- Elasticsearch with no authentication and public port
- Default credentials unchanged: admin/admin, root/root, postgres/postgres

## Output format

```json
{
  "file": "myapp/settings.py",
  "line": 12,
  "category": "debug_mode",
  "title": "DEBUG=True in production settings file",
  "description": "Django DEBUG mode exposes full stack traces, source code snippets, SQL queries, and system paths to any user who triggers an error.",
  "impact": "Information disclosure leading to targeted exploitation.",
  "remediation": "Set DEBUG=False in production. Use environment variable: DEBUG = os.environ.get('DEBUG', 'False') == 'True'",
  "cwe": "CWE-94",
  "severity": "high"
}
```
