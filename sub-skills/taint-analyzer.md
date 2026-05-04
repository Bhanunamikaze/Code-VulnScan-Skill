# taint-analyzer

Read this when performing taint-flow analysis on a codebase or individual file.

## Goal

Trace user-controlled data from its entry point (source) to a dangerous operation (sink), confirming whether effective sanitization exists on every path between them.

A taint path is **confirmed exploitable** only when all three are true:
1. The source is genuinely user-controlled (not hardcoded or trusted-internal).
2. The data reaches the sink without being neutralized by appropriate sanitization.
3. The code path is actually reachable (not dead code, not behind an impossible condition).

## Phase 1: Source identification

### What counts as a source

A source is any value that an external, untrusted party can influence. This includes:

**Direct HTTP input:**
- Python/Flask: `request.args`, `request.form`, `request.json`, `request.data`, `request.files`, `request.cookies`, `request.headers`, `request.values`, `request.get_json()`
- Python/Django: `request.GET`, `request.POST`, `request.FILES`, `request.COOKIES`, `request.META`, `request.body`, form `cleaned_data` (before validation)
- Python/FastAPI: function parameters annotated with `Query()`, `Body()`, `Form()`, `File()`, `Cookie()`, `Header()`, `Path()`
- Node.js/Express: `req.query`, `req.body`, `req.params`, `req.cookies`, `req.headers`, `req.files`
- Java/Spring: `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, `HttpServletRequest.getParameter()`
- Go: `r.URL.Query().Get()`, `r.FormValue()`, `r.PostFormValue()`, `r.Header.Get()`, JSON decode from `r.Body`
- PHP: `$_GET`, `$_POST`, `$_REQUEST`, `$_FILES`, `$_COOKIE`, `$_SERVER['HTTP_*']`
- Ruby/Rails: `params`, `request.headers`, `cookies`
- C#: `Request.Query[]`, `Request.Form[]`, `Request.Headers[]`, model binding parameters

**System-level input:**
- `sys.argv`, `os.environ`, `os.getenv()`
- `input()`, `stdin.read()`
- Files read from user-controlled paths
- Environment variable expansions

**Second-order sources (high priority):**
- Database columns that store user-supplied data (e.g., a stored comment, username, uploaded filename) later read back and used without re-sanitization
- Message queue payloads
- Webhook request bodies
- Cached values from external systems

### Source tracing rules

When you find a source assignment, record:
- Variable name
- Function/method where it appears
- Line number
- Source type (HTTP param, env var, file read, etc.)

Track the variable as it flows through:
- Direct assignments: `user_input = request.args.get('q')`
- Returned values: `def get_query(): return request.args.get('q')`
- Data structure membership: `data = {'name': request.form['name']}`
- String operations: `query = "SELECT * FROM users WHERE name = " + user_input`
- Format strings: `f"SELECT ... WHERE name = '{user_input}'"`
- Passed as arguments: `execute_query(user_input)`

## Phase 2: Sink identification

### Sink types and their dangerous patterns

**SQL Injection sinks:**
- Python: `cursor.execute(f"...")`, `cursor.execute("..." + var)`, `cursor.execute("..." % var)`, `.raw(query_string)`, `extra(where=[...])`, `RawSQL()`
- JavaScript: `db.query("..." + var)`, `connection.query(\`...\`)`, `sequelize.query("..." + var)`, `mongoose.find({$where: ...})`
- Java: `statement.execute(query)`, `createNativeQuery(query)`, `session.createSQLQuery(query)`, JDBC string concatenation
- PHP: `mysqli_query($conn, "SELECT..." . $var)`, `$pdo->query("..." . $var)`, `"SELECT..." . $_GET['id']`
- Go: `db.Query("SELECT..." + var)`, `db.Exec("..." + userInput)`
- Ruby: `User.where("name = '#{params[:name]}'")`

**Command injection sinks:**
- Python: `os.system(cmd)`, `os.popen(cmd)`, `subprocess.run(cmd, shell=True)`, `subprocess.call(cmd, shell=True)`, `subprocess.Popen(cmd, shell=True)`, `eval(code)`, `exec(code)`
- JavaScript: `child_process.exec(cmd)`, `child_process.execSync(cmd)`, `eval(code)`, `Function(code)()`
- PHP: `system($cmd)`, `exec($cmd)`, `shell_exec($cmd)`, `passthru($cmd)`, `popen($cmd)`, `preg_replace('/.../e', ...)`, backtick operator
- Ruby: `system(cmd)`, `exec(cmd)`, `%x{...}`, backtick operator, `open("|cmd")`
- Go: `exec.Command(parts[0], parts[1:]...)` when parts contain user input

**Path traversal sinks:**
- Python: `open(user_path)`, `os.path.join(base, user_input)` without validation, `send_file(user_path)`, `send_from_directory(base, user_input)`
- JavaScript: `fs.readFile(path)`, `fs.createReadStream(path)`, `path.join(base, userInput)` without restriction
- PHP: `include($path)`, `require($path)`, `file_get_contents($path)`, `fopen($path)`, `readfile($path)`
- Java: `new FileInputStream(path)`, `Files.readAllBytes(Paths.get(path))`

**XSS sinks:**
- JavaScript/Browser: `.innerHTML = data`, `.outerHTML = data`, `document.write(data)`, `insertAdjacentHTML('...', data)`, `location.href = data`
- Server-side templates: Jinja2 `{{ var|safe }}` or `Markup(var)`, EJS `<%- var %>`, Handlebars `{{{ var }}}`, JSP `<%= var %>`, Thymeleaf `th:utext`
- Python: `render_template_string(f"..{user_input}..")`, `jinja2.Template(user_input).render()`
- Node.js/React: `dangerouslySetInnerHTML={{ __html: userInput }}`

**SSRF sinks:**
- Python: `requests.get(url)`, `requests.post(url)`, `urllib.request.urlopen(url)`, `httpx.get(url)`, `aiohttp.ClientSession().get(url)`
- JavaScript: `fetch(url)`, `axios.get(url)`, `http.get(url)`, `request(url)`
- Java: `new URL(url).openConnection()`, `RestTemplate.getForObject(url)`, `WebClient.get().uri(url)`
- PHP: `file_get_contents($url)`, `curl_setopt($ch, CURLOPT_URL, $url)`, `fopen($url)`

**Deserialization sinks:**
- Python: `pickle.loads(data)`, `pickle.load(f)`, `yaml.load(data)` (without Loader=yaml.SafeLoader), `marshal.loads(data)`
- Java: `ObjectInputStream.readObject()`, `XMLDecoder.readObject()`, `XStream.fromXML()`, `JsonTypeInfo.As.WRAPPER_ARRAY`
- PHP: `unserialize($data)`, YAML parsing of untrusted input
- Ruby: `Marshal.load(data)`, `YAML.load(data)` (not safe_load)

**Template Injection sinks:**
- Python: `render_template_string(user_input)`, `jinja2.Environment().from_string(user_input)`
- JavaScript: EJS/Pug/Handlebars template compilation with user-controlled template strings
- Java: Velocity/Freemarker template compilation from user input

## Phase 3: Taint flow tracing

### Tracing algorithm

For each source variable, trace forward through the code:

1. **Direct use**: Source variable used directly as a sink argument → high confidence finding
2. **Assignment chain**: `a = source; b = a; sink(b)` → follow the chain
3. **String concatenation**: `"..." + source` or f-strings → flag the result as tainted
4. **Dictionary/list membership**: `data['key'] = source; sink(data['key'])` → item is tainted
5. **Function argument**: `helper(source)` → if helper calls a sink with the arg, taint flows through
6. **Return value propagation**: `def f(): return source; result = f(); sink(result)` → result is tainted
7. **Object attribute**: `obj.field = source; sink(obj.field)` → attribute is tainted

### Interprocedural analysis

Do not stop tracing at function call boundaries. When a tainted variable is passed to a function, read that function and continue tracing within it. Mark the finding as interprocedural.

Common interprocedural patterns:
- Helper functions that build SQL queries from parameters
- Utility functions that execute system commands
- Wrapper functions around file operations

### Sanitization recognition

A taint path is broken **only if** the sanitization is appropriate for the specific sink type. Mismatched sanitization does not break the path.

| Sink type | Effective sanitization |
|-----------|----------------------|
| SQL | Parameterized queries (`%s`/`?`/`:name` placeholders), ORM query builders (not `.raw()`) |
| Command | `shlex.quote()` (Python), `shell=False` with list args (Python), argument arrays without `shell:true` (Node) |
| Path traversal | `os.path.realpath()` + prefix check, `werkzeug.utils.secure_filename()` + base dir enforcement |
| XSS | `html.escape()`, `markupsafe.escape()`, auto-escaping templates (Jinja2 default, React JSX), `bleach.clean()` |
| SSRF | URL scheme allowlist + hostname allowlist, internal IP block |
| Deserialization | Using safe alternatives: `json.loads()` instead of `pickle`, `yaml.safe_load()` instead of `yaml.load()` |
| SSTI | Not rendering user input as a template; escaping before template insertion |

### Sanitization bypasses to verify

Even when sanitization is present, verify it cannot be bypassed:

- **SQL escaping without parameterization**: `escape(user_input)` then string concatenation is still SQLi in many contexts (charset attacks, second-order)
- **Incomplete allowlists**: `if '..' not in path` misses `%2e%2e`, null bytes, or URL-encoded variants
- **Wrong sanitization for context**: HTML-escaping a value inserted into a JavaScript string block does not prevent XSS
- **Sanitization after dangerous use**: Input validated after it was already logged, stored, or used
- **Type confusion**: PHP loose comparison `== "admin"` vs `=== "admin"`, JavaScript `==` coercion
- **Null byte injection**: `\x00` terminating strings in C/PHP before path suffix checks
- **Encoding bypass**: Double URL encoding, Unicode normalization, charset tricks

## Phase 4: Confidence assignment

Assign confidence based on completeness of the verified trace:

| Confidence | Criteria |
|------------|---------|
| **Confirmed** | Source found, sink found, complete taint path traced, no effective sanitization present |
| **Likely** | Source and sink identified, path strongly implied but one function not read in full |
| **Possible** | Pattern match with partial context — source or sink inferred, not directly read |
| **Unlikely** | Pattern match only, no supporting context — do not report |

Only `Confirmed` and `Likely` findings should appear in the final report.

## Output format per finding

For every confirmed or likely finding, record:

```json
{
  "file": "app/routes/user.py",
  "line_start": 42,
  "line_end": 45,
  "language": "python",
  "vuln_type": "sqli",
  "confidence": "confirmed",
  "title": "SQL Injection via unsanitized username parameter",
  "description": "The 'username' parameter from request.args is interpolated directly into a SQL query string without parameterization.",
  "code_snippet": "query = f\"SELECT * FROM users WHERE name = '{username}'\"",
  "taint_source": "request.args.get('username') at line 40",
  "taint_sink": "cursor.execute(query) at line 45",
  "taint_path": [
    "line 40: username = request.args.get('username')  [SOURCE]",
    "line 42: query = f\"SELECT * FROM users WHERE name = '{username}'\"  [TAINT PROPAGATES]",
    "line 45: cursor.execute(query)  [SINK]"
  ],
  "sanitization_present": false,
  "sanitization_note": "No parameterization. Direct f-string interpolation.",
  "cwe": "CWE-89",
  "owasp": "A03:2021 - Injection",
  "severity": "critical",
  "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = %s', (username,))"
}
```

Every finding must include a populated `taint_path` array showing the step-by-step data flow.
