# scan-strategy

Read this first whenever a new `vulnscan scan` request arrives.

## Goal

Build a concrete scan plan before any code is read. A good plan prevents wasted effort and ensures the highest-risk areas are analyzed first.

## Required decisions

### 1. Detect languages and frameworks

Identify every language present in the codebase. Do not scan auto-generated code, vendored dependencies, minified bundles, or test fixtures unless the user asks.

Map each language to its likely framework:

| Language | Frameworks to detect |
|----------|---------------------|
| Python | Flask, Django, FastAPI, Pyramid, Tornado, aiohttp |
| JavaScript/TypeScript | Express, Next.js, Nuxt, Koa, Hapi, NestJS, React, Vue, Angular |
| Java | Spring Boot, Spring MVC, Servlet, Struts, Dropwizard, JAX-RS |
| Go | net/http, Gin, Echo, Fiber, Chi, Gorilla |
| PHP | Laravel, Symfony, CodeIgniter, WordPress, Drupal, Yii |
| Ruby | Rails, Sinatra, Hanami |
| C/C++ | No standard framework; focus on input parsing, memory ops |
| C# | ASP.NET Core, .NET MVC, Blazor, Web API |
| Rust | Actix-web, Axum, Warp, Rocket |

Framework detection matters because each framework has its own:
- Request data access patterns (how user input enters)
- ORM and query patterns (how SQL is constructed)
- Template engine and output patterns (how responses are rendered)
- Auth middleware patterns (how access control works)

### 2. Map the attack surface

Enumerate every entry point: all places where external, user-controlled data can enter the application.

**Primary entry point types:**
- HTTP request parameters, body, headers, cookies
- CLI arguments and environment variables
- File uploads and file content reads
- Inter-process communication (message queues, sockets, pipes)
- Database content that was previously written by users (second-order injection sources)
- Configuration files parsed at runtime
- Deserialized data from external sources

**Entry point signals per language:**

Python/Flask: `@app.route`, `@blueprint.route`, handler function parameters
Python/Django: `urlpatterns`, views receiving `request`, `forms.py`
JavaScript/Express: `app.get`, `app.post`, `router.use`, middleware `(req, res, next)`
Java/Spring: `@Controller`, `@RestController`, `@RequestMapping`, `@GetMapping`, `@PostMapping`
Go/Gin: `r.GET`, `r.POST`, `r.Any`, handler `func(c *gin.Context)`
PHP: `$_GET`, `$_POST`, `$_REQUEST`, `$_FILES`, `$_COOKIE`, `$_SERVER`

List every identified entry point explicitly in your plan. Missing an entry point means missing every vulnerability reachable through it.

### 3. Prioritize files

Not all files carry equal risk. Rank files for deep analysis:

**Highest priority:**
- HTTP request handlers and controllers
- Files that query databases
- Files that execute OS commands
- Auth, session, and token management code
- File upload and file serving code
- Deserialization entry points
- Template rendering code

**High priority:**
- Utility functions called by high-priority files
- Middleware and filters
- Configuration parsing
- Input validation modules

**Lower priority (but do not skip):**
- Helper utilities not on a request path
- Static configuration
- Pure data models with no query construction

### 4. Choose vulnerability categories

Based on the framework and entry points detected, decide which vulnerability categories are in scope. Do not do a generic scan that ignores context.

For each category, confirm at minimum:
- Is there an entry point that could reach this sink type?
- Does the framework or ORM offer protections (e.g., Django ORM auto-escapes SQL)?
- Are there any overrides or raw-mode patterns that disable those protections?

Known framework protections to verify are not bypassed:
- Django ORM: protects against SQLi unless `.raw()`, `extra()`, or `RawSQL()` is used
- Spring Data JPA: protects unless `@Query(nativeQuery=true)` with concatenation is used
- Active Record: protects unless `where("... #{params}")` string interpolation is used
- Hibernate: protects unless `createNativeQuery()` with concatenation is used

### 5. Identify sanitization infrastructure

Before scanning, catalog what sanitization utilities already exist:
- Custom validators, sanitizers, escaping functions
- Allowlist/blocklist modules
- Framework-provided CSRF tokens, HTML escaping, parameterized queries
- Security middleware (CORS, CSP, rate limiting)

Understanding what protection exists tells you where protection is missing.

### 6. Plan analysis order

Execute analysis in this order to maximize signal early:

1. High-complexity entry point handlers (most likely to have missed validation)
2. Database query construction (SQL injection)
3. OS command construction (command injection)
4. File system access with user-controlled paths (path traversal)
5. HTML/template output (XSS)
6. HTTP client calls with user-controlled URLs (SSRF)
7. Deserialization entry points
8. Auth and session management
9. Cryptographic operations and hardcoded secrets
10. Dependency manifest scan

### 7. Fresh or resume decision

Check scan state before starting:

```bash
python3 scripts/scan.py --status-only
```

If an incomplete recent run exists:
- Ask whether to resume or start fresh.
- On resume: skip already-analyzed files, carry forward confirmed findings.
- On fresh: use `--force` to reset state.

## Output contract

Produce a scan plan with:

- detected languages and frameworks
- entry point list (file, line, type)
- files ranked for priority analysis
- vulnerability categories in scope
- sanitization infrastructure found
- analysis order
- fresh or resume decision

State the entry point count explicitly. Do not begin analysis without a completed plan.
