# input-validator

Read this when checking whether input validation is correctly implemented at entry points.

## Goal

Verify that every user-controlled input is validated before use: correct type, format, range, and content — using allowlists where possible, and that validation cannot be bypassed by encoding tricks, type confusion, or partial matches.

## Phase 1: Enumerate validation points

For every entry point identified in `scan-strategy`, find where validation occurs:

- **Form validation**: framework form classes, schema validators (Pydantic, Marshmallow, Cerberus, Joi, Zod, Yup)
- **Type coercion**: explicit casts, type annotations with enforcement
- **Regex checks**: `re.match`, `re.fullmatch`, pattern validators
- **Length checks**: `len()`, `maxLength`, `minLength`
- **Allowlist checks**: `if value in allowed_set`, enum validation
- **Blocklist checks**: `if banned_pattern in value` (weaker — note separately)

Validation that is absent entirely is the simplest finding. Validation that is present but bypessable is harder to spot.

## Phase 2: Validation bypass patterns

Check every validator for these bypass classes:

### Type juggling / loose comparison

**PHP**: `"0" == false`, `"0e123" == "0e456"` (hash comparison bypass), `strcmp()` returns 0 for array input
- Flag: any security check using `==` instead of `===` in PHP
- Flag: `strcmp($user, $expected) == 0` when `$user` can be an array (returns NULL, which `== 0`)

**JavaScript**: `"1" == 1`, `null == undefined`, `[] == false`
- Flag: security checks with `==` instead of `===`
- Flag: `isNaN()` on untrusted numeric strings

**Python**: No implicit type coercion for comparisons, but watch for:
- `int(request.args.get('id'))` without try/except — exception handling may expose info or bypass logic

### Regex bypass patterns

Flag these regex validator weaknesses:

| Pattern | Bypass |
|---------|--------|
| `re.match(r'\d+', val)` | Matches prefix only — `"123abc"` passes |
| `re.search(r'safe', val)` | Matches substring — `"evil\nsafe"` passes |
| No anchors `^` or `$` | Partial match — add payload after valid prefix |
| Missing `re.DOTALL` | `.` doesn't match `\n` — newline injection possible |
| Missing `re.IGNORECASE` | `Admin` passes `admin` blocklist |
| Catastrophic backtracking | ReDoS possible with complex patterns |

The correct pattern is `re.fullmatch(r'^[a-zA-Z0-9_]+$', val)` (anchored) or equivalently `re.match(r'^[a-zA-Z0-9_]+$', val)`.

### Allowlist vs blocklist

Blocklists should always raise a question. Flag any validation that:
- Checks for known bad characters (`.`, `/`, `..`, `<`, `>`, etc.) instead of checking for known good characters
- Could be bypassed by alternate encodings: URL encoding (`%2e%2f`), double encoding (`%252e`), Unicode equivalents, HTML entities
- Relies on removing bad input rather than rejecting it (sanitization instead of validation)

Correct approach: define exactly what is allowed (allowlist) and reject everything else.

### Length and size validation

- Flag: no maximum length check on string inputs (buffer overflow risk in C/C++, database truncation attacks elsewhere)
- Flag: `maxlength` enforced only client-side (HTML attribute) with no server-side check
- Flag: file upload size checked only after the file is written to disk
- Flag: integer overflow — user-supplied size used in memory allocation without upper bound

### Array and object injection

- Flag: accepting a JSON body without schema validation — extra fields may trigger mass assignment
- Flag: `**kwargs` or spread operator on untrusted JSON with no allowlist
- Flag: `request.POST.dict()` or `.getlist()` when single value is expected

### Path canonicalization

For any path-related input:
- Flag: `os.path.join(BASE, user_input)` without `os.path.realpath()` check
- Flag: prefix check before canonicalization: `if user_path.startswith('/safe/')` — pass `'/safe/../etc/passwd'`
- Correct pattern: `abs = os.path.realpath(os.path.join(BASE, user_input)); assert abs.startswith(BASE)`
- Flag in Windows paths: backslash vs forward slash, UNC paths `\\server\share`

### Numeric input validation

- Flag: user-supplied integer used as array index without bounds check
- Flag: negative number accepted where only positive is valid
- Flag: float accepted where integer is required (e.g., `1.5` becomes `1` in some languages)
- Flag: very large integers used in loops or memory allocations

## Phase 3: Framework-specific validation gaps

### Python / Pydantic

- `model_validate(request.json())` without strict mode may coerce types silently
- `Optional[int]` accepts `None` — check None is handled before use
- Validators on nested models may not run if the outer model fails first

### Python / Django Forms

- `form.cleaned_data` is safe only after `form.is_valid()` returns True
- Flag: accessing `request.POST['key']` directly, bypassing form validation
- `CharField(max_length=...)` truncates silently in some backends — verify DB constraint matches

### JavaScript / Joi or Zod

- `schema.validate(obj)` vs `schema.validateAsync(obj)` — ensure schema is applied
- `.unknown(true)` allows arbitrary extra keys — mass assignment risk
- Flag: validation on query params but not on body, or vice versa

### Java / Bean Validation

- `@Valid` on method parameter only works if AOP/proxy is active — direct instantiation bypasses it
- `@NotNull` with `@RequestBody` still allows `null` JSON values for Optional fields
- Custom `@Constraint` validators: verify `isValid()` returns false for null when null is not allowed

### PHP

- `filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT)` returns null OR false on failure — check for both
- `intval($_GET['id'])` returns 0 for non-numeric — verify 0 is not a valid "not found" state that leaks
- `htmlspecialchars($val)` without `ENT_QUOTES` leaves single quotes unescaped — flag

## Phase 4: Second-order validation

Second-order vulnerabilities occur when data is validated on input but not re-validated on output or when used in a different context later.

Flag:
- User-supplied data stored in DB, then later retrieved and used in a security-sensitive context without re-checking
- File content treated as safe because the filename passed validation
- JWT claims trusted after signature verification without re-checking claim values against the database
- Session data treated as authoritative without checking current state

## Output format

For each entry point, record:

```json
{
  "file": "app/views/search.py",
  "line": 18,
  "entry_point": "GET /search?q=",
  "parameter": "q",
  "validation_present": true,
  "validation_type": "length_check_only",
  "bypass_possible": true,
  "bypass_description": "Only length is checked. No allowlist. Special characters pass through to SQL query at line 34.",
  "finding": "partial_validation",
  "severity": "high"
}
```

Mark each entry point as one of:
- `validated_correctly` — allowlist-based, appropriate for context, cannot be bypassed
- `partial_validation` — some validation present but bypassable or incomplete
- `no_validation` — no validation before dangerous use
- `validation_after_use` — validation occurs too late
