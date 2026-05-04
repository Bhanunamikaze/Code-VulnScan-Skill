---
name: regex-analyzer
description: ReDoS detection sub-skill
---

# regex-analyzer

Read this when analyzing regular expressions for ReDoS (Regular Expression Denial of Service) vulnerabilities, or when the `scan-strategy` sub-skill identifies regex-heavy code.

## Goal

Identify regular expressions whose worst-case matching time is super-linear with respect to input length, so that a crafted input can force the engine to spend seconds or minutes on a single match call — effectively causing a denial of service.

## What is ReDoS?

Most programming languages implement regex using a backtracking NFA (Non-deterministic Finite Automaton) engine. When the input does not match, the engine must exhaustively explore all possible match paths before giving up. With certain pattern structures, the number of paths grows exponentially or polynomially with input length.

### Catastrophic backtracking

Occurs when quantifier nesting creates an exponential number of ways to partition the input. Example: `(a+)+` matching `"aaaaaaaaaaaaaaaaaab"` — the engine tries every way to split the `a` sequence across the inner and outer repetitions before concluding no match.

Input length 30: ~1 billion backtracks. Input length 35: ~32 billion. The curve is `2^n`.

### Polynomial backtracking

Less severe but still exploitable. Patterns with many independent quantifiers applied to overlapping character sets cause `O(n^k)` behavior where `k` is the number of quantifiers. Rarely catastrophic from a single request but can degrade under concurrent load.

## Pattern structures that cause ReDoS

### Category 1: Nested quantifiers (catastrophic)

The outer quantifier wraps a group that itself contains a quantifier over the same or broader character class.

```
(a+)+         — the canonical example
(a+)*         — same: + inside, * outside
([a-z]+)*     — character class variant
(\w+)+        — word characters, very common in real code
(.+)+         — dot-all variant — matches almost anything
(a{1,10})+    — bounded inner, unbounded outer — still catastrophic
((ab|cd)+)+   — alternation inside quantified group, quantified again
```

Detection rule: a capturing or non-capturing group containing `*`, `+`, or `{n,}` is itself followed by `*`, `+`, or `{n,}`.

### Category 2: Alternation with overlapping character classes (exponential)

When alternation branches can each match the same character at any given position, the engine tries all combinations.

```
(a|aa)+        — both branches match 'a', engine tries all splits
(a|a?)+        — a? matches empty or 'a', creating exponential paths
([a-z]|[a-zA-Z])+   — overlapping classes
(\w|\d)+       — \d is a subset of \w — overlapping
(ab|a)+b       — common prefix in alternation branches
```

Detection rule: inside an alternation, two or more branches share overlapping character sets and the whole group has an unbounded repetition.

### Category 3: Unbounded repetition of groups containing alternation (polynomial → exponential)

```
(a|b|c|d)*     — 4-way alternation under *
([a-zA-Z0-9._-]+@[a-zA-Z0-9-]+\.)+   — common in naive email validators
(https?|ftp)://([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}   — URL validators
```

Email and URL validators are among the most common real-world ReDoS vectors. Always examine them.

### Category 4: Multiple adjacent quantifiers without anchoring

```
\s*\w+\s*\w+\s*\w+\s*    — many \s* around \w+ — polynomial
[a-z]*[a-z]*[a-z]*        — repeated same-class quantifiers — exponential
```

### Real-world dangerous patterns (flag these)

| Pattern | Risk | Notes |
|---------|------|-------|
| `^([a-zA-Z0-9])(([\\-.]|[_]+)?([a-zA-Z0-9]+))*(@)([a-z]([-a-z0-9]*[a-z0-9])?)(\\.[a-z]([-a-z0-9]*[a-z0-9])?)*$` | Catastrophic | Common naive email validator |
| `^(\w+\s?)*$` | Catastrophic | "Words with spaces" check |
| `(\w+)+([\w._%+-]+@[\w.-]+\.[a-zA-Z]{2,})+` | Exponential | Email in larger pattern |
| `([a-z]+)*` | Catastrophic | Lowercase word check |
| `^(([a-z])+.)+[A-Z]([a-z])+$` | Catastrophic | CamelCase validator |
| `(.*a){20,}` | Exponential | "20 or more a's" pattern |
| `<([a-z]+)([^<]+)*(?:>(.*)<\/\1>|\s+\/>)` | Polynomial | Naive HTML tag parser |

## Analysis approach

### Step 1: Extract all regex patterns

Locate every regex literal, `compile()` call, or regex function invocation in the file. The `scripts/regex_analyzer.py` tool automates this for Python, JavaScript, TypeScript, Java, Kotlin, PHP, Ruby, Go, and C#.

### Step 2: Check nesting depth of quantifiers

For each pattern:
1. Strip escaped characters (`\\.` → placeholder).
2. For each group `(...)`, determine if the group body contains a quantifier (`*`, `+`, `{n,}`).
3. Check if the group itself is followed by a quantifier.
4. If yes → **nested quantifier** → catastrophic backtracking candidate.
5. Recurse for groups inside groups (depth-2+ nesting multiplies the risk).

### Step 3: Check alternation with overlapping character classes

1. For each alternation `(A|B|C)`:
   - Extract the character set that each branch can match at position 0.
   - Check for intersection between any two branches.
2. If the alternation group has an outer quantifier and branches overlap → exponential backtracking.

### Step 4: Check unbounded repetition of groups containing quantifiers

Even without strict nesting, `(\w+\s*)+` creates polynomial paths because `\w+` and `\s*` together can match the same whitespace in multiple ways as the outer `+` re-attempts.

### Step 5: Assess anchoring

A fully anchored pattern `^...$` reduces risk because the engine fails fast at the string boundaries. It does not eliminate catastrophic backtracking but reduces the practical exploitability window. Note: `^` alone (no `$`) or `$` alone still allows exponential backtracking on the unanchored side.

### Step 6: Count quantifiers

Patterns with 4+ quantifiers and no anchoring are polynomial at minimum. Flag for manual review.

## Language-specific notes

### Python (`re` module)

- Uses a **backtracking NFA** — fully vulnerable to ReDoS.
- No built-in timeout. A catastrophic pattern will block the Python thread indefinitely.
- Mitigation: use the `regex` module (third-party) which supports atomic groups and possessive quantifiers; or use `re2` bindings (`google-re2` package) which use a linear-time engine.
- `re.DOTALL` flag makes `.` match newlines — widens the attack surface for dot-based nested quantifiers.
- Python 3.11+ has some improvements but the NFA engine remains vulnerable.

```python
# Vulnerable — catastrophic
import re
pattern = re.compile(r'(\w+)+$')
re.match(pattern, 'aaaaaaaaaaaaaaaaaaaaa!')  # hangs

# Safe — use re2
import re2
pattern = re2.compile(r'(\w+)+$')  # re2 rejects or safely handles
```

### JavaScript (`RegExp`)

- Uses a **backtracking NFA** in V8/SpiderMonkey — fully vulnerable.
- Node.js: a blocking regex in the event loop blocks ALL requests — high severity in server-side code.
- No native timeout. Mitigation: `node-re2` package or `safe-regex` linter, or timeout via `Worker` thread.
- ES2018 introduced named capture groups and lookbehind — no safety improvement.

```javascript
// Vulnerable
const re = /^(\w+\s?)*$/;
re.test('aaaaaaaaaaaaaaaaaaaaaaaaa!');  // hangs Node.js

// Safe alternative
const re2 = require('re2');
const r = new re2('^(\\w+\\s?)*$');
```

### Java (`java.util.regex`)

- Uses a **backtracking NFA** — fully vulnerable.
- **No built-in timeout** — thread will hang until JVM timeout or OutOfMemoryError from the call stack.
- `Pattern.compile()` with a complex pattern and `Matcher.matches()` is the most common attack vector.
- Mitigation: use `com.google.re2j` library, or run matching in a separate thread with `Future.get(timeout)`.

```java
// Vulnerable
Pattern p = Pattern.compile("(a+)+$");
p.matcher("aaaaaaaaaaaaaaaaaaaaaaaaa!").matches();  // hangs

// Safe — re2j
import com.google.re2j.Pattern;
Pattern p = Pattern.compile("(a+)+$");  // re2j — linear time
```

### Go (`regexp` package)

- Uses **RE2** — a linear-time NFA/DFA hybrid. **Immune to catastrophic backtracking.**
- `regexp.Compile()` and `regexp.MustCompile()` both use RE2.
- Lookahead and lookbehind are NOT supported — attempts to use them return a compile error.
- Flag: if code uses a third-party regex library (e.g., `dlclark/regexp2`) that adds PCRE support, those patterns are vulnerable.

### PHP (`preg_*` functions — PCRE)

- Uses **PCRE** backtracking NFA — fully vulnerable.
- Has a `pcre.backtrack_limit` ini setting (default 1,000,000) which throws `PREG_BACKTRACK_LIMIT_ERROR` but does NOT prevent CPU exhaustion before the limit.
- Mitigation: check `preg_last_error()` after every `preg_match()`, use input length limits, rewrite patterns.

### Ruby (`Regexp`)

- Uses **Oniguruma** — a backtracking NFA. Vulnerable.
- Ruby 2.0+ supports atomic groups `(?>...)` and possessive quantifiers — use them.
- No built-in timeout for `Regexp#match`. Use `Timeout.timeout` as a last resort (heavy-handed).

### C# (`System.Text.RegularExpressions`)

- Uses a **backtracking NFA** — fully vulnerable.
- .NET 7+ introduced `RegexOptions.NonBacktracking` — a linear-time engine. Use it.
- Mitigation: `Regex` constructor accepts a `matchTimeout` parameter — always set it.

```csharp
// Vulnerable — no timeout
var r = new Regex(@"(a+)+$");

// Safe — timeout
var r = new Regex(@"(a+)+$", RegexOptions.None, TimeSpan.FromMilliseconds(100));

// Safe — non-backtracking (.NET 7+)
var r = new Regex(@"(a+)+$", RegexOptions.NonBacktracking);
```

## How to use `scripts/regex_analyzer.py`

The script scans a directory tree, extracts all regex patterns using language-aware extractors, and applies the complexity analysis described above.

```bash
# Scan a directory and print JSON results
python3 scripts/regex_analyzer.py --path /path/to/repo

# Write results to file with pretty-printing
python3 scripts/regex_analyzer.py --path /path/to/repo --output results.json --pretty
```

### Output fields

| Field | Meaning |
|-------|---------|
| `severity` | `high` (catastrophic, unanchored), `medium` (exponential, unanchored), `low` (polynomial, unanchored) |
| `complexity` | `catastrophic` / `exponential` / `polynomial` / `linear` |
| `anchored` | Whether `^` at start and `$` at end are present |
| `nested_quantifiers` | Boolean — primary ReDoS indicator |
| `alt_common_prefix` | Boolean — alternation with overlapping prefixes |
| `quantifier_count` | Total number of `*`, `+`, `?`, `{n,m}` tokens |

### Interpreting results

- `high` + `nested_quantifiers: true`: prioritize — verify with crafted input, remediate before deployment.
- `medium` + `alt_common_prefix: true`: review — verify actual exploitability.
- `low`: note — may be exploitable under load, lower urgency.
- All Go findings: if using stdlib `regexp`, these are false positives; re-check if third-party regex library is imported.

## Remediation

### 1. Atomic groups (eliminate backtracking into the group)

Supported: Ruby, PCRE (PHP), Java (via `(?>...)`), .NET.

```
# Instead of: (\w+)+
# Use atomic: (?>\w+)+   — engine commits to the longest match, no backtracking
```

### 2. Possessive quantifiers (same effect as atomic, shorter syntax)

Supported: Java, PHP/PCRE, Ruby, .NET.

```
# Instead of: (\w+)+
# Use:         \w++    — possessive + never gives back characters
```

### 3. Use the RE2 engine

RE2 guarantees linear-time matching by construction (no lookahead/lookbehind).

| Language | RE2 package |
|----------|-------------|
| Python | `google-re2` (`pip install google-re2`) |
| JavaScript/Node | `node-re2` (`npm install re2`) |
| Java | `com.google.re2j:re2j` |
| Go | Native stdlib (already RE2) |
| C# | `RE2.Managed` NuGet package or `RegexOptions.NonBacktracking` (.NET 7+) |

### 4. Rewrite patterns to eliminate ambiguity

```
# Original (catastrophic): ^(\w+\s?)*$
# Rewritten (linear):      ^\w+(\s\w+)*$
# Explanation: removes the ambiguity — only one way to parse each word boundary
```

### 5. Input length limits

Apply before the regex call. Even a catastrophic pattern is safe if input is limited to a reasonable length.

```python
MAX_INPUT = 1000
if len(user_input) > MAX_INPUT:
    raise ValueError("Input too long")
re.match(pattern, user_input)
```

### 6. Anchoring

Always anchor patterns that validate a complete string. `^...$` limits the backtracking window and prevents partial-match scenarios where the engine tries the pattern at every position.

### 7. Timeout (last resort)

Use only when rewriting the pattern or switching engines is not feasible.

```python
import signal
def timeout_handler(signum, frame): raise TimeoutError()
signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(1)  # 1-second timeout
try:
    result = re.match(pattern, user_input)
finally:
    signal.alarm(0)
```

Note: `signal.SIGALRM` is Unix-only and not safe in multi-threaded applications.

## Verification: crafting a malicious input

The standard technique for confirming ReDoS:

1. Identify the repeating unit in the pattern (e.g., `\w` in `(\w+)+`).
2. Create a string entirely composed of that unit, followed by a character that forces a full mismatch.
3. Measure execution time for increasing input lengths.

```python
import re, time

pattern = re.compile(r'(\w+)+$')
for n in [10, 15, 20, 25, 30]:
    s = 'a' * n + '!'      # 'a' matches \w, '!' forces mismatch
    t0 = time.time()
    pattern.match(s)
    elapsed = time.time() - t0
    print(f"n={n:3d}  time={elapsed:.4f}s")
```

Expected output for a catastrophic pattern:
```
n= 10  time=0.0001s
n= 15  time=0.0020s
n= 20  time=0.0640s
n= 25  time=2.0480s
n= 30  time=65.536s   ← exponential growth
```

A safe (linear) pattern shows constant or slowly growing times across all `n`.

For patterns that accept Unicode or whitespace, adjust the repeating unit accordingly (`' '` for `\s`, `'α'` for broad Unicode classes, etc.).

## Output format per finding

```json
{
  "file": "app/validators.py",
  "line_start": 24,
  "language": "python",
  "vuln_type": "redos",
  "severity": "high",
  "complexity": "catastrophic",
  "pattern": "(\\w+)+$",
  "anchored": false,
  "nested_quantifiers": true,
  "cwe": "CWE-1333",
  "owasp": "A04:2021 - Insecure Design",
  "title": "ReDoS — catastrophic backtracking in input validator",
  "description": "Nested quantifier (\\w+)+ with no anchoring. Crafted input of 30+ word characters followed by a non-word character causes exponential backtracking.",
  "remediation": "Rewrite as ^\\w+(\\s\\w+)*$ or use google-re2. Apply input length limit (max 500 chars) before matching.",
  "verification": "python3 -c \"import re,time; p=re.compile(r'(\\\\w+)+$'); s='a'*25+'!'; t=time.time(); p.match(s); print(time.time()-t)\""
}
```
