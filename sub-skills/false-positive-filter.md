# false-positive-filter

Read this before finalizing any findings. Apply the three-pass protocol to every candidate before it reaches the confirmed list.

## Goal

Eliminate false positives without discarding real vulnerabilities. A finding that survives all three passes is genuinely exploitable. A finding that fails any pass is removed or downgraded.

The cost of a false positive: erodes trust in the report, wastes developer time, and dilutes attention from real issues.
The cost of a false negative: a real vulnerability ships.

Default to skepticism on candidates. Confirm on evidence.

## Three-pass protocol

Every candidate finding must complete all three passes in order.

---

### Pass 1: Source reachability

**Question: Can an external, untrusted party actually control this value?**

Disqualify if:
- The "source" is actually hardcoded in the application (constants, default config values loaded at startup without user override)
- The source is set only by authenticated administrators through a privileged endpoint (not exploitable by attackers without prior access)
- The source is an internal service-to-service call where the caller is trusted and its inputs are already validated
- The source is read from a file that only the application owner can modify (not a config file writable by users)
- The "user input" is a numeric ID that is integer-parsed and range-checked before reaching the sink (no injection possible through a validated integer)

Downgrade to `possible` (not `confirmed`) if:
- The source is indirectly user-controlled through a chain of 3+ function calls that are not all read
- The source is a session value — confirm whether users can set arbitrary session values or only predefined ones

Confirm if:
- The value comes directly from HTTP request params, body, headers, cookies with no mandatory transformation
- The value comes from a file read where the filename is user-supplied
- The value was previously stored in the database from a user-controlled input (second-order)

---

### Pass 2: Path completeness

**Question: Does the tainted value actually reach the sink? Read every line of the path.**

Disqualify if:
- There is a sanitization function on the path that was missed during initial analysis
- The tainted variable is reassigned to a safe, hardcoded value before the sink
- The code path to the sink is unreachable (dead code: unreachable branch, feature flag always false, deprecated endpoint not in routing)
- The sink is inside a try/except that catches all exceptions and returns an error before damage is done (note: this is a defense but not a fix — downgrade but don't remove if the exception handling itself is broken)

Downgrade to `likely` if:
- One intermediate function in the call chain was not read — note which one
- The sink is inside a conditional that depends on a value that could not be fully determined

Confirm if:
- Every step in the taint path was read directly from source code and no sanitization was found

**Mandatory check — framework ORM protections:**

If the sink involves a database framework, verify the framework's protection is not overridden:
- Django ORM: `.raw()`, `.extra()`, `RawSQL()`, `connection.execute()` bypass ORM protection — confirm raw SQL is used
- SQLAlchemy: `text()` with string concatenation bypasses ORM protection — confirm `text()` is used with f-strings or `+`
- ActiveRecord: `where("column = '#{val}'")`  bypasses AR protection — confirm string interpolation
- Hibernate: `createNativeQuery()` with concatenation bypasses JPA — confirm

If the framework's safe API is used correctly, the finding is a false positive.

---

### Pass 3: Exploitability context

**Question: Even if the path exists, can an attacker realistically exploit it?**

Reduce confidence (do not remove) if:
- Exploitation requires authentication but the auth bypass is a separate unconfirmed finding — note the dependency
- The payload must survive multiple layers of transformation (e.g., JSON parse → ORM → templating) that may neutralize it — test each layer
- The application is internal-only (no public network access) — note as a qualifier, not a disqualification

Disqualify if:
- The "sink" is a log statement — logging user input is bad practice but is not itself exploitable as an injection unless the log system interprets format strings (e.g., Log4Shell pattern — if so, confirm separately)
- The SQL sink only performs a SELECT and the ORM returns typed objects, not raw SQL execution results — read escalation is a data exposure issue, not SQLi for code execution
- The XSS sink is in an admin panel accessible only to already-authenticated admins with equivalent permissions — note as low risk rather than critical

**Exception — do not disqualify:**
- Never disqualify because "the application is well-coded in general"
- Never disqualify because "the developer probably intended this to be safe"
- Never disqualify because the pattern is common — common patterns are exploited at scale

---

## Adversarial challenge protocol

Before assigning a final verdict to any `confirmed` finding, write a 2-sentence argument for why it should be a false positive. If you cannot produce a credible argument, the finding earns its confidence level. If you can produce a credible argument, investigate it before deciding.

Include the challenge argument in the finding's `false_positive_analysis` field.

Example:
```
challenge: "The variable 'name' is derived from request.args but the route decorator includes @login_required — only authenticated users can reach this endpoint. However, authenticated users can still be attackers (privilege escalation, insider threat), and the SQL injection here could allow any authenticated user to access all accounts. Finding stands."
```

---

## Downgrade table

| Scenario | Action |
|----------|--------|
| Source is hardcoded or admin-only | Remove |
| ORM protection is active (correct API used) | Remove |
| Dead code path | Remove |
| Sanitization found that was initially missed | Remove |
| One intermediate function not read | Downgrade to `likely` |
| Requires prior authentication to reach | Keep but note as qualifier, ensure severity reflects access requirement |
| Exploitation is complex but possible | Keep `confirmed`, note complexity in description |
| Second-order injection | Keep, note as second-order in title |

---

## Output: reviewed findings list

After applying the three-pass protocol, output:

- **Confirmed**: passed all three passes with no disqualifying factors
- **Likely**: passed with one unverified step or minor qualifier
- **Removed**: explain which pass failed and why (brief)

Do not include removed findings in the final report. Do include the removal reason in the workspace output for auditability.
