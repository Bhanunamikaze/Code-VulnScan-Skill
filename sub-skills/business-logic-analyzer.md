# business-logic-analyzer

Read this when analyzing business logic flaws, race conditions, state machine vulnerabilities, and workflow bypasses.

## Goal

Find vulnerabilities that arise from incorrect assumptions about how users will interact with the application — not from missing input sanitization, but from missing enforcement of business rules. These are frequently missed by automated scanners and have high real-world impact.

## Part 1: Workflow and state machine analysis

### Step sequence enforcement

Multi-step workflows (checkout, registration, password reset, verification) must enforce step ordering server-side. Never trust the client to follow the intended sequence.

Check every multi-step flow:
1. Can a step be skipped by directly requesting the URL of a later step?
2. Is completion of each previous step verified server-side before allowing the next?
3. Can the flow be reversed or replayed after completion?

```python
# Flag: step enforcement based only on session flag the client previously set
@app.route('/checkout/confirm')
def confirm_order():
    if session.get('cart_validated'):   # set in previous step, not re-verified
        process_payment()               # can be reached without payment selection
```

Correct: re-verify all preconditions at each step.

### State transition attacks

Map all object states and verify only valid transitions are permitted:

Example: Order states: `draft → placed → paid → shipped → delivered → refunded`

Check:
- Can an order be refunded without being in `paid` or `shipped` state?
- Can a draft order be marked `shipped` directly?
- Can state be set via a request parameter instead of server-side logic?

```python
# Flag: state supplied by client
@app.route('/api/orders/<id>/update')
def update_order(id):
    order = Order.get(id)
    order.status = request.json['status']   # client controls state transition
    order.save()
```

### Feature flag and A/B test bypasses

- Feature flags stored in cookies or client-visible tokens — users can enable hidden features
- A/B test group membership not enforced server-side — price manipulation between groups

## Part 2: Numeric and quantity manipulation

### Price and discount logic

Flag any arithmetic on prices, discounts, quantities, or totals where the inputs come from the client:

```python
# Flag: price from client
total = request.json['quantity'] * request.json['price_per_item']

# Flag: discount calculated on client-side total
if request.json['total'] < 0:   # negative total — refund to attacker
    process_payment(request.json['total'])
```

Check:
- Integer overflow / underflow: `uint` wrapping, very large quantities producing negative totals
- Floating-point precision abuse: `0.1 + 0.2 != 0.3` exploited in financial calculations
- Currency unit confusion: cents vs dollars, satoshi vs BTC
- Negative quantities in cart/transfer creating credit
- Free items by setting price to 0 before checkout completes

### Coupon and voucher logic

- Coupon applied multiple times in same transaction
- Coupon shared across users when it should be single-use
- Coupon validity checked client-side only
- Stack discounts to get negative price

## Part 3: Race conditions

### Classic TOCTOU (Time-of-Check-Time-of-Use)

The pattern: check a condition, then act on it — if the state changes between check and act, behavior is incorrect.

```python
# Flag: TOCTOU on balance
def transfer_funds(user_id, amount, target_id):
    balance = get_balance(user_id)          # check
    if balance >= amount:
        deduct_balance(user_id, amount)     # use — race window here
        add_balance(target_id, amount)

# Concurrent calls: balance read twice before either deduction runs → double spend
```

Correct: use database-level atomic operations: `UPDATE accounts SET balance = balance - %s WHERE id = %s AND balance >= %s`

### Coupon / one-time-use race condition

```python
# Flag: check-then-mark as used in non-atomic operation
def use_coupon(coupon_code, user_id):
    coupon = Coupon.get(coupon_code)
    if coupon.uses_remaining > 0:           # check
        apply_discount()
        coupon.uses_remaining -= 1          # use — race: two requests between check and decrement
        coupon.save()
```

### File TOCTOU

```python
# Flag: check existence, then act
if not os.path.exists(target_path):         # check
    shutil.copy(source, target_path)        # use — symlink swap in between

# Same pattern for os.access() → open()
if os.access(path, os.R_OK):               # check
    with open(path, 'r') as f:             # use — file replaced between check and open
        data = f.read()
```

### Token / OTP race condition

- OTP consumed only after successful use, not immediately marked used → replay in parallel requests
- Password reset token not atomically invalidated on use → parallel requests with same token

## Part 4: Authorization logic errors

### Context-dependent authorization

Permission checks that depend on context (project membership, team membership, subscription tier) are prone to:

- Parameter pollution: `?user_id=victim&user_id=self` — which one gets checked vs used?
- Object ID vs object type confusion: authorization checks object ID 42, but type changes between check and use
- Indirect access: no direct access to resource A, but resource B references A and has weaker controls

### Privilege level assumption errors

```python
# Flag: checking role presence, not level
if 'editor' in user.roles:          # 'admin' role does not include this check
    allow_edit()                    # admin should also be able to edit
# Alternatively: admin access paths not checked at all because "admins can do everything"
```

### Multi-tenant isolation

In SaaS/multi-tenant systems:
- Is every database query scoped by `tenant_id` / `organization_id`?
- Can a user in tenant A access data from tenant B by guessing IDs?
- Are tenant IDs validated server-side (not trusted from JWT payload without DB verification)?

```python
# Flag: tenant ID from user input without verification
tenant_id = request.json['tenant_id']    # user can supply any tenant_id
records = Record.query.filter_by(tenant_id=tenant_id).all()
```

## Part 5: API abuse patterns

### Mass operation attacks

- Bulk delete/update endpoint without per-item authorization check
- Batch API that accepts 10,000 items and processes them without rate limiting
- `DELETE /api/users` vs `DELETE /api/users/123` — bulk vs single resource

### Account takeover via logic flaw

- Email change without re-authentication → account takeover if email MFA is used
- Username change to an existing user → session confusion
- Merging accounts without verifying ownership of both
- Password reset invalidates all sessions but active JWT tokens remain valid

## Output format

```json
{
  "file": "app/services/payment.py",
  "lines": "45-62",
  "category": "race_condition",
  "title": "Double-spend via concurrent balance deduction race condition",
  "description": "balance check and deduction are non-atomic. Two concurrent /transfer requests can both read the same balance before either deduction runs, allowing double-spend.",
  "reproduction": "Send two concurrent POST /api/transfer requests with the same payload. Both will pass the balance check before either updates the DB.",
  "impact": "Users can spend the same balance multiple times, causing negative balances or financial loss.",
  "remediation": "Use an atomic SQL UPDATE with balance constraint: UPDATE accounts SET balance = balance - %s WHERE id = %s AND balance >= %s. Check rows_affected == 1.",
  "cwe": "CWE-362",
  "severity": "high"
}
```
