# api-security-reviewer

Read this when auditing REST APIs, GraphQL APIs, gRPC services, or WebSocket endpoints.

## Goal

Find IDOR/BOLA, broken function-level authorization, mass assignment, excessive data exposure, rate limiting gaps, and API-specific vulnerabilities that differ from traditional web app issues.

## Part 1: Object-level authorization (BOLA/IDOR)

This is consistently the #1 API vulnerability. Every endpoint that returns or modifies a specific object by ID must verify the caller owns or is authorized to access that object.

### Finding IDOR

For every route with a resource identifier (numeric ID, UUID, slug), check:

1. Is there an authorization check that ties the resource to the current user?
2. Is that check in the handler, not just middleware that only verifies authentication?

```python
# Flag: authentication present, authorization absent
@app.route('/api/v1/documents/<doc_id>', methods=['GET'])
@jwt_required()
def get_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    return doc.serialize()              # no check that current_user owns doc_id

# Safe
@app.route('/api/v1/documents/<doc_id>', methods=['GET'])
@jwt_required()
def get_document(doc_id):
    doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first_or_404()
    return doc.serialize()
```

```javascript
// Flag: Express
app.get('/api/orders/:id', authenticate, async (req, res) => {
  const order = await Order.findById(req.params.id);   // no owner check
  res.json(order);
});
```

### Indirect IDOR

Nested resources: `/api/projects/123/documents/456` — does the handler verify that document 456 belongs to project 123, AND that the user has access to project 123?

### IDOR in write operations (BOLA)

PUT/PATCH/DELETE endpoints are equally or more critical than GET. Check:

```python
# Flag: update any user's data
@app.route('/api/users/<user_id>/profile', methods=['PUT'])
@login_required
def update_profile(user_id):
    user = User.query.get_or_404(user_id)
    user.update(**request.json)           # any authenticated user can update any profile
```

### IDOR through references in body

```python
# Flag: object referenced in body not verified
@app.route('/api/messages', methods=['POST'])
@login_required
def send_message():
    recipient_id = request.json['recipient_id']
    thread_id = request.json['thread_id']    # does user have access to this thread?
    # no verification that current_user is a member of thread_id
    Message.create(thread_id=thread_id, ...)
```

## Part 2: Function-level authorization

Different HTTP methods or endpoints with different privilege requirements must each be checked independently.

### Admin/privileged endpoint exposure

```python
# Flag: admin endpoint not protected
@app.route('/api/admin/users', methods=['GET'])
@login_required               # only checks authentication, not admin role
def list_all_users():
    return User.query.all()
```

### HTTP method confusion

```python
# Flag: GET is open, but DELETE or PATCH on same resource is not protected differently
@app.route('/api/items/<id>', methods=['GET', 'DELETE', 'PATCH'])
@login_required
def item_operations(id):
    if request.method == 'GET':
        return Item.query.get(id).serialize()
    elif request.method == 'DELETE':
        Item.query.get(id).delete()      # no ownership check for destructive ops
```

### Version-specific authorization gaps

- `/api/v1/admin/users` is protected; `/api/v2/admin/users` is a new unprotected endpoint
- Old API version still deployed with weaker security: `/api/v1/legacy/export`
- Internal vs external version: internal API path not restricted to internal network

## Part 3: Mass assignment

When a request body is mapped directly to a model without an allowlist, attackers can set fields they shouldn't be able to.

### Python / Django / SQLAlchemy

```python
# Flag: direct **kwargs from request body
user = User(**request.json)     # can set is_admin, role, etc.
user.update(**request.get_json())

# Flag: Django model update
user.__dict__.update(request.POST.dict())

# Safe: explicit field allowlist
user.name = request.json['name']
user.email = request.json['email']
# OR: define allowed_fields in serializer
```

### JavaScript / Express

```javascript
// Flag: spread request body into model
const user = new User({ ...req.body });   // can set admin: true
User.findByIdAndUpdate(id, req.body);    // unfiltered update

// Safe
User.findByIdAndUpdate(id, {
  name: req.body.name,
  email: req.body.email
});
```

### Java / Spring

```java
// Flag: @RequestBody to full entity
@PostMapping("/users")
public User createUser(@RequestBody User user) {  // user.setAdmin() possible
    return userRepository.save(user);
}

// Safe: use DTO with only allowed fields
@PostMapping("/users")
public User createUser(@RequestBody UserCreateDTO dto) {
    User user = new User(dto.getName(), dto.getEmail());
    return userRepository.save(user);
}
```

### Sensitive fields to look for

After finding mass assignment, check which sensitive fields exist on the model: `is_admin`, `role`, `permissions`, `verified`, `email_verified`, `account_balance`, `subscription_tier`, `created_at`, `password`, `api_key`.

## Part 4: Excessive data exposure

APIs that return full objects when only a subset is needed expose PII, internal IDs, and sensitive fields.

Flag:
- Serialization returns all model fields by default: `return user.to_dict()` includes password_hash, api_key, internal_flags
- GraphQL resolvers resolve all fields without field-level authorization
- List endpoints returning N objects with full details when only IDs/names are needed
- Internal fields (database IDs, created_at, updated_at, internal flags) in public API responses

```python
# Flag: returns full user object
def get_user_profile(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_dict())    # includes password_hash, api_key, admin_notes

# Safe: explicit response schema
return jsonify({
    'id': user.public_id,
    'name': user.name,
    'bio': user.bio
})
```

## Part 5: Rate limiting and resource consumption

### Missing rate limiting

Flag endpoints with no rate limiting:
- Authentication: login, password reset, OTP verification — brute force risk
- Account enumeration endpoints: registration, password reset (can enumerate valid emails)
- Expensive operations: file uploads, report generation, email sending
- Public data endpoints: can be scraped without throttling

### GraphQL-specific: query complexity and depth

```graphql
# Malicious query: deeply nested, exponential DB load
query {
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              # unlimited depth — can cause DoS
            }
          }
        }
      }
    }
  }
}
```

Check for:
- Query depth limit (max 5–10 levels typical)
- Query complexity limit (field count × resolver cost)
- Batch query limit: `query { u1: user(id:1) { ... } u2: user(id:2) { ... } }` — can enumerate all IDs
- Introspection enabled in production (disclose schema structure)
- Rate limiting per IP or per token on GraphQL endpoint

### WebSocket security

- Missing authentication on WebSocket upgrade
- Message origin not validated
- Missing rate limiting on message send
- Sensitive data broadcast to all connected clients instead of targeted delivery
- WebSocket not secured over WSS (ws:// vs wss://)

## Part 6: API design security

### Sensitive data in URLs

- API keys, tokens, passwords in query parameters: `/api/export?token=abc123` → logged in server logs, browser history, Referer headers
- User IDs as sequential integers vs UUIDs → enumerable

### HTTP response headers

Check API responses for:
- `Content-Type: application/json` — missing or wrong type can enable MIME sniffing
- `X-Content-Type-Options: nosniff`
- `Cache-Control: no-store` for sensitive endpoints (profile, payment, auth)
- CORS: `Access-Control-Allow-Origin: *` for authenticated endpoints → any site can make credentialed requests

### API key management

- API keys returned in response body and not stored hashed
- Long-lived API keys with no expiry
- API keys with overly broad permissions (no scoping)
- API key rotation mechanism absent

## Output format

```json
{
  "file": "api/routes/documents.py",
  "line": 28,
  "category": "idor",
  "endpoint": "GET /api/v1/documents/:id",
  "title": "IDOR — any authenticated user can read any document",
  "description": "Document retrieval checks authentication but not document ownership. Authenticated users can retrieve documents belonging to other users by incrementing the document ID.",
  "reproduction": "Authenticate as user A. Note document ID from /api/v1/my-documents. Change ID to another value. The response returns the other user's document.",
  "impact": "Full read access to all user documents in the system.",
  "cwe": "CWE-639",
  "owasp_api": "API1:2023 - Broken Object Level Authorization",
  "severity": "high"
}
```
