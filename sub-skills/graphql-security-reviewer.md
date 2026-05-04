---
name: graphql-security-reviewer
description: GraphQL-specific security review sub-skill
---

# graphql-security-reviewer

Read this when a codebase imports a GraphQL library or exposes a `/graphql` endpoint. Works alongside `taint-analyzer` and `auth-reviewer`.

## Goal

Find GraphQL-specific vulnerabilities: introspection exposure, missing query depth and complexity limits, batching abuse vectors, resolver-level authorization gaps, N+1 data leakage, subscription endpoint security, SSRF via schema stitching, and type system abuse.

## Detecting GraphQL in the codebase

Look for these imports and framework identifiers:

| Language | Indicators |
|----------|-----------|
| JavaScript/TypeScript | `graphql`, `apollo-server`, `@apollo/server`, `express-graphql`, `graphql-yoga`, `pothos-graphql`, `nexus`, `type-graphql` |
| Python | `graphene`, `strawberry`, `ariadne`, `graphql-core` |
| Java/Kotlin | `graphql-java`, `com.graphql-java-kickstart`, `dgs-framework` (Netflix DGS) |
| Go | `gqlgen`, `graphql-go`, `thunder` |
| Ruby | `graphql-ruby` (`graphql` gem) |
| PHP | `webonyx/graphql-php`, `lighthouse-php` |
| .NET/C# | `Hot Chocolate`, `GraphQL.NET` (`GraphQL`), `strawberry-shake` |

## Issue 1: Introspection enabled in production

### What it is

Introspection allows any client to query the full schema — all types, fields, mutations, and their arguments. This is intended for development tooling but should be disabled in production. It gives attackers a complete map of the API surface.

### Detection patterns

**JavaScript/Node (Apollo Server):**
```javascript
// Flag: introspection not explicitly disabled (default is enabled)
const server = new ApolloServer({
  typeDefs,
  resolvers,
  // introspection not set — defaults to true
});

// Also flag: explicitly enabled in non-dev environments
const server = new ApolloServer({
  introspection: true,   // hardcoded true — always enabled
});

// Safe:
const server = new ApolloServer({
  introspection: process.env.NODE_ENV !== 'production',
});
```

**Python/Graphene:**
```python
# Flag: no introspection control
app.add_url_rule('/graphql', view_func=GraphQLView.as_view(
    'graphql', schema=schema
))

# Safe:
app.add_url_rule('/graphql', view_func=GraphQLView.as_view(
    'graphql', schema=schema,
    graphiql=False  # also disable GraphiQL IDE in production
))
# Plus disable introspection at schema level via middleware
```

**Python/Strawberry:**
```python
# Flag
@strawberry.type
class Query:
    ...
# No DisableIntrospection extension added

# Safe
from strawberry.extensions import DisableIntrospection
schema = strawberry.Schema(query=Query, extensions=[DisableIntrospection])
```

**graphql-ruby:**
```ruby
# Flag: no introspection control
class MySchema < GraphQL::Schema
  query Types::QueryType
end

# Safe
class MySchema < GraphQL::Schema
  disable_introspection_entry_points if Rails.env.production?
end
```

### Detection check

1. Search for `introspection` keyword near server/schema initialization.
2. If not found, the default is usually `true` — flag as likely enabled.
3. Verify no middleware or directive disables it.

### Remediation

Disable introspection in production. Keep it enabled in development/staging behind authentication. Alternatively, use persisted queries and disable ad-hoc introspection entirely.

---

## Issue 2: Query depth and complexity limits missing

### What it is

Without depth limits, an attacker can send arbitrarily nested queries that cause exponential resolver calls:

```graphql
{
  user {
    friends {
      friends {
        friends {
          friends {
            friends { id name }
          }
        }
      }
    }
  }
}
```

Without complexity limits, an attacker can request thousands of items at multiple levels to overwhelm the server.

### Detection patterns

**JavaScript/Apollo — look for missing depth-limit middleware:**
```javascript
// Flag: no depth/complexity plugin
const server = new ApolloServer({
  typeDefs,
  resolvers,
  // no validationRules, no plugins for depth/complexity
});

// Safe: using graphql-depth-limit
const depthLimit = require('graphql-depth-limit');
const server = new ApolloServer({
  validationRules: [depthLimit(10)],
});

// Safe: using graphql-query-complexity
const { createComplexityLimitRule } = require('graphql-query-complexity');
const server = new ApolloServer({
  validationRules: [createComplexityLimitRule(1000)],
});
```

**Python/Graphene:**
```python
# Flag: no depth/complexity limiter in middleware list
GRAPHENE = {
    'MIDDLEWARE': [
        # no QueryDepthLimiter or QueryComplexityLimiter here
    ]
}

# Safe
from graphene_django.views import GraphQLView
from graphql_query_cost import add_query_depth_limit_directive
```

**graphql-java:**
```java
// Flag: no MaxQueryDepthInstrumentation
GraphQL graphQL = GraphQL.newGraphQL(schema)
    .build();  // no instrumentation

// Safe
GraphQL graphQL = GraphQL.newGraphQL(schema)
    .instrumentation(new MaxQueryDepthInstrumentation(10))
    .instrumentation(new MaxQueryComplexityInstrumentation(200))
    .build();
```

### Detection check

Search for: `depthLimit`, `depth_limit`, `MaxQueryDepth`, `complexityLimit`, `complexity_limit`, `MaxQueryComplexity`, `QueryComplexity`, `query_depth`. Absence of any of these near schema/server initialization is a flag.

---

## Issue 3: Batching abuse

### What it is

GraphQL supports two batching patterns that can be abused for brute-force or rate-limit bypass:

**Alias-based batching:** send many aliased operations in a single request, each attempting a different value (e.g., 1000 password guesses):

```graphql
{
  a1: login(username: "admin", password: "password1") { token }
  a2: login(username: "admin", password: "password2") { token }
  a3: login(username: "admin", password: "password3") { token }
  # ... repeated 997 more times
}
```

**Array-based batching** (Apollo/express-graphql batch endpoint): send a JSON array of operations in one HTTP request, bypassing per-request rate limits.

### Detection patterns

```javascript
// Flag: batch endpoint enabled without per-operation rate limiting
// express-graphql with batching
app.use('/graphql', graphqlHTTP({
    schema,
    // no operation count limit
}));

// Apollo — array batching enabled by default in older versions
// Check for @apollo/server bodyParser accepting arrays

// Flag: mutation resolvers with no per-operation rate limiting
const resolvers = {
  Mutation: {
    login: async (_, { username, password }) => {
      // no rate limit check per alias/operation
      return authenticate(username, password);
    }
  }
};
```

### Detection check

1. Look for `login`, `authenticate`, `verify`, `resetPassword`, `requestOtp`, `changePassword` mutations.
2. Check if rate limiting is applied per HTTP request OR per operation. HTTP-level rate limiting does not protect against alias batching.
3. Look for alias count limits: `maxAliasCount`, `alias_limit`, or similar.

### Remediation

- Limit the number of aliases/operations per request (max 10–20 is typical).
- Apply rate limiting per operation type, not just per HTTP request.
- Disable array-based batching if not required.

---

## Issue 4: Field-level authorization missing

### What it is

Authentication middleware verifies identity. Authorization must happen at each resolver. A common mistake is relying solely on top-level auth middleware and not checking permissions for each sensitive field.

### Detection patterns

**JavaScript — check each resolver for auth context use:**
```javascript
// Flag: resolver does not check permissions
const resolvers = {
  Query: {
    adminDashboard: (_, __, context) => {
      // context.user exists (authenticated) but role not checked
      return Admin.findAll();
    }
  },
  User: {
    ssn: (parent, _, context) => {
      // sensitive field returned with no ownership check
      return parent.ssn;
    }
  }
};

// Safe
const resolvers = {
  Query: {
    adminDashboard: (_, __, context) => {
      if (!context.user || context.user.role !== 'admin') {
        throw new ForbiddenError('Admin only');
      }
      return Admin.findAll();
    }
  },
  User: {
    ssn: (parent, _, context) => {
      if (context.user.id !== parent.id && !context.user.isAdmin) {
        throw new ForbiddenError('Access denied');
      }
      return parent.ssn;
    }
  }
};
```

**Python/Strawberry — check for permission classes:**
```python
# Flag: sensitive field without IsAuthenticated or custom permission
@strawberry.type
class User:
    email: str          # returned to any authenticated user
    credit_card: str    # sensitive — no field-level permission

# Safe
from strawberry.permission import BasePermission
class IsOwner(BasePermission):
    message = "Access denied"
    def has_permission(self, source, info, **kwargs):
        return info.context.user.id == source.id

@strawberry.type
class User:
    email: str
    @strawberry.field(permission_classes=[IsOwner])
    def credit_card(self) -> str:
        return self._credit_card
```

**graphql-ruby — check for `authorized?` method:**
```ruby
# Flag: field with no authorization
field :admin_secret, String, null: false

# Safe
field :admin_secret, String, null: false do
  def authorized?(object, args, context)
    context[:current_user]&.admin?
  end
end
```

### Detection check

1. List all `Query`, `Mutation`, and `Subscription` resolvers.
2. For each, check if the `context` object's user/role/permission is verified before data access.
3. For object types with sensitive fields (credentials, PII, financial data), check field-level resolvers.

---

## Issue 5: N+1 injection via nested resolvers

### What it is

Nested resolvers that individually query the database can be abused to leak data or cause DoS. A client requesting `users { posts { comments { author { email } } } }` may trigger thousands of DB queries, causing performance degradation or leaking data via timing.

### Detection patterns

```javascript
// Flag: resolver makes individual DB query for each parent object
const resolvers = {
  User: {
    posts: async (user) => {
      return Post.findAll({ where: { userId: user.id } });
      // Called once per User — N+1 if N users returned
    }
  }
};

// Safe: using DataLoader for batching
const resolvers = {
  User: {
    posts: async (user, _, context) => {
      return context.loaders.postsByUserId.load(user.id);
    }
  }
};
```

### Detection check

1. Find resolver functions for object types (not just Query/Mutation root).
2. Check if they perform individual DB calls without DataLoader or equivalent batching.
3. Check if query depth limits would stop a deeply nested query before N+1 becomes costly.

---

## Issue 6: Subscription endpoint security

### What it is

GraphQL subscriptions use WebSockets. Authentication is often applied to HTTP routes but WebSocket upgrade handlers are missed, leaving subscriptions open to unauthenticated access.

### Detection patterns

**Apollo Server with subscriptions:**
```javascript
// Flag: subscription server with no auth on WebSocket connection
const wsServer = new WebSocketServer({ server: httpServer, path: '/graphql' });
const serverCleanup = useServer(
  {
    schema,
    // no onConnect handler with auth check
  },
  wsServer
);

// Safe
useServer(
  {
    schema,
    onConnect: async (ctx) => {
      const token = ctx.connectionParams?.authorization;
      if (!token || !verifyToken(token)) {
        throw new Error('Unauthorized');
      }
    },
    context: (ctx) => {
      const user = getUserFromToken(ctx.connectionParams?.authorization);
      return { user };
    }
  },
  wsServer
);
```

**graphql-ruby ActionCable:**
```ruby
# Flag: subscription channel with no authentication
class GraphqlChannel < ApplicationCable::Channel
  def subscribed
    # no current_user check before subscribing
    @subscription_ids = []
  end
end

# Safe
class GraphqlChannel < ApplicationCable::Channel
  def subscribed
    reject unless current_user  # ApplicationCable auth
    @subscription_ids = []
  end
end
```

---

## Issue 7: SSRF via schema stitching and remote schema fetching

### What it is

Schema stitching and federation allow a GraphQL gateway to fetch schemas from remote URLs. If the remote URL is user-controlled or derived from user input, it becomes an SSRF vector.

### Detection patterns

```javascript
// Flag: remote schema URL from user input or environment without allowlist
const { introspectSchema } = require('@graphql-tools/wrap');
const remoteUrl = config.remoteSchemaUrl;  // if this comes from user input → SSRF
const remoteSchema = await introspectSchema(
  buildHTTPExecutor({ endpoint: remoteUrl })
);

// Flag: Apollo Federation with configurable service endpoints
const gateway = new ApolloGateway({
  serviceList: [
    { name: 'users', url: process.env.USERS_SERVICE_URL },
    // if USERS_SERVICE_URL can be influenced by an attacker → SSRF
  ],
});

// Safe: hardcoded or strictly validated URLs
const ALLOWED_SCHEMAS = new Set(['https://internal.example.com/graphql']);
if (!ALLOWED_SCHEMAS.has(remoteUrl)) throw new Error('URL not allowed');
```

### Detection check

Look for `introspectSchema`, `buildHTTPExecutor`, `@graphql-tools/wrap`, `RemoteSchema`, `ApolloGateway`, `serviceList`, or federation gateway configuration. Check if the URLs are hardcoded or come from config that could be influenced by external input.

---

## Issue 8: Type confusion and null injection

### What it is

- **Type confusion**: passing an unexpected type for a field (e.g., `id: {toString: "..."}`) can bypass validation in weakly-typed resolvers.
- **Null injection**: passing `null` for a non-null field may bypass business logic that assumes the field has a value.
- **Enum injection**: passing integer values or string literals for enum fields.

### Detection patterns

```javascript
// Flag: resolver assumes type without validation
const resolvers = {
  Mutation: {
    updateUser: (_, { id, data }) => {
      // id assumed to be a string — no typeof check
      return User.findByIdAndUpdate(id, data);
    }
  }
};

// Flag: schema defines non-null field but resolver handles null
type User {
  email: String!   # non-null in schema
}
// But resolver: return user.email || null — mismatch
```

### Detection check

1. Check that schema types and resolver implementations agree on nullability.
2. In JavaScript resolvers, verify that numeric IDs are not used directly in string contexts.
3. Check that input validation happens on resolver arguments, not just schema types.

---

## Summary: patterns to search for

| Issue | Search terms |
|-------|-------------|
| Introspection | `introspection`, `IntrospectionQuery`, `graphiql`, `__schema`, `DisableIntrospection` |
| Depth limit | `depthLimit`, `depth_limit`, `MaxQueryDepth`, `maxDepth` |
| Complexity limit | `complexityLimit`, `complexity_limit`, `MaxQueryComplexity`, `QueryComplexity` |
| Batching | `alias`, `batch`, `operationName`, array body parsing |
| Field auth | `context.user`, `hasPermission`, `authorized?`, `permission_classes`, `IsAuthenticated` in resolvers |
| DataLoader/N+1 | `DataLoader`, `dataloader`, `load(`, absence of batch loading in object resolvers |
| Subscription auth | `onConnect`, `connectionParams`, WebSocket `upgrade`, `subscribed` handler |
| SSRF/stitching | `introspectSchema`, `RemoteSchema`, `ApolloGateway`, `serviceList`, `buildHTTPExecutor` |

## Output format per finding

```json
{
  "file": "src/graphql/server.js",
  "line": 12,
  "vuln_type": "graphql_introspection_enabled",
  "severity": "medium",
  "cwe": "CWE-200",
  "owasp": "A05:2021 - Security Misconfiguration",
  "title": "GraphQL introspection enabled in production",
  "description": "The Apollo Server is initialized without setting introspection: false. Introspection is enabled by default, exposing the full schema to unauthenticated callers.",
  "remediation": "Set introspection: process.env.NODE_ENV !== 'production' in ApolloServer options. Also disable GraphiQL in production.",
  "references": ["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"]
}
```
