# Roles extraction & simplified authorization config

## Context

The plugin currently supports `withPermissions` (with `some`/`every` matching
gates) and a flat `headerName`/`headerMap` config. We're extending it to also
extract roles from the JWT, and simplifying the config schema to a nested
`roles`/`permissions` shape. Both roles and permissions get `some`/`every`
gating, symmetric with each other: reject if enabled but empty, reject if
`some` doesn't intersect, reject if `every` isn't a full subset. Roles are
matched as `client:role` pairs (matching the grouped header format's
building blocks), permissions as `resource:scope` pairs (unchanged).

Target Kubernetes Middleware config:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: prod-my-app-jwt-authorization
  namespace: my-app
spec:
  plugin:
    jwtAuthorization:
      issuer: https://auth.example.com/realms/myrealm-prod
      roles:
        enabled: true
        headerName: X-KP-User-Rol
        some:
          - client1:role1
          - client2:role2
      permissions:
        enabled: true
        headerName: X-KP-User-Prm
        audience: client-x
        some: ["orders:read"]
        every: ["billing:write"]
```

## Config schema

```go
type RolesConfig struct {
    Enabled    bool     `json:"enabled,omitempty"`
    HeaderName string   `json:"headerName,omitempty"` // default: X-User-Rol
    Some       []string `json:"some,omitempty"`       // "client:role" pairs
    Every      []string `json:"every,omitempty"`      // "client:role" pairs
}

type PermissionsConfig struct {
    Enabled    bool     `json:"enabled,omitempty"`
    HeaderName string   `json:"headerName,omitempty"` // default: X-User-Prm
    Audience   string   `json:"audience,omitempty"`
    Some       []string `json:"some,omitempty"`
    Every      []string `json:"every,omitempty"`
}

type Config struct {
    Issuer      string            `json:"issuer,omitempty"`
    Roles       RolesConfig       `json:"roles,omitempty"`
    Permissions PermissionsConfig `json:"permissions,omitempty"`
    HeaderMap   map[string]string `json:"headerMap,omitempty"`
}
```

Removed: top-level `Audience`, `WithPermissions`, `HeaderName` (singular).
`Some`/`Every` move under `Permissions` (same semantics as before) and are
newly added under `Roles`, matched as `client:role` pairs.

## Request flow

1. Parse `reqToken` from the incoming request locally (`jwt.ParseUnverified`,
   as today — issuer is trusted, no signature check).
2. If `Roles.Enabled`: extract roles from `reqToken`'s `resource_access`
   claim only (not `realm_access` — realm-level roles like
   `offline_access`/`uma_authorization` are not resource-scoped and are
   excluded). No audience filtering: every client under `resource_access` is
   included.
3. If `Permissions.Enabled`: call Keycloak's uma-ticket token endpoint with
   `Permissions.Audience` (as today), obtain the RPT, extract permissions
   from `authorization.permissions` on the RPT.
4. If `Permissions.Enabled` is false, skip the Keycloak network call
   entirely — there's nothing that needs it.
5. `HeaderMap` claim-to-header mapping runs against the RPT when permissions
   are enabled (RPT mirrors original claims plus adds
   `authorization.permissions`, preserving today's behavior), otherwise
   against `reqToken` directly.
6. Gating applies symmetrically to both roles and permissions, using the
   same rule shape for each (permissions' behavior is unchanged from
   today; roles gains an equivalent):
   - If `Permissions.Enabled` and the extracted permissions list is empty,
     403 ("No permission found").
   - If `Permissions.Some` is non-empty and none of the extracted
     `resource:scope` permissions intersect it, 403 ("Unmatched
     permissions").
   - If `Permissions.Every` is non-empty and not all of its entries are
     present in the extracted permissions, 403 ("Insufficient
     permissions").
   - If `Roles.Enabled` and the extracted roles are empty (no
     `resource_access` clients with roles at all), 403 ("No role found").
   - If `Roles.Some` is non-empty and none of the extracted roles —
     flattened to `client:role` pairs — intersect it, 403 ("Unmatched
     roles").
   - If `Roles.Every` is non-empty and not all of its entries are present
     in the flattened `client:role` pairs, 403 ("Insufficient roles").
   - Roles gating runs against the flattened `client:role` pairs only for
     matching purposes — the header output stays in the grouped
     `client:role1+role2` format regardless.
   - All other cases proceed to `p.next.ServeHTTP`.
   The request is otherwise only rejected (403) on token-parse errors or
   Keycloak-request errors.

## Header value formats

Both headers are single-line, comma-separated at the top level, matching
HTTP's native list-value convention (RFC 9110 §5.3).

**Permissions** (unchanged): `resource:scope` pairs, comma-separated —
e.g. `orders:read,orders:write`.

**Roles**: grouped by client to avoid repeating the client name per role,
and to preserve which client a role belongs to (flattening loses this and
risks collisions between same-named roles on different clients). Format:

```
client:role1+role2+role3,client2:role4
```

Clients and roles within each client are sorted alphabetically for
deterministic output (Go map iteration order is randomized).

Reserved characters: `,`, `:`, `+` must not appear in role or client names.
This is a documented constraint, not enforced by escaping — Keycloak role
and client names are admin-defined identifiers in this project and are not
expected to contain these characters. No escaping is implemented (would
conflict with the "minimal format" goal); if names become
externally-controlled/arbitrary in the future, revisit with a structured
format (e.g. RFC 8941 Structured Field Values).

### Worked example

Given a token with:
```json
"resource_access": {
  "client-x": { "roles": ["merchant", "customer"] },
  "client-y": { "roles": ["agent"] },
  "account": { "roles": ["manage-account", "manage-account-links", "view-profile"] }
}
```

Result:
```
X-KP-User-Rol: account:manage-account+manage-account-links+view-profile,client-y:agent,client-x:customer+merchant
```

## Out of scope

- Escaping/quoting of delimiter characters within role or client names.
- Roles filtered by a single audience — deliberately all clients are
  included since the config no longer ties roles to `permissions.audience`.
