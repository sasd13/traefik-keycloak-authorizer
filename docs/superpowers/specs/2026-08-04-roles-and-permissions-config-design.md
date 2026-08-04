# Roles extraction & simplified authorization config

## Context

The plugin currently supports `withPermissions` (with `some`/`every` matching
gates) and a flat `headerName`/`headerMap` config. We're extending it to also
extract roles from the JWT, and simultaneously simplifying the config schema
and dropping the pass/fail authorization gating — the plugin becomes purely
an authenticator + claims-to-headers extractor, with authorization decisions
delegated to downstream services that read the headers.

Target Kubernetes Middleware config:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: prod-kpay-common-jwt-authorization
  namespace: kpay
spec:
  plugin:
    jwtAuthorization:
      issuer: https://auth.kartalys.io/realms/kartapay-prod
      roles:
        enabled: true
        headerName: X-KP-User-Rol
      permissions:
        enabled: true
        headerName: X-KP-User-Prm
        audience: kartapay-website
```

## Config schema

```go
type RolesConfig struct {
    Enabled    bool   `json:"enabled,omitempty"`
    HeaderName string `json:"headerName,omitempty"` // default: X-User-Rol
}

type PermissionsConfig struct {
    Enabled    bool   `json:"enabled,omitempty"`
    HeaderName string `json:"headerName,omitempty"` // default: X-User-Prm
    Audience   string `json:"audience,omitempty"`
}

type Config struct {
    Issuer      string            `json:"issuer,omitempty"`
    Roles       RolesConfig       `json:"roles,omitempty"`
    Permissions PermissionsConfig `json:"permissions,omitempty"`
    HeaderMap   map[string]string `json:"headerMap,omitempty"`
}
```

Removed: top-level `Audience`, `WithPermissions`, `HeaderName` (singular),
`Some`, `Every`.

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
6. No gating: the request is only rejected (403) on token-parse errors or
   Keycloak-request errors — never because roles/permissions are empty or
   don't match anything. `some`/`every` matching is removed entirely.

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
  "kartapay-website": { "roles": ["merchant", "customer"] },
  "kartapay-bo": { "roles": ["bo-agent"] },
  "account": { "roles": ["manage-account", "manage-account-links", "view-profile"] }
}
```

Result:
```
X-KP-User-Rol: account:manage-account+manage-account-links+view-profile,kartapay-bo:bo-agent,kartapay-website:customer+merchant
```

## Out of scope

- Escaping/quoting of delimiter characters within role or client names.
- Authorization gating of any kind (some/every-style matching) — removed,
  not replaced.
- Roles filtered by a single audience — deliberately all clients are
  included since the config no longer ties roles to `permissions.audience`.
