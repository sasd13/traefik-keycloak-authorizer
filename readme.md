# Keycloak authorizer middleware

A Traefik plugin that authenticates a request's bearer JWT against Keycloak
and forwards extracted roles and permissions as request headers.

Both roles and permissions can gate requests, symmetrically: if `enabled` is
true, the request is rejected when nothing is found at all, or when `some`/
`every` don't match. The request is also rejected when the bearer token is
missing/malformed, or when the Keycloak permissions request fails.

## Configuration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: jwt-authorization
spec:
  plugin:
    jwtAuthorization:
      issuer: https://auth.example.com/realms/myrealm
      roles:
        enabled: true
        headerName: X-User-Rol   # default: X-User-Rol
        some:
          - my-client:admin
        every:
          - my-client:verified
      permissions:
        enabled: true
        headerName: X-User-Prm   # default: X-User-Prm
        audience: my-client
        some:
          - orders:read
        every:
          - billing:write
      headerMap:
        X-User-Email: email
```

- `issuer` — the Keycloak realm issuer URL. Required.
- `roles.enabled` — when true, extracts roles from the request token's
  `resource_access` claim directly (no network call to Keycloak). Roles from
  `realm_access` are not included. All clients present in `resource_access`
  are included — there's no audience filter for roles. Rejects the request
  (403) if no roles are found at all.
- `roles.headerName` — header the roles are written to. Format:
  `client:role1+role2,client2:role3` — clients and roles sorted
  alphabetically. Role and client names must not contain `,`, `:`, or `+`.
- `roles.some` — if non-empty, at least one of these `client:role` pairs
  must be present, or the request is rejected (403).
- `roles.every` — if non-empty, all of these `client:role` pairs must be
  present, or the request is rejected (403).
- `permissions.enabled` — when true, exchanges the request token with
  Keycloak's token endpoint (`urn:ietf:params:oauth:grant-type:uma-ticket`)
  for a permissions-bearing token, scoped to `permissions.audience`. Rejects
  the request (403) if the resulting permissions list is empty.
- `permissions.headerName` — header the permissions are written to. Format:
  `resource:scope,resource2:scope2`.
- `permissions.audience` — the Keycloak client id (resource server) to
  request permissions for. Required when `permissions.enabled` is true.
- `permissions.some` — if non-empty, at least one of these `resource:scope`
  pairs must be present, or the request is rejected (403).
- `permissions.every` — if non-empty, all of these `resource:scope` pairs
  must be present, or the request is rejected (403).
- `headerMap` — maps arbitrary token claims to request headers
  (`<header-name>: <claim-name>`). Applied against the original request
  token, or against the Keycloak-issued token when `permissions.enabled` is
  true.
```
