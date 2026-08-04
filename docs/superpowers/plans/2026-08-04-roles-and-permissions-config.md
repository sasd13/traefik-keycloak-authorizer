# Roles Extraction & Simplified Authorization Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add roles extraction from the JWT (grouped by client, from `resource_access` only) and replace the current flat `withPermissions`/`some`/`every`/`headerName` config with a nested `roles`/`permissions` config, dropping all authorization gating so the plugin becomes a pure authenticate-and-extract-to-headers middleware.

**Architecture:** `authorizer.go` owns config/orchestration. `internal/keycloak/token.go` gains a `readRoles` extractor mirroring the existing `readPermissions`. `internal/keycloak/api.go`'s `ParseResponse` is replaced by two focused entry points so the plugin only calls Keycloak's network endpoint when permissions are enabled. `internal/util/util.go`'s now-unused `Intersect` is deleted.

**Tech Stack:** Go 1.19, `github.com/golang-jwt/jwt/v5`, `github.com/stretchr/testify` for tests, `golangci-lint` + `gofumpt` for lint/format.

## Global Constraints

- Module path: `github.com/sasd13/traefik-keycloak-authorizer` — spec's package/import paths must match exactly.
- Go 1.19 syntax only (no generics-heavy stdlib features beyond what's already used).
- Header values: comma-separated at top level; roles grouped as `client:role1+role2,client2:role3`; reserved chars `,`, `:`, `+` are documented as forbidden in role/client names, not escaped.
- Roles source: `resource_access.<client>.roles` only — `realm_access.roles` is explicitly excluded.
- No audience filtering for roles — every client under `resource_access` is included.
- No authorization gating: the plugin never 403s because roles/permissions are empty or unmatched — only on token-parse or Keycloak-request failure.
- Default header names: `X-User-Rol` for roles, `X-User-Prm` for permissions (used when `HeaderName` is empty), matching the existing default-header convention in `setMetadata`.
- Roles and clients must be sorted alphabetically in the output header (Go map iteration order is randomized).
- Run `go test -v -cover ./...` and `golangci-lint run` and `gofumpt -extra -l .` (must report no files) before each commit that touches `.go` files.

---

### Task 1: Add `ReadRoles` to `internal/keycloak/token.go`

**Files:**
- Modify: `internal/keycloak/token.go`
- Test: `internal/keycloak/token_test.go` (new file)

**Interfaces:**
- Consumes: `jwt.MapClaims` (from `github.com/golang-jwt/jwt/v5`), already used by `readPermissions` in this file.
- Produces: `ReadRoles(token jwt.MapClaims) map[string][]string` — **exported**, a map from client id to its **sorted, deduplicated** list of role names, extracted only from `resource_access.<client>.roles`. Returns an empty (non-nil) map if `resource_access` is missing or malformed, mirroring `readPermissions`'s defensive style (type-assert everything, skip on failure, never panic). Task 2 (`internal/keycloak/api.go`) and Task 4 (`authorizer.go`) consume this function directly by name (`kc.ReadRoles`).

There is no existing test file for this package — create `internal/keycloak/token_test.go` as an internal test (`package keycloak`, not `keycloak_test`) since `readRoles`/`readPermissions` are unexported and the package has no exported test surface yet.

- [ ] **Step 1: Write the failing test**

Create `internal/keycloak/token_test.go`:

```go
// Package keycloak provides keycloak functionalities.
package keycloak

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestReadRolesFlattensAndDedupesPerClient(t *testing.T) {
	token := jwt.MapClaims{
		"resource_access": map[string]interface{}{
			"kartapay-website": map[string]interface{}{
				"roles": []interface{}{"merchant", "customer", "merchant"},
			},
			"kartapay-bo": map[string]interface{}{
				"roles": []interface{}{"bo-agent"},
			},
			"account": map[string]interface{}{
				"roles": []interface{}{"manage-account", "manage-account-links", "view-profile"},
			},
		},
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"offline_access", "uma_authorization"},
		},
	}

	roles := ReadRoles(token)

	assert.Equal(t, map[string][]string{
		"kartapay-website": {"customer", "merchant"},
		"kartapay-bo":       {"bo-agent"},
		"account":           {"manage-account", "manage-account-links", "view-profile"},
	}, roles)
}

func TestReadRolesMissingResourceAccessReturnsEmptyMap(t *testing.T) {
	token := jwt.MapClaims{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"offline_access"},
		},
	}

	roles := ReadRoles(token)

	assert.Empty(t, roles)
}

func TestReadRolesMalformedResourceAccessReturnsEmptyMap(t *testing.T) {
	token := jwt.MapClaims{
		"resource_access": "not-a-map",
	}

	roles := ReadRoles(token)

	assert.Empty(t, roles)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keycloak/... -run TestReadRoles -v`
Expected: FAIL — `undefined: ReadRoles`

- [ ] **Step 3: Write minimal implementation**

In `internal/keycloak/token.go`, add the import `"sort"` to the existing import block, and add this function after `readPermissions`:

```go
// ReadRoles extracts resource-scoped roles from the token's resource_access claim, grouped by client.
func ReadRoles(token jwt.MapClaims) map[string][]string {
	roles := map[string][]string{}

	resourceAccess, ok := token["resource_access"].(map[string]interface{})
	if !ok {
		return roles
	}

	for client, access := range resourceAccess {
		accessMap, ok := access.(map[string]interface{})
		if !ok {
			continue
		}

		clientRoles, ok := accessMap["roles"]
		if !ok {
			continue
		}

		clientRolesList, ok := clientRoles.([]interface{})
		if !ok {
			continue
		}

		seen := map[string]bool{}
		var names []string
		for _, role := range clientRolesList {
			roleStr, ok := role.(string)
			if !ok || seen[roleStr] {
				continue
			}
			seen[roleStr] = true
			names = append(names, roleStr)
		}

		if len(names) == 0 {
			continue
		}

		sort.Strings(names)
		roles[client] = names
	}

	return roles
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keycloak/... -run TestReadRoles -v`
Expected: PASS (all 3 subtests)

- [ ] **Step 5: Format, lint, commit**

```bash
gofumpt -extra -w internal/keycloak/token.go internal/keycloak/token_test.go
golangci-lint run ./internal/keycloak/...
git add internal/keycloak/token.go internal/keycloak/token_test.go
git commit -m "feat: extract roles from resource_access claim"
```

---

### Task 2: Split `ParseResponse` into permission-fetching and local-parsing entry points in `internal/keycloak/api.go`

**Files:**
- Modify: `internal/keycloak/api.go`
- Test: `internal/keycloak/api_test.go` (new file)

**Files (add to above):**
- Modify: `internal/keycloak/token.go` (rename `readPermissions` → exported `ReadPermissions`, same body, add doc comment)
- Modify: `internal/keycloak/token_test.go` if it references `readPermissions` (it doesn't — only `ReadRoles` was tested in Task 1)

**Interfaces:**
- Consumes: `kc.ReadRoles(token jwt.MapClaims) map[string][]string` (Task 1, same package so no import needed), `parseToken(token string) (jwt.MapClaims, error)` (existing, same package, stays unexported).
- Produces:
  - `ReadPermissions(token jwt.MapClaims) []string` — **exported** (renamed from `readPermissions`, same body, same package `internal/keycloak`), so `authorizer.go` (Task 4) can call it directly as `kc.ReadPermissions`.
  - `ParseToken(token string) (jwt.MapClaims, error)` — **exported** wrapper around the existing unexported `parseToken`, so `authorizer.go` (Task 4) can parse the raw request token locally without a network call.
  - `ParseResponse(resBody []byte) (jwt.MapClaims, error)` — modified signature (drops the `withPermissions bool` parameter and the permissions return value). Parses the Keycloak token endpoint's JSON response body and returns the RPT's claims only. Callers get permissions via `ReadPermissions(claims)` and roles via `ReadRoles(claims)` on whichever claims they have (either `ParseToken`'s or `ParseResponse`'s), removing the old asymmetry where only `ParseResponse` could produce permissions.
  - `NewRequest` is unchanged.

This task changes `ParseResponse`'s signature, which breaks `authorizer.go` — that's expected and fixed in Task 4. Compile errors in `authorizer.go` between this task and Task 4 are acceptable mid-plan; the test step below only runs `internal/keycloak/...` tests, not the whole module.

- [ ] **Step 1: Write the failing test**

Create `internal/keycloak/api_test.go`:

```go
// Package keycloak provides keycloak functionalities.
package keycloak

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseResponseReturnsClaims(t *testing.T) {
	// Token payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
	body := []byte(`{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}`)

	claims, err := ParseResponse(body)

	assert.NoError(t, err)
	assert.Equal(t, "1234567890", claims["sub"])
}

func TestParseResponseInvalidJSON(t *testing.T) {
	_, err := ParseResponse([]byte("not-json"))

	assert.Error(t, err)
}

func TestParseTokenExported(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	claims, err := ParseToken(token)

	assert.NoError(t, err)
	assert.Equal(t, "1234567890", claims["sub"])
}

func TestReadPermissionsExported(t *testing.T) {
	claims, err := ParseToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
	assert.NoError(t, err)

	// This token has no "authorization" claim, so ReadPermissions must return an empty (non-nil-panicking) slice.
	permissions := ReadPermissions(claims)

	assert.Empty(t, permissions)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/keycloak/... -run 'TestParseResponse|TestParseTokenExported|TestReadPermissionsExported' -v`
Expected: FAIL — `ParseResponse` still requires a second `bool` argument and returns 3 values (compile error); `ParseToken` and `ReadPermissions` undefined (still named `readPermissions`, unexported).

- [ ] **Step 3: Write minimal implementation**

In `internal/keycloak/token.go`, rename the existing `readPermissions` function to `ReadPermissions` (exported) and add a doc comment, keeping its body unchanged:

```go
// ReadPermissions extracts granted permissions from the token's authorization claim.
func ReadPermissions(token jwt.MapClaims) []string {
```

(Only the `func` line changes — the body of the existing `readPermissions` stays exactly as-is underneath this new signature line.)

Replace the whole `ParseResponse` function in `internal/keycloak/api.go` with:

```go
// ParseToken parses a raw JWT string into its claims, without verifying the signature
// (the issuer is trusted upstream of this call).
func ParseToken(token string) (jwt.MapClaims, error) {
	return parseToken(token)
}

// ParseResponse parses the response from Keycloak's token endpoint and extracts the RPT claims.
func ParseResponse(resBody []byte) (jwt.MapClaims, error) {
	var data keycloakAPIResponse
	if err := json.Unmarshal(resBody, &data); err != nil {
		return nil, err
	}

	return parseToken(data.AccessToken)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/keycloak/... -run 'TestParseResponse|TestParseTokenExported|TestReadPermissionsExported' -v`
Expected: PASS (all 4 subtests)

- [ ] **Step 5: Format, lint (this package only — `authorizer.go` is expected broken until Task 4), commit**

```bash
gofumpt -extra -w internal/keycloak/api.go internal/keycloak/api_test.go internal/keycloak/token.go
golangci-lint run ./internal/keycloak/...
git add internal/keycloak/api.go internal/keycloak/api_test.go internal/keycloak/token.go
git commit -m "refactor: split ParseResponse into ParseToken and ParseResponse(resBody), export ReadPermissions"
```

---

### Task 3: Delete unused `util.Intersect`

**Files:**
- Modify: `internal/util/util.go`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing. `Intersect`'s only caller is the `some`/`every` gating logic in `authorizer.go`, which Task 4 removes in the same edit that rewrites `authorizer.go`. Deleting `internal/util/util.go` here, before that edit lands, would leave `authorizer.go` referencing a deleted function and break the build mid-plan. **This task's deletion is executed as the final step of Task 4 (Task 4 Step 3), in the same commit as the `authorizer.go` rewrite — not as a separate commit.** It's listed here only so the file-structure map stays complete: `internal/util/util.go` has zero remaining callers once Task 4 lands, and is deleted.

---

### Task 4: Rewrite `authorizer.go` config, orchestration, and header formatting

**Files:**
- Modify: `authorizer.go`
- Modify: `authorizer_test.go`
- Delete: `internal/util/util.go` (see Task 3)

**Interfaces:**
- Consumes:
  - `util.GetRequestToken(r *http.Request) (string, error)` (existing, `internal/util/http.go`, unchanged)
  - `util.SendRequest(req *http.Request) ([]byte, error)` (existing, `internal/util/http.go`, unchanged)
  - `kc.NewRequest(ctx, token, issuer, audience string) (*http.Request, error)` (existing, unchanged)
  - `kc.ParseToken(token string) (jwt.MapClaims, error)` (Task 2)
  - `kc.ParseResponse(resBody []byte) (jwt.MapClaims, error)` (Task 2)
  - `kc.ReadPermissions(token jwt.MapClaims) []string` (Task 2)
  - `kc.ReadRoles(token jwt.MapClaims) map[string][]string` (Task 1)
- Produces: `Config`, `RolesConfig`, `PermissionsConfig` structs and `New`/`ServeHTTP` behavior described below — this is the outermost layer, nothing downstream consumes its output except Traefik itself.

- [ ] **Step 1: Write the failing test**

Replace `authorizer_test.go` entirely:

```go
// Package traefik_keycloak_authorizer_test provides the tests.
// revive:disable-next-line var-naming.
package traefik_keycloak_authorizer_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	authorizer "github.com/sasd13/traefik-keycloak-authorizer"
	"github.com/stretchr/testify/assert"
)

const validJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicmVzb3VyY2VfYWNjZXNzIjp7ImthcnRhcGF5LXdlYnNpdGUiOnsicm9sZXMiOlsibWVyY2hhbnQiLCJjdXN0b21lciJdfSwia2FydGFwYXktYm8iOnsicm9sZXMiOlsiYm8tYWdlbnQiXX19fQ." +
	"invalidsignaturebutunverified"

func TestAuthorizerRejectsRequestWithoutToken(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.example.com/auth/realms/myrealm"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := authorizer.New(ctx, next, cfg, "keycloak-authorizer-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 403, recorder.Result().StatusCode)
}

func TestAuthorizerRolesOnlySetsHeaderWithoutNetworkCall(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example" // unreachable on purpose — must not be called
	cfg.Roles.Enabled = true
	cfg.Roles.HeaderName = "X-KP-User-Rol"

	ctx := context.Background()
	var capturedHeader string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get("X-KP-User-Rol")
	})

	handler, err := authorizer.New(ctx, next, cfg, "keycloak-authorizer-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+validJWT)

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Result().StatusCode)
	assert.Equal(t, "kartapay-bo:bo-agent,kartapay-website:customer+merchant", capturedHeader)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run TestAuthorizer -v`
Expected: FAIL to compile — `cfg.Roles` undefined (old `Config` has no `Roles` field yet), plus the `TestAuthorizerRolesOnlySetsHeaderWithoutNetworkCall` case will fail against old behavior even once it compiles (old code always calls Keycloak).

- [ ] **Step 3: Write minimal implementation**

Replace `authorizer.go` entirely:

```go
// Package traefik-keycloak-authorizer provides functionality for authorizing requests given a JWT token.
//
//nolint:revive
package traefik_keycloak_authorizer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	kc "github.com/sasd13/traefik-keycloak-authorizer/internal/keycloak"
	util "github.com/sasd13/traefik-keycloak-authorizer/internal/util"
)

const (
	errForbidden = "Forbidden"

	defaultRolesHeaderName       = "X-User-Rol"
	defaultPermissionsHeaderName = "X-User-Prm"
)

// RolesConfig configures roles extraction.
type RolesConfig struct {
	Enabled    bool   `json:"enabled,omitempty"`
	HeaderName string `json:"headerName,omitempty"`
}

// PermissionsConfig configures permissions extraction.
type PermissionsConfig struct {
	Enabled    bool   `json:"enabled,omitempty"`
	HeaderName string `json:"headerName,omitempty"`
	Audience   string `json:"audience,omitempty"`
}

// Config the plugin configuration.
type Config struct {
	Issuer      string            `json:"issuer,omitempty"`
	Roles       RolesConfig       `json:"roles,omitempty"`
	Permissions PermissionsConfig `json:"permissions,omitempty"`
	HeaderMap   map[string]string `json:"headerMap,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// KeycloakAuthorizer plugin struct.
type KeycloakAuthorizer struct {
	issuer      string
	roles       RolesConfig
	permissions PermissionsConfig
	headerMap   map[string]string
	next        http.Handler
	name        string
}

// New creates a new KeycloakAuthorizer plugin.
// revive:disable-next-line unused-parameter.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &KeycloakAuthorizer{
		issuer:      strings.TrimRight(config.Issuer, "/"),
		roles:       config.Roles,
		permissions: config.Permissions,
		headerMap:   config.HeaderMap,
		next:        next,
		name:        name,
	}, nil
}

func (p *KeycloakAuthorizer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	reqToken, err := util.GetRequestToken(r)
	if err != nil {
		log.Printf("Failed to get request token: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	claims, err := kc.ParseToken(reqToken)
	if err != nil {
		log.Printf("Failed to parse request token: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	var permissions []string
	if p.permissions.Enabled {
		log.Printf("Fetching permissions against: %s", p.issuer)

		req, err := kc.NewRequest(r.Context(), reqToken, p.issuer, p.permissions.Audience)
		if err != nil {
			log.Printf("Failed to create request: %v", err)
			http.Error(rw, errForbidden, http.StatusForbidden)
			return
		}

		resBody, err := util.SendRequest(req)
		if err != nil {
			log.Printf("Failed to send request: %v", err)
			http.Error(rw, errForbidden, http.StatusForbidden)
			return
		}

		rpt, err := kc.ParseResponse(resBody)
		if err != nil {
			log.Printf("Failed to parse response: %v", err)
			http.Error(rw, errForbidden, http.StatusForbidden)
			return
		}

		claims = rpt
		permissions = kc.ReadPermissions(claims)
	}

	var roles map[string][]string
	if p.roles.Enabled {
		roles = kc.ReadRoles(claims)
	}

	p.setMetadata(r, claims, roles, permissions)

	p.next.ServeHTTP(rw, r)
}

func (p *KeycloakAuthorizer) setMetadata(
	r *http.Request,
	claims jwt.MapClaims,
	roles map[string][]string,
	permissions []string,
) {
	p.mapClaimsToHeaders(r, claims)

	if p.roles.Enabled {
		header := strings.TrimSpace(p.roles.HeaderName)
		if header == "" {
			header = defaultRolesHeaderName
		}

		r.Header.Set(header, formatRoles(roles))
	}

	if p.permissions.Enabled {
		header := strings.TrimSpace(p.permissions.HeaderName)
		if header == "" {
			header = defaultPermissionsHeaderName
		}

		r.Header.Set(header, strings.Join(permissions, ","))
	}
}

// formatRoles renders a client->roles map as "client:role1+role2,client2:role3",
// with clients and roles sorted alphabetically for deterministic output.
func formatRoles(roles map[string][]string) string {
	clients := make([]string, 0, len(roles))
	for client := range roles {
		clients = append(clients, client)
	}
	sort.Strings(clients)

	groups := make([]string, 0, len(clients))
	for _, client := range clients {
		groups = append(groups, client+":"+strings.Join(roles[client], "+"))
	}

	return strings.Join(groups, ",")
}

func (p *KeycloakAuthorizer) mapClaimsToHeaders(r *http.Request, claims jwt.MapClaims) {
	for header, claim := range p.headerMap {
		value, ok := claims[claim]
		if !ok {
			log.Printf("failed to get claim: %s", claim)
			continue
		}

		r.Header.Del(header)
		switch value := value.(type) {
		case []any, map[string]any, nil:
			json, err := json.Marshal(value)
			if err == nil {
				r.Header.Add(header, string(json))
			}
			// Although we check err, we don't have a branch to log an error for err != nil, because it's not possible
			// that the value won't be marshallable to json, given it has already been unmarshalled _from_ json to get here
		default:
			r.Header.Add(header, fmt.Sprint(value))
		}
	}
}
```

Finally, delete `internal/util/util.go` (Task 3) — its only function, `Intersect`, has no remaining caller now that this rewrite removes the `some`/`every` gating that called it.

```bash
rm internal/util/util.go
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -v -cover`
Expected: PASS for all tests in `.`, `internal/keycloak/...`. (`internal/util` now has no test file and no source file — `go test` reports `?  github.com/sasd13/traefik-keycloak-authorizer/internal/util  [no test files]` only if `http.go` still exists there, which it does — confirm the package still builds with only `http.go` left in it.)

- [ ] **Step 5: Format, lint, commit**

```bash
gofumpt -extra -w authorizer.go authorizer_test.go internal/keycloak/token.go internal/keycloak/token_test.go internal/keycloak/api_test.go
golangci-lint run ./...
git add authorizer.go authorizer_test.go internal/keycloak/token.go internal/keycloak/token_test.go internal/keycloak/api_test.go internal/util/util.go
git commit -m "feat: nested roles/permissions config, drop authorization gating"
```

(`git add internal/util/util.go` on a deleted file stages the deletion — this is correct.)

---

### Task 5: Update `.traefik.yml` and `readme.md` to match the new config

**Files:**
- Modify: `.traefik.yml`
- Modify: `readme.md`

**Interfaces:**
- Consumes: nothing (documentation only).
- Produces: nothing consumed by later tasks — this is the last task in the plan.

- [ ] **Step 1: Update `.traefik.yml` testData**

Current `.traefik.yml` `testData` block uses the old flat `Issuer`/`Audience` fields. Replace it with:

```yaml
displayName: Keycloak authorizer middleware
type: middleware

import: github.com/sasd13/traefik-keycloak-authorizer

summary: 'Authorizes requests given a JWT token issued with Keycloak'

testData:
  Issuer: https://keycloak.example.com/auth/realms/myrealm
  Roles:
    Enabled: true
    HeaderName: X-User-Rol
  Permissions:
    Enabled: true
    HeaderName: X-User-Prm
    Audience: myclient
```

- [ ] **Step 2: Write `readme.md` usage docs**

Replace `readme.md` entirely:

```markdown
# Keycloak authorizer middleware

A Traefik plugin that authenticates a request's bearer JWT against Keycloak
and forwards extracted roles and permissions as request headers. It performs
no authorization gating — it never rejects a request because roles or
permissions are missing; that decision is left to downstream services
reading the headers. A request is only rejected when the token is missing/
malformed, or when the Keycloak permissions request fails.

## Configuration

\`\`\`yaml
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
      permissions:
        enabled: true
        headerName: X-User-Prm   # default: X-User-Prm
        audience: my-client
      headerMap:
        X-User-Email: email
\`\`\`

- `issuer` — the Keycloak realm issuer URL. Required.
- `roles.enabled` — when true, extracts roles from the request token's
  `resource_access` claim directly (no network call to Keycloak). Roles from
  `realm_access` are not included. All clients present in `resource_access`
  are included — there's no audience filter for roles.
- `roles.headerName` — header the roles are written to. Format:
  `client:role1+role2,client2:role3` — clients and roles sorted
  alphabetically. Role and client names must not contain `,`, `:`, or `+`.
- `permissions.enabled` — when true, exchanges the request token with
  Keycloak's token endpoint (`urn:ietf:params:oauth:grant-type:uma-ticket`)
  for a permissions-bearing token, scoped to `permissions.audience`.
- `permissions.headerName` — header the permissions are written to. Format:
  `resource:scope,resource2:scope2`.
- `permissions.audience` — the Keycloak client id (resource server) to
  request permissions for. Required when `permissions.enabled` is true.
- `headerMap` — maps arbitrary token claims to request headers
  (`<header-name>: <claim-name>`). Applied against the original request
  token, or against the Keycloak-issued token when `permissions.enabled` is
  true.
\`\`\`
```

(Use literal triple backticks in the actual file — the outer fence above is just this plan document's own quoting.)

- [ ] **Step 3: Commit**

```bash
git add .traefik.yml readme.md
git commit -m "docs: update traefik.yml testData and readme for nested roles/permissions config"
```

---

## Self-Review Notes

- **Spec coverage:** config schema (Task 4), roles-only-skips-network (Task 4 Step 3 + test), resource_access-only + realm_access excluded (Task 1), no audience filter for roles (Task 1 iterates all clients), no gating/some/every removed (Task 3+4, `Intersect` deleted, no matching code written), grouped `client:role+role` format with alphabetical sort (Task 1 + `formatRoles` in Task 4), reserved-char documentation (Task 5 readme). All spec sections have a task.
- **Type consistency:** `ReadRoles`/`ReadPermissions` (Task 1/2, exported per the Task 4 note) match the call sites used in Task 4's `authorizer.go`. `kc.ParseToken`/`kc.ParseResponse(resBody []byte)` signatures in Task 2 match Task 4's call sites exactly (no `withPermissions bool` argument, single return value plus error).
- **No placeholders:** every step has literal code, no "TBD"/"add validation"/"similar to Task N" hand-waving.
