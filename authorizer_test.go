// Package traefik_keycloak_authorizer_test provides the tests.
// revive:disable-next-line var-naming.
package traefik_keycloak_authorizer_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	authorizer "github.com/sasd13/traefik-keycloak-authorizer"
	"github.com/stretchr/testify/assert"
)

const validJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicmVzb3VyY2VfYWNjZXNzIjp7ImNsaWVudC1hIjp7InJvbGVzIjpbInZpZXdlciIsImVkaXRvciJdfSwiY2xpZW50LWIiOnsicm9sZXMiOlsiYWRtaW4iXX19fQ." +
	"invalidsignaturebutunverified"

// makeJWT builds an unsigned "header.payload.signature" JWT string from arbitrary
// claims, following the same pattern as validJWT above, for use in tests that need
// distinct/controlled claim content (e.g. a mocked Keycloak RPT response).
func makeJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	return header + "." + payload + ".invalidsignaturebutunverified"
}

// newPermissionsServer starts a test server that mimics Keycloak's token endpoint,
// returning an RPT whose authorization.permissions claim matches permissions.
func newPermissionsServer(t *testing.T, permissions []map[string]any) *httptest.Server {
	t.Helper()

	rptClaims := map[string]any{"sub": "rpt-subject"}
	if permissions != nil {
		rptClaims["authorization"] = map[string]any{"permissions": permissions}
	}
	rpt := makeJWT(rptClaims)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, err := json.Marshal(map[string]string{"access_token": rpt})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(body)
	}))
}

func TestAuthorizerRejectsRequestWithoutToken(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.example.com/auth/realms/myrealm"
	cfg.Roles.Enabled = true

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
	assert.Equal(t, "client-a:editor,client-a:viewer,client-b:admin", capturedHeader)
}

func TestAuthorizerRolesSomeRejectsWhenUnmatched(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example" // unreachable on purpose — must not be called
	cfg.Roles.Enabled = true
	cfg.Roles.Some = []string{"client-a:owner"} // not present in validJWT's roles

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
	req.Header.Set("Authorization", "Bearer "+validJWT)

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 403, recorder.Result().StatusCode)
}

func TestAuthorizerRolesSomeAllowsWhenMatched(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example" // unreachable on purpose — must not be called
	cfg.Roles.Enabled = true
	cfg.Roles.Some = []string{"client-a:editor"} // present in validJWT's roles

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
	req.Header.Set("Authorization", "Bearer "+validJWT)

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Result().StatusCode)
}

func TestAuthorizerPermissionsEnabledRejectsWhenKeycloakUnreachable(t *testing.T) {
	// A local server returning a non-200 status stands in for an unreachable
	// Keycloak, deterministically and without depending on DNS resolution
	// behavior (which can hang or vary across sandboxed CI environments).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg := authorizer.CreateConfig()
	cfg.Issuer = server.URL
	cfg.Permissions.Enabled = true
	cfg.Permissions.Audience = "myclient"

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
	req.Header.Set("Authorization", "Bearer "+validJWT)

	handler.ServeHTTP(recorder, req)

	// Keycloak request fails (non-200 status) -> 403, proving permissions.enabled
	// still triggers the network call and gating path, unlike roles.
	assert.Equal(t, 403, recorder.Result().StatusCode)
}

func TestNewAllowsWhenNeitherRolesNorPermissionsEnabled(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example" // unreachable on purpose — must not be called

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := authorizer.New(ctx, next, cfg, "keycloak-authorizer-plugin")

	assert.NoError(t, err)
	assert.NotNil(t, handler)
}

func TestAuthorizerPassesThroughWhenNeitherRolesNorPermissionsEnabled(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example" // unreachable on purpose — must not be called

	ctx := context.Background()
	reached := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { reached = true })

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
	assert.True(t, reached)
}

func TestNewRejectsWhenPermissionsEnabledWithoutAudience(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.example.com/auth/realms/myrealm"
	cfg.Permissions.Enabled = true
	cfg.Permissions.Audience = "   " // blank after trimming

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	_, err := authorizer.New(ctx, next, cfg, "keycloak-authorizer-plugin")

	assert.Error(t, err)
}

func TestNewRejectsWhenPermissionsEnabledWithoutIssuer(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "   " // blank after trimming
	cfg.Permissions.Enabled = true
	cfg.Permissions.Audience = "myclient"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	_, err := authorizer.New(ctx, next, cfg, "keycloak-authorizer-plugin")

	assert.Error(t, err)
}

func TestNewAllowsRolesOnlyWithoutIssuer(t *testing.T) {
	cfg := authorizer.CreateConfig()
	// Issuer intentionally left blank: roles-only configs never call Keycloak.
	cfg.Roles.Enabled = true

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := authorizer.New(ctx, next, cfg, "keycloak-authorizer-plugin")

	assert.NoError(t, err)
	assert.NotNil(t, handler)
}

// TestAuthorizerPermissionsSuccessUsesRequestTokenForRoles exercises the full
// permissions-gating path against a real (mocked) Keycloak response, with both
// roles and permissions enabled together. The mocked RPT carries a different
// resource_access than the original request token (validJWT), so that if roles
// were ever read from the RPT instead of the request token (the bug fixed
// alongside this test), the roles header would reflect the RPT's roles
// ("other-client:admin") instead of validJWT's ("client-a:editor+viewer,
// client-b:admin").
func TestAuthorizerPermissionsSuccessUsesRequestTokenForRoles(t *testing.T) {
	rpt := makeJWT(map[string]any{
		"sub": "rpt-subject",
		"resource_access": map[string]any{
			"other-client": map[string]any{
				"roles": []string{"admin"},
			},
		},
		"authorization": map[string]any{
			"permissions": []map[string]any{
				{"rsname": "orders", "scopes": []string{"read"}},
			},
		},
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, err := json.Marshal(map[string]string{"access_token": rpt})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	cfg := authorizer.CreateConfig()
	cfg.Issuer = server.URL
	cfg.Roles.Enabled = true
	cfg.Roles.HeaderName = "X-Test-Rol"
	cfg.Permissions.Enabled = true
	cfg.Permissions.HeaderName = "X-Test-Prm"
	cfg.Permissions.Audience = "myclient"

	ctx := context.Background()
	var capturedRoles, capturedPermissions string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedRoles = r.Header.Get("X-Test-Rol")
		capturedPermissions = r.Header.Get("X-Test-Prm")
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
	assert.Equal(t, "orders:read", capturedPermissions)
	// Must reflect validJWT (the request token), never the RPT's "other-client:admin".
	assert.Equal(t, "client-a:editor,client-a:viewer,client-b:admin", capturedRoles)
}

func TestAuthorizerRejectsWhenRequestTokenMalformed(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example" // unreachable on purpose — must not be called
	cfg.Roles.Enabled = true

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
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 403, recorder.Result().StatusCode)
}

func TestAuthorizerRejectsWhenKeycloakRequestCreationFails(t *testing.T) {
	cfg := authorizer.CreateConfig()
	// A control character in the issuer makes the underlying http.NewRequestWithContext fail.
	cfg.Issuer = "https://keycloak.example.com/\n"
	cfg.Permissions.Enabled = true
	cfg.Permissions.Audience = "myclient"

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
	req.Header.Set("Authorization", "Bearer "+validJWT)

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 403, recorder.Result().StatusCode)
}

func TestAuthorizerRejectsWhenKeycloakResponseMalformed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer server.Close()

	cfg := authorizer.CreateConfig()
	cfg.Issuer = server.URL
	cfg.Permissions.Enabled = true
	cfg.Permissions.Audience = "myclient"

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
	req.Header.Set("Authorization", "Bearer "+validJWT)

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 403, recorder.Result().StatusCode)
}

func TestAuthorizerPermissionsRejectsWhenEmpty(t *testing.T) {
	server := newPermissionsServer(t, nil)
	defer server.Close()

	cfg := authorizer.CreateConfig()
	cfg.Issuer = server.URL
	cfg.Permissions.Enabled = true
	cfg.Permissions.Audience = "myclient"

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
	req.Header.Set("Authorization", "Bearer "+validJWT)

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 403, recorder.Result().StatusCode)
}

func TestAuthorizerPermissionsSomeRejectsWhenUnmatched(t *testing.T) {
	server := newPermissionsServer(t, []map[string]any{
		{"rsname": "orders", "scopes": []string{"read"}},
	})
	defer server.Close()

	cfg := authorizer.CreateConfig()
	cfg.Issuer = server.URL
	cfg.Permissions.Enabled = true
	cfg.Permissions.Audience = "myclient"
	cfg.Permissions.Some = []string{"billing:write"} // not present

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
	req.Header.Set("Authorization", "Bearer "+validJWT)

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 403, recorder.Result().StatusCode)
}

func TestAuthorizerPermissionsEveryRejectsWhenInsufficient(t *testing.T) {
	server := newPermissionsServer(t, []map[string]any{
		{"rsname": "orders", "scopes": []string{"read"}},
	})
	defer server.Close()

	cfg := authorizer.CreateConfig()
	cfg.Issuer = server.URL
	cfg.Permissions.Enabled = true
	cfg.Permissions.Audience = "myclient"
	cfg.Permissions.Every = []string{"orders:read", "billing:write"} // billing:write missing

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
	req.Header.Set("Authorization", "Bearer "+validJWT)

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 403, recorder.Result().StatusCode)
}

func TestAuthorizerPermissionsEveryAllowsWhenSatisfied(t *testing.T) {
	server := newPermissionsServer(t, []map[string]any{
		{"rsname": "orders", "scopes": []string{"read"}},
	})
	defer server.Close()

	cfg := authorizer.CreateConfig()
	cfg.Issuer = server.URL
	cfg.Permissions.Enabled = true
	cfg.Permissions.Audience = "myclient"
	cfg.Permissions.Every = []string{"orders:read"}

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
	req.Header.Set("Authorization", "Bearer "+validJWT)

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Result().StatusCode)
}

func TestAuthorizerPermissionsDefaultHeaderName(t *testing.T) {
	server := newPermissionsServer(t, []map[string]any{
		{"rsname": "orders", "scopes": []string{"read"}},
	})
	defer server.Close()

	cfg := authorizer.CreateConfig()
	cfg.Issuer = server.URL
	cfg.Permissions.Enabled = true
	cfg.Permissions.Audience = "myclient"
	// Permissions.HeaderName intentionally left blank to exercise the default.

	ctx := context.Background()
	var capturedHeader string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get("X-User-Prm")
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
	assert.Equal(t, "orders:read", capturedHeader)
}

func TestAuthorizerRolesRejectsWhenNoRolesFound(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example" // unreachable on purpose — must not be called
	cfg.Roles.Enabled = true

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
	// A token with no resource_access claim at all -> zero roles extracted.
	req.Header.Set("Authorization", "Bearer "+makeJWT(map[string]any{"sub": "1234567890"}))

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 403, recorder.Result().StatusCode)
}

func TestAuthorizerRolesEveryRejectsWhenInsufficient(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example" // unreachable on purpose — must not be called
	cfg.Roles.Enabled = true
	cfg.Roles.Every = []string{"client-a:editor", "client-a:owner"} // client-a:owner missing

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
	req.Header.Set("Authorization", "Bearer "+validJWT)

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 403, recorder.Result().StatusCode)
}

func TestAuthorizerHeaderMapMapsClaims(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example" // unreachable on purpose — must not be called
	cfg.Roles.Enabled = true
	cfg.HeaderMap = map[string]string{
		"X-Test-Name":    "name",   // string claim
		"X-Test-Roles":   "roles",  // array claim -> JSON-marshaled
		"X-Test-Missing": "absent", // missing claim -> skipped, not set
	}

	ctx := context.Background()
	var nameHeader, rolesHeader string
	var missingHeaderPresent bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		nameHeader = r.Header.Get("X-Test-Name")
		rolesHeader = r.Header.Get("X-Test-Roles")
		_, missingHeaderPresent = r.Header["X-Test-Missing"]
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
	token := makeJWT(map[string]any{
		"name":  "John Doe",
		"roles": []string{"a", "b"},
		"resource_access": map[string]any{
			"client-a": map[string]any{"roles": []string{"editor"}},
		},
	})
	req.Header.Set("Authorization", "Bearer "+token)

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Result().StatusCode)
	assert.Equal(t, "John Doe", nameHeader)
	assert.Equal(t, `["a","b"]`, rolesHeader)
	assert.False(t, missingHeaderPresent)
}

func TestCreateConfigDefaultsEnforceToTrue(t *testing.T) {
	cfg := authorizer.CreateConfig()

	assert.True(t, cfg.Roles.Enforce)
	assert.True(t, cfg.Permissions.Enforce)
}

func TestAuthorizerRolesEnforceFalseAllowsNoRoles(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example" // unreachable on purpose — must not be called
	cfg.Roles.Enabled = true
	cfg.Roles.Enforce = false

	ctx := context.Background()
	reached := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { reached = true })

	handler, err := authorizer.New(ctx, next, cfg, "keycloak-authorizer-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	// A token with no resource_access claim at all -> zero roles extracted, but not enforced.
	req.Header.Set("Authorization", "Bearer "+makeJWT(map[string]any{"sub": "1234567890"}))

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Result().StatusCode)
	assert.True(t, reached)
}

func TestAuthorizerRolesEnforceFalseSkipsSomeAndEvery(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example" // unreachable on purpose — must not be called
	cfg.Roles.Enabled = true
	cfg.Roles.Enforce = false
	cfg.Roles.Some = []string{"client-a:owner"} // not present in validJWT's roles; would reject if enforced

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
	req.Header.Set("Authorization", "Bearer "+validJWT)

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Result().StatusCode)
}

func TestAuthorizerPermissionsEnforceFalseAllowsEmpty(t *testing.T) {
	server := newPermissionsServer(t, nil)
	defer server.Close()

	cfg := authorizer.CreateConfig()
	cfg.Issuer = server.URL
	cfg.Permissions.Enabled = true
	cfg.Permissions.Enforce = false
	cfg.Permissions.Audience = "myclient"

	ctx := context.Background()
	reached := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { reached = true })

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
	assert.True(t, reached)
}

func TestAuthorizerRolesEveryWithDuplicatesDoesNotReject(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example" // unreachable on purpose — must not be called
	cfg.Roles.Enabled = true
	// Duplicate entry, both satisfied by validJWT's roles.
	cfg.Roles.Every = []string{"client-a:editor", "client-a:editor"}

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
	req.Header.Set("Authorization", "Bearer "+validJWT)

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Result().StatusCode)
}
