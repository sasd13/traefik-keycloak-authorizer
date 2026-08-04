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
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicmVzb3VyY2VfYWNjZXNzIjp7ImthcnRhcGF5LXdlYnNpdGUiOnsicm9sZXMiOlsibWVyY2hhbnQiLCJjdXN0b21lciJdfSwia2FydGFwYXktYm8iOnsicm9sZXMiOlsiYm8tYWdlbnQiXX19fQ." +
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
	assert.Equal(t, "kartapay-bo:bo-agent,kartapay-website:customer+merchant", capturedHeader)
}

func TestAuthorizerRolesSomeRejectsWhenUnmatched(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example" // unreachable on purpose — must not be called
	cfg.Roles.Enabled = true
	cfg.Roles.Some = []string{"kartapay-website:admin"} // not present in validJWT's roles

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
	cfg.Roles.Some = []string{"kartapay-website:merchant"} // present in validJWT's roles

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
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example.test-does-not-resolve"
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

	// Keycloak request fails (DNS won't resolve) -> 403, proving permissions.enabled
	// still triggers the network call and gating path, unlike roles.
	assert.Equal(t, 403, recorder.Result().StatusCode)
}

func TestNewRejectsWhenNeitherRolesNorPermissionsEnabled(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.example.com/auth/realms/myrealm"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	_, err := authorizer.New(ctx, next, cfg, "keycloak-authorizer-plugin")

	assert.Error(t, err)
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

// TestAuthorizerPermissionsSuccessUsesRequestTokenForRoles exercises the full
// permissions-gating path against a real (mocked) Keycloak response, with both
// roles and permissions enabled together. The mocked RPT carries a different
// resource_access than the original request token (validJWT), so that if roles
// were ever read from the RPT instead of the request token (the bug fixed
// alongside this test), the roles header would reflect the RPT's roles
// ("other-client:admin") instead of validJWT's ("kartapay-bo:bo-agent,
// kartapay-website:customer+merchant").
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
	assert.Equal(t, "kartapay-bo:bo-agent,kartapay-website:customer+merchant", capturedRoles)
}

func TestAuthorizerRolesEveryWithDuplicatesDoesNotReject(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Issuer = "https://keycloak.invalid.example" // unreachable on purpose — must not be called
	cfg.Roles.Enabled = true
	// Duplicate entry, both satisfied by validJWT's roles.
	cfg.Roles.Every = []string{"kartapay-website:merchant", "kartapay-website:merchant"}

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
