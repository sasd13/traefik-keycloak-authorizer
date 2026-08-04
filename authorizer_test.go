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
