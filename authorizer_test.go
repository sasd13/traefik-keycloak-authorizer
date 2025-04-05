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

func TestAuthorizer(t *testing.T) {
	cfg := authorizer.CreateConfig()
	cfg.Headers["X-Api-Key"] = "DEMO_KEY"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := authorizer.New(ctx, next, cfg, "keycloak-authorizer-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	req.Header.Set("Location", "https://api.nasa.gov/planetary/apod")
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, 200, recorder.Result().StatusCode)
}
