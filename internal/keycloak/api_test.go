// Package keycloak provides keycloak functionalities.
package keycloak

import (
	"context"
	"io"
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
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" //nolint:gosec

	claims, err := ParseToken(token)

	assert.NoError(t, err)
	assert.Equal(t, "1234567890", claims["sub"])
}

func TestNewRequestBuildsExpectedRequest(t *testing.T) {
	req, err := NewRequest(context.Background(), "the-token", "https://keycloak.example.com/realms/myrealm", "my-client")

	assert.NoError(t, err)
	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token", req.URL.String())
	assert.Equal(t, "Bearer the-token", req.Header.Get("Authorization"))
	assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))

	body, err := io.ReadAll(req.Body)
	assert.NoError(t, err)
	assert.Equal(t, "audience=my-client&grant_type=urn:ietf:params:oauth:grant-type:uma-ticket", string(body))
}

func TestNewRequestErrorsOnInvalidIssuerURL(t *testing.T) {
	// A control character in the URL makes http.NewRequestWithContext fail.
	_, err := NewRequest(context.Background(), "the-token", "https://keycloak.example.com/\n", "my-client")

	assert.Error(t, err)
}

func TestReadPermissionsExported(t *testing.T) {
	claims, err := ParseToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
	assert.NoError(t, err)

	// This token has no "authorization" claim, so ReadPermissions must return an empty (non-nil-panicking) slice.
	permissions := ReadPermissions(claims)

	assert.Empty(t, permissions)
}
