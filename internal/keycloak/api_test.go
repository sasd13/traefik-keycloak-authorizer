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
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" //nolint:gosec

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
