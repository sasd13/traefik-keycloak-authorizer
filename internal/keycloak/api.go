// Package keycloak provides keycloak functionalities.
package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type keycloakAPIResponse struct {
	//nolint:tagliatelle
	AccessToken string `json:"access_token"`
}

// NewRequest creates a new HTTP request to Keycloak API
// with the provided token, issuer, and audience.
func NewRequest(
	ctx context.Context,
	token string,
	issuer string,
	audience string,
) (*http.Request, error) {
	url := issuer + "/protocol/openid-connect/token"
	reqBody := fmt.Sprintf("audience=%s&grant_type=urn:ietf:params:oauth:grant-type:uma-ticket", audience)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte(reqBody)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

// ParseResponse parses the response from Keycloak API and extracts the access token and permissions.
func ParseResponse(resBody []byte) (jwt.MapClaims, []string, error) {
	var data keycloakAPIResponse
	if err := json.Unmarshal(resBody, &data); err != nil {
		return nil, nil, err
	}

	token, err := parseToken(data.AccessToken)
	if err != nil {
		return nil, nil, err
	}

	permissions := readPermissions(token)

	return token, permissions, nil
}
