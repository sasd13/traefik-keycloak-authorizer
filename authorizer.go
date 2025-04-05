// Package traefik-keycloak-authorizer provides functionality for authorizing requests given a JWT token.
//
//nolint:revive
package traefik_keycloak_authorizer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

const (
	errForbidden = "Forbidden"
)

// Config the plugin configuration.
type Config struct {
	Issuer   string `json:"issuer,omitempty"`
	Audience string `json:"audience,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// KeycloakAuthorizer plugin struct.
type KeycloakAuthorizer struct {
	issuer   string
	audience string
	next     http.Handler
	name     string
}

// New created a new KeycloakAuthorizer plugin.
// revive:disable-next-line unused-parameter.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &KeycloakAuthorizer{
		issuer:   strings.TrimRight(config.Issuer, "/"),
		audience: config.Audience,
		next:     next,
		name:     name,
	}, nil
}

func (p *KeycloakAuthorizer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	reqToken, err := getRequestToken(r)
	if err != nil {
		log.Printf("Failed to get request token: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	log.Printf("Authorizing request against: %s", p.issuer)

	// Create a new request to the token endpoint
	url := p.issuer + "/protocol/openid-connect/token"
	reqBody := fmt.Sprintf("audience=%s&grant_type=urn:ietf:params:oauth:grant-type:uma-ticket", p.audience)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader([]byte(reqBody)))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	req.Header.Set("Authorization", "Bearer "+reqToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Perform the request
	resBody, err := sendRequest(req)
	if err != nil {
		log.Printf("Failed to send request: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	var data keycloakAPIResponse
	if err = json.Unmarshal(resBody, &data); err != nil {
		log.Printf("Failed to parse response body: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	decodedToken, err := parseToken(data.AccessToken)
	if err != nil {
		log.Printf("Failed to parse access token: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	permissions := readPermissions(decodedToken)

	// Check permissions
	if err := p.checkPermissions(permissions); err != nil {
		log.Printf("Permission check failed: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	// Set request metadata
	r.Header.Set("X-User-Aud", strings.Join(decodedToken.Audience, " "))
	r.Header.Set("X-User-Azp", decodedToken.AuthorizedParty)
	r.Header.Set("X-User-Sub", decodedToken.Subject)
	r.Header.Set("X-User-Permissions", toBase64String(strings.Join(permissions, ",")))

	p.next.ServeHTTP(rw, r)
}

func (p *KeycloakAuthorizer) checkPermissions(permissions []string) error {
	if len(permissions) == 0 {
		return errors.New("No permission found")
	}

	return nil
}
