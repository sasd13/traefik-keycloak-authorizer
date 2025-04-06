// Package traefik-keycloak-authorizer provides functionality for authorizing requests given a JWT token.
//
//nolint:revive
package traefik_keycloak_authorizer

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	kc "github.com/sasd13/traefik-keycloak-authorizer/internal/keycloak"
	util "github.com/sasd13/traefik-keycloak-authorizer/internal/util"
)

const (
	errForbidden = "Forbidden"
)

// Config the plugin configuration.
type Config struct {
	Issuer   string   `json:"issuer,omitempty"`
	Audience string   `json:"audience,omitempty"`
	Some     []string `json:"some,omitempty"`
	Every    []string `json:"every,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// KeycloakAuthorizer plugin struct.
type KeycloakAuthorizer struct {
	issuer   string
	audience string
	some     []string
	every    []string
	next     http.Handler
	name     string
}

// New created a new KeycloakAuthorizer plugin.
// revive:disable-next-line unused-parameter.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &KeycloakAuthorizer{
		issuer:   strings.TrimRight(config.Issuer, "/"),
		audience: config.Audience,
		some:     config.Some,
		every:    config.Every,
		next:     next,
		name:     name,
	}, nil
}

func (p *KeycloakAuthorizer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	reqToken, err := util.GetRequestToken(r)
	if err != nil {
		log.Printf("Failed to get request token: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	log.Printf("Authorizing request against: %s", p.issuer)

	// Create a new request to Keycloak token endpoint
	req, err := kc.NewRequest(r.Context(), reqToken, p.issuer, p.audience)
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	// Perform the request
	resBody, err := util.SendRequest(req)
	if err != nil {
		log.Printf("Failed to send request: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	// Parse the response
	resToken, permissions, err := kc.ParseResponse(resBody)
	if err != nil {
		log.Printf("Failed to parse response: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	// Check permissions
	if err := p.checkPermissions(permissions); err != nil {
		log.Printf("Permission check failed: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	// Set request metadata
	p.setRequestMetadata(r, resToken, permissions)

	p.next.ServeHTTP(rw, r)
}

func (p *KeycloakAuthorizer) checkPermissions(permissions []string) error {
	if len(permissions) == 0 {
		return errors.New("No permission found")
	}

	some := util.Intersect(permissions, p.some)
	if len(p.some) > 0 && len(some) == 0 {
		return errors.New("Unmatched permissions")
	}

	every := util.Intersect(permissions, p.every)
	if len(p.every) > len(every) {
		return errors.New("Insufficient permissions")
	}

	return nil
}

func (p *KeycloakAuthorizer) setRequestMetadata(r *http.Request, token jwt.MapClaims, permissions []string) {
	aud, _ := kc.GetClaim(token, "aud")
	azp, _ := kc.GetClaim(token, "azp")
	sub, _ := kc.GetClaim(token, "sub")

	r.Header.Set("X-User-Aud", aud)
	r.Header.Set("X-User-Azp", azp)
	r.Header.Set("X-User-Sub", sub)
	r.Header.Set("X-User-Prm", strings.Join(permissions, ","))
}
