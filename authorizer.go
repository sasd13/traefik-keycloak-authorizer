// Package traefik-keycloak-authorizer provides functionality for authorizing requests given a JWT token.
//
//nolint:revive
package traefik_keycloak_authorizer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	Issuer          string            `json:"issuer,omitempty"`
	Audience        string            `json:"audience,omitempty"`
	Some            []string          `json:"some,omitempty"`
	Every           []string          `json:"every,omitempty"`
	WithPermissions bool              `json:"withPermissions,omitempty"`
	HeaderMap       map[string]string `json:"headerMap,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// KeycloakAuthorizer plugin struct.
type KeycloakAuthorizer struct {
	issuer          string
	audience        string
	some            []string
	every           []string
	withPermissions bool
	headerMap       map[string]string
	next            http.Handler
	name            string
}

// New creates a new KeycloakAuthorizer plugin.
// revive:disable-next-line unused-parameter.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &KeycloakAuthorizer{
		issuer:          strings.TrimRight(config.Issuer, "/"),
		audience:        config.Audience,
		some:            config.Some,
		every:           config.Every,
		withPermissions: config.WithPermissions,
		headerMap:       config.HeaderMap,
		next:            next,
		name:            name,
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
	resToken, permissions, err := kc.ParseResponse(resBody, p.withPermissions)
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

	// Set metadata
	p.setMetadata(r, resToken, permissions)

	p.next.ServeHTTP(rw, r)
}

func (p *KeycloakAuthorizer) checkPermissions(permissions []string) error {
	if !p.withPermissions {
		return nil
	}

	if len(permissions) == 0 {
		return errors.New("No permission found")
	}

	some := util.Intersect(permissions, p.some)
	if len(p.some) > 0 && len(some) == 0 {
		return errors.New("Unmatched permissions")
	}

	every := util.Intersect(permissions, p.every)
	if len(p.every) > 0 && len(p.every) > len(every) {
		return errors.New("Insufficient permissions")
	}

	return nil
}

func (p *KeycloakAuthorizer) setMetadata(r *http.Request, claims jwt.MapClaims, permissions []string) {
	p.mapClaimsToHeaders(r, claims)

	if len(permissions) > 0 {
		r.Header.Set("X-User-Perm", strings.Join(permissions, ","))
	}
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
