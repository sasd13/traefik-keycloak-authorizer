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
	"sort"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	kc "github.com/sasd13/traefik-keycloak-authorizer/internal/keycloak"
	util "github.com/sasd13/traefik-keycloak-authorizer/internal/util"
)

const (
	errForbidden = "Forbidden"

	defaultRolesHeaderName       = "X-User-Rol"
	defaultPermissionsHeaderName = "X-User-Prm"
)

// RolesConfig configures roles extraction and gating.
type RolesConfig struct {
	Enabled    bool     `json:"enabled,omitempty"`
	HeaderName string   `json:"headerName,omitempty"`
	Some       []string `json:"some,omitempty"`
	Every      []string `json:"every,omitempty"`
}

// PermissionsConfig configures permissions extraction and gating.
type PermissionsConfig struct {
	Enabled    bool     `json:"enabled,omitempty"`
	HeaderName string   `json:"headerName,omitempty"`
	Audience   string   `json:"audience,omitempty"`
	Some       []string `json:"some,omitempty"`
	Every      []string `json:"every,omitempty"`
}

// Config the plugin configuration.
type Config struct {
	Issuer      string            `json:"issuer,omitempty"`
	Roles       RolesConfig       `json:"roles,omitempty"`
	Permissions PermissionsConfig `json:"permissions,omitempty"`
	HeaderMap   map[string]string `json:"headerMap,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// KeycloakAuthorizer plugin struct.
type KeycloakAuthorizer struct {
	issuer      string
	roles       RolesConfig
	permissions PermissionsConfig
	headerMap   map[string]string
	next        http.Handler
	name        string
}

// New creates a new KeycloakAuthorizer plugin.
// revive:disable-next-line unused-parameter.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &KeycloakAuthorizer{
		issuer:      strings.TrimRight(config.Issuer, "/"),
		roles:       config.Roles,
		permissions: config.Permissions,
		headerMap:   config.HeaderMap,
		next:        next,
		name:        name,
	}, nil
}

func (p *KeycloakAuthorizer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	reqToken, err := util.GetRequestToken(r)
	if err != nil {
		log.Printf("Failed to get request token: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	claims, err := kc.ParseToken(reqToken)
	if err != nil {
		log.Printf("Failed to parse request token: %v", err)
		http.Error(rw, errForbidden, http.StatusForbidden)
		return
	}

	var permissions []string
	if p.permissions.Enabled {
		log.Printf("Fetching permissions against: %s", p.issuer)

		req, err := kc.NewRequest(r.Context(), reqToken, p.issuer, p.permissions.Audience)
		if err != nil {
			log.Printf("Failed to create request: %v", err)
			http.Error(rw, errForbidden, http.StatusForbidden)
			return
		}

		resBody, err := util.SendRequest(req)
		if err != nil {
			log.Printf("Failed to send request: %v", err)
			http.Error(rw, errForbidden, http.StatusForbidden)
			return
		}

		rpt, err := kc.ParseResponse(resBody)
		if err != nil {
			log.Printf("Failed to parse response: %v", err)
			http.Error(rw, errForbidden, http.StatusForbidden)
			return
		}

		claims = rpt
		permissions = kc.ReadPermissions(claims)

		if err := p.checkPermissions(permissions); err != nil {
			log.Printf("Permission check failed: %v", err)
			http.Error(rw, errForbidden, http.StatusForbidden)
			return
		}
	}

	var roles map[string][]string
	if p.roles.Enabled {
		roles = kc.ReadRoles(claims)

		if err := p.checkRoles(roles); err != nil {
			log.Printf("Role check failed: %v", err)
			http.Error(rw, errForbidden, http.StatusForbidden)
			return
		}
	}

	p.setMetadata(r, claims, roles, permissions)

	p.next.ServeHTTP(rw, r)
}

func (p *KeycloakAuthorizer) checkPermissions(permissions []string) error {
	if len(permissions) == 0 {
		return errors.New("No permission found")
	}

	some := util.Intersect(permissions, p.permissions.Some)
	if len(p.permissions.Some) > 0 && len(some) == 0 {
		return errors.New("Unmatched permissions")
	}

	every := util.Intersect(permissions, p.permissions.Every)
	if len(p.permissions.Every) > 0 && len(p.permissions.Every) > len(every) {
		return errors.New("Insufficient permissions")
	}

	return nil
}

func (p *KeycloakAuthorizer) checkRoles(roles map[string][]string) error {
	flattened := flattenRoles(roles)

	if len(flattened) == 0 {
		return errors.New("No role found")
	}

	some := util.Intersect(flattened, p.roles.Some)
	if len(p.roles.Some) > 0 && len(some) == 0 {
		return errors.New("Unmatched roles")
	}

	every := util.Intersect(flattened, p.roles.Every)
	if len(p.roles.Every) > 0 && len(p.roles.Every) > len(every) {
		return errors.New("Insufficient roles")
	}

	return nil
}

// flattenRoles renders a client->roles map as a flat "client:role" pair list, for gating only.
// Header output uses formatRoles (grouped), not this.
func flattenRoles(roles map[string][]string) []string {
	var pairs []string
	for client, names := range roles {
		for _, name := range names {
			pairs = append(pairs, client+":"+name)
		}
	}

	return pairs
}

func (p *KeycloakAuthorizer) setMetadata(
	r *http.Request,
	claims jwt.MapClaims,
	roles map[string][]string,
	permissions []string,
) {
	p.mapClaimsToHeaders(r, claims)

	if p.roles.Enabled {
		header := strings.TrimSpace(p.roles.HeaderName)
		if header == "" {
			header = defaultRolesHeaderName
		}

		r.Header.Set(header, formatRoles(roles))
	}

	if p.permissions.Enabled {
		header := strings.TrimSpace(p.permissions.HeaderName)
		if header == "" {
			header = defaultPermissionsHeaderName
		}

		r.Header.Set(header, strings.Join(permissions, ","))
	}
}

// formatRoles renders a client->roles map as "client:role1+role2,client2:role3",
// with clients and roles sorted alphabetically for deterministic output.
func formatRoles(roles map[string][]string) string {
	clients := make([]string, 0, len(roles))
	for client := range roles {
		clients = append(clients, client)
	}
	sort.Strings(clients)

	groups := make([]string, 0, len(clients))
	for _, client := range clients {
		groups = append(groups, client+":"+strings.Join(roles[client], "+"))
	}

	return strings.Join(groups, ",")
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
