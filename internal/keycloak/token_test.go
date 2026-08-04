// Package keycloak provides keycloak functionalities.
package keycloak

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestReadRolesFlattensAndDedupesPerClient(t *testing.T) {
	token := jwt.MapClaims{
		"resource_access": map[string]interface{}{
			"kartapay-website": map[string]interface{}{
				"roles": []interface{}{"merchant", "customer", "merchant"},
			},
			"kartapay-bo": map[string]interface{}{
				"roles": []interface{}{"bo-agent"},
			},
			"account": map[string]interface{}{
				"roles": []interface{}{"manage-account", "manage-account-links", "view-profile"},
			},
		},
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"offline_access", "uma_authorization"},
		},
	}

	roles := ReadRoles(token)

	assert.Equal(t, map[string][]string{
		"kartapay-website": {"customer", "merchant"},
		"kartapay-bo":      {"bo-agent"},
		"account":          {"manage-account", "manage-account-links", "view-profile"},
	}, roles)
}

func TestReadRolesMissingResourceAccessReturnsEmptyMap(t *testing.T) {
	token := jwt.MapClaims{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"offline_access"},
		},
	}

	roles := ReadRoles(token)

	assert.Empty(t, roles)
}

func TestReadRolesMalformedResourceAccessReturnsEmptyMap(t *testing.T) {
	token := jwt.MapClaims{
		"resource_access": "not-a-map",
	}

	roles := ReadRoles(token)

	assert.Empty(t, roles)
}
