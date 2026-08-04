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
			"client-x": map[string]interface{}{
				"roles": []interface{}{"merchant", "customer", "merchant"},
			},
			"client-y": map[string]interface{}{
				"roles": []interface{}{"agent"},
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
		"client-x": {"customer", "merchant"},
		"client-y": {"agent"},
		"account":  {"manage-account", "manage-account-links", "view-profile"},
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

func TestReadRolesSkipsMalformedClientEntries(t *testing.T) {
	token := jwt.MapClaims{
		"resource_access": map[string]interface{}{
			"not-a-map-client":    "not-a-map",
			"no-roles-key-client": map[string]interface{}{},
			"roles-not-list-client": map[string]interface{}{
				"roles": "not-a-list",
			},
			"client-y": map[string]interface{}{
				"roles": []interface{}{"agent"},
			},
		},
	}

	roles := ReadRoles(token)

	assert.Equal(t, map[string][]string{"client-y": {"agent"}}, roles)
}

func TestReadRolesSkipsClientWithNoValidRoleNames(t *testing.T) {
	token := jwt.MapClaims{
		"resource_access": map[string]interface{}{
			"client-x": map[string]interface{}{
				"roles": []interface{}{42, true}, // no string entries at all
			},
			"client-y": map[string]interface{}{
				"roles": []interface{}{"agent"},
			},
		},
	}

	roles := ReadRoles(token)

	assert.Equal(t, map[string][]string{"client-y": {"agent"}}, roles)
}

func TestParseTokenErrorsOnMalformedToken(t *testing.T) {
	_, err := ParseToken("not-a-jwt")

	assert.Error(t, err)
}

func TestReadPermissionsHappyPath(t *testing.T) {
	token := jwt.MapClaims{
		"authorization": map[string]interface{}{
			"permissions": []interface{}{
				map[string]interface{}{
					"rsname": "orders",
					"scopes": []interface{}{"read", "write"},
				},
				map[string]interface{}{
					"rsname": "billing",
					"scopes": []interface{}{"view"},
				},
			},
		},
	}

	permissions := ReadPermissions(token)

	assert.ElementsMatch(t, []string{"orders:read", "orders:write", "billing:view"}, permissions)
}

func TestReadPermissionsMissingPermissionsKeyReturnsEmpty(t *testing.T) {
	token := jwt.MapClaims{
		"authorization": map[string]interface{}{},
	}

	assert.Empty(t, ReadPermissions(token))
}

func TestReadPermissionsPermissionsNotListReturnsEmpty(t *testing.T) {
	token := jwt.MapClaims{
		"authorization": map[string]interface{}{
			"permissions": "not-a-list",
		},
	}

	assert.Empty(t, ReadPermissions(token))
}

func TestReadPermissionsSkipsNonMapEntries(t *testing.T) {
	token := jwt.MapClaims{
		"authorization": map[string]interface{}{
			"permissions": []interface{}{"not-a-map"},
		},
	}

	assert.Empty(t, ReadPermissions(token))
}

func TestReadPermissionsSkipsEntriesMissingRsname(t *testing.T) {
	token := jwt.MapClaims{
		"authorization": map[string]interface{}{
			"permissions": []interface{}{
				map[string]interface{}{"scopes": []interface{}{"read"}},
			},
		},
	}

	assert.Empty(t, ReadPermissions(token))
}

func TestReadPermissionsSkipsWhenScopesNotList(t *testing.T) {
	token := jwt.MapClaims{
		"authorization": map[string]interface{}{
			"permissions": []interface{}{
				map[string]interface{}{"rsname": "orders", "scopes": "not-a-list"},
			},
		},
	}

	assert.Empty(t, ReadPermissions(token))
}

func TestReadPermissionsSkipsNonStringScopes(t *testing.T) {
	token := jwt.MapClaims{
		"authorization": map[string]interface{}{
			"permissions": []interface{}{
				map[string]interface{}{"rsname": "orders", "scopes": []interface{}{42}},
			},
		},
	}

	assert.Empty(t, ReadPermissions(token))
}

func TestGetClaimReturnsValue(t *testing.T) {
	token := jwt.MapClaims{"sub": "1234567890"}

	value, err := GetClaim(token, "sub")

	assert.NoError(t, err)
	assert.Equal(t, "1234567890", value)
}

func TestGetClaimErrorsWhenMissingOrWrongType(t *testing.T) {
	token := jwt.MapClaims{"sub": 12345}

	_, err := GetClaim(token, "sub")
	assert.Error(t, err)

	_, err = GetClaim(token, "missing")
	assert.Error(t, err)
}
