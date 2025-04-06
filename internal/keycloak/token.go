// Package keycloak provides keycloak functionalities.
package keycloak

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func parseToken(token string) (jwt.MapClaims, error) {
	// Parse the JWT token without verifying the signature since the issuer is trusted
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse token claims")
	}

	return claims, nil
}

func readPermissions(token jwt.MapClaims) []string {
	var grants []string

	authorization, ok := token["authorization"].(map[string]interface{})
	if !ok {
		return grants
	}

	permissions, ok := authorization["permissions"]
	if !ok {
		return grants
	}

	permissionsList, ok := permissions.([]interface{})
	if !ok {
		return grants
	}

	for _, permission := range permissionsList {
		permissionMap, ok := permission.(map[string]interface{})
		if !ok {
			continue
		}

		rsname, ok := permissionMap["rsname"].(string)
		if !ok {
			continue
		}

		if scopes, ok := permissionMap["scopes"]; ok {
			scopesList, ok := scopes.([]interface{})
			if !ok {
				continue
			}

			for _, scope := range scopesList {
				scopeStr, ok := scope.(string)
				if !ok {
					continue
				}

				grants = append(grants, fmt.Sprintf("%s:%s", rsname, scopeStr))
			}
		}
	}

	return grants
}

// GetClaim retrieves a claim from the token.
func GetClaim(token jwt.MapClaims, claim string) (string, error) {
	claim, ok := token[claim].(string)
	if !ok {
		return "", fmt.Errorf("failed to get claim: %s", claim)
	}

	return claim, nil
}
