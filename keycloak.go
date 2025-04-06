//nolint:revive
package traefik_keycloak_authorizer

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type keycloakAPIResponse struct {
	//nolint:tagliatelle
	AccessToken string `json:"access_token"`
}

func parseToken(token string) (jwt.MapClaims, error) {
	// Parse the JWT token without verifying the signature since the issuer is trusted
	parsed, _, err := jwt.NewParser().ParseUnverified(token, &jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse token claims")
	}

	return claims, nil
}

func getClaim(token jwt.MapClaims, claim string) (string, error) {
	claim, ok := token[claim].(string)
	if !ok {
		return "", fmt.Errorf("failed to get claim: %s", claim)
	}

	return claim, nil
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

	for _, permission := range permissions.([]interface{}) {
		permissionMap := permission.(map[string]interface{})
		rsname := permissionMap["rsname"].(string)

		if scopes, ok := permissionMap["scopes"]; ok {
			for _, scope := range scopes.([]interface{}) {
				grants = append(grants, fmt.Sprintf("%s:%s", rsname, scope.(string)))
			}
		}
	}

	return grants
}
