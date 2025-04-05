package traefik_keycloak_authorizer

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type KeycloakPermission struct {
	Rsid 	string 		`json:"rsid"`
	Rsname 	string 		`json:"rsname"`
	Scopes	[]string 	`json:"scopes,omitempty"`
}

type KeycloakAuthorization struct {
	Permissions []KeycloakPermission `json:"permissions"`
}

type KeycloakAccessToken struct {
	jwt.RegisteredClaims

	// The following fields are not standard JWT claims but are included for convenience
	AuthorizedParty	string 	`json:"azp"`
	Authorization	KeycloakAuthorization `json:"authorization"`
}

type KeycloakApiResponse struct {
	AccessToken string `json:"access_token"`
}

func ParseToken(token string) (*KeycloakAccessToken, error) {
	// Parse the JWT token without verifying the signature since the issuer is trusted
	claims := &KeycloakAccessToken{}
	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	})
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func ReadPermissions(token *KeycloakAccessToken) ([]string, error) {
	var permissions []string
	for _, permission := range token.Authorization.Permissions {
		if len(permission.Scopes) > 0 {
			for _, scope := range permission.Scopes {
				permissions = append(permissions, fmt.Sprintf("%s:%s", permission.Rsname, scope))
			}
		}
	}

	return permissions, nil
}