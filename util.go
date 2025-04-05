//nolint:revive
package traefik_keycloak_authorizer

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

func getRequestToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", errors.New("Header not found")
	}

	prefix := "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", errors.New("Header is invalid")
	}

	accessToken := header[len(prefix):]
	if accessToken == "" {
		return "", errors.New("Access token not found")
	}

	return accessToken, nil
}

func sendRequest(req *http.Request) ([]byte, error) {
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.New("Request client failed")
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Request failed with status: %s", res.Status)
	}

	defer func() {
		if err := res.Body.Close(); err != nil {
			log.Printf("Failed to close response body: %v", err)
		}
	}()

	return io.ReadAll(res.Body)
}

func toBase64String(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}
