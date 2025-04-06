// Package util provides util functionalities.
package util

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// GetRequestToken extracts the token from the Authorization header of the request.
func GetRequestToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", errors.New("Header not found")
	}

	prefix := "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", errors.New("Header is invalid")
	}

	token := header[len(prefix):]
	if token == "" {
		return "", errors.New("Token not found")
	}

	return token, nil
}

// SendRequest sends an HTTP request and returns the response body.
func SendRequest(req *http.Request) ([]byte, error) {
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
