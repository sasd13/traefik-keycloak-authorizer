// Package util provides util functionalities.
package util

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRequestTokenReturnsToken(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer the-token")

	token, err := GetRequestToken(req)

	assert.NoError(t, err)
	assert.Equal(t, "the-token", token)
}

func TestGetRequestTokenErrorsWhenHeaderMissing(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost", nil)
	assert.NoError(t, err)

	_, err = GetRequestToken(req)

	assert.Error(t, err)
}

func TestGetRequestTokenErrorsWhenHeaderMissingBearerPrefix(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Basic the-token")

	_, err = GetRequestToken(req)

	assert.Error(t, err)
}

func TestGetRequestTokenErrorsWhenTokenEmpty(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer ")

	_, err = GetRequestToken(req)

	assert.Error(t, err)
}

func TestSendRequestReturnsBodyOnSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	assert.NoError(t, err)

	body, err := SendRequest(req)

	assert.NoError(t, err)
	assert.Equal(t, `{"ok":true}`, string(body))
}

func TestSendRequestErrorsOnNonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	assert.NoError(t, err)

	_, err = SendRequest(req)

	assert.Error(t, err)
}

func TestSendRequestErrorsWhenClientFails(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:0", nil)
	assert.NoError(t, err)

	_, err = SendRequest(req)

	assert.Error(t, err)
}
