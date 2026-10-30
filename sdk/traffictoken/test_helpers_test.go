/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package traffictoken

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func newTestClient(t *testing.T, signer *httptest.Server, provider BearerTokenProvider) *Client {
	t.Helper()
	client, err := New(Config{
		ManagerURL:          signer.URL + "/base",
		Namespace:           "team-a",
		SandboxID:           "sandbox/id",
		SandboxUID:          "uid-1",
		BearerTokenProvider: provider,
		SigningClient:       signer.Client(),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

func newTestTransport(t *testing.T, client *Client, gateway *httptest.Server) *Transport {
	t.Helper()
	transport, err := client.NewTransport(gateway.URL, gateway.Client().Transport)
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	return transport
}

func newTokenServer(t *testing.T, token string, expiration time.Time) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTokenResponse(t, w, token, expiration)
	}))
	t.Cleanup(server.Close)
	return server
}

func writeTokenResponse(t *testing.T, w http.ResponseWriter, token string, expiration time.Time) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"trafficAccessToken":           token,
		"trafficAccessTokenExpiration": expiration.Format(time.RFC3339Nano),
	}); err != nil {
		t.Errorf("encode token response: %v", err)
	}
}

func writeFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
