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
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransportInjectsTokenWithoutMutatingRequest(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	var bearerCalls atomic.Int32
	signer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.EscapedPath() != "/base/kruise/api/sandboxes/sandbox%2Fid/traffic-access-token" {
			t.Errorf("path = %q", r.URL.EscapedPath())
		}
		if values := r.URL.Query()["namespace"]; len(values) != 1 || values[0] != "team-a" {
			t.Errorf("namespace values = %v", values)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer signing-bearer" {
			t.Errorf("Authorization = %q", got)
		}
		writeTokenResponse(t, w, "traffic-jwt", now.Add(time.Hour))
	}))
	t.Cleanup(signer.Close)

	gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(TrafficAccessTokenHeader); got != "traffic-jwt" {
			t.Errorf("traffic token = %q", got)
		}
		if got := r.Header.Get("X-Access-Token"); got != "runtime-token" {
			t.Errorf("X-Access-Token = %q", got)
		}
		if got := r.Header.Get("X-Custom"); got != "preserved" {
			t.Errorf("X-Custom = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("signing bearer leaked to gateway: %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(gateway.Close)

	client := newTestClient(t, signer, func(context.Context) (string, error) {
		bearerCalls.Add(1)
		return "signing-bearer", nil
	})
	client.now = func() time.Time { return now }
	transport := newTestTransport(t, client, gateway)
	httpClient := &http.Client{Transport: transport}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, gateway.URL+"/health", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	request.Header.Set(TrafficAccessTokenHeader, "callers-old-token")
	request.Header.Set("X-Access-Token", "runtime-token")
	request.Header.Set("X-Custom", "preserved")
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	closeResponse(t, response)

	if got := request.Header.Get(TrafficAccessTokenHeader); got != "callers-old-token" {
		t.Fatalf("original request token = %q, want callers-old-token", got)
	}
	if got := bearerCalls.Load(); got != 1 {
		t.Fatalf("bearer provider calls = %d, want 1", got)
	}
}

func TestTransportCachesUntilAdaptiveRefreshMargin(t *testing.T) {
	current := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	var signingCalls atomic.Int32
	signer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := signingCalls.Add(1)
		writeTokenResponse(t, w, fmt.Sprintf("token-%d", call), current.Add(100*time.Second))
	}))
	t.Cleanup(signer.Close)

	seenTokens := make(chan string, 3)
	gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenTokens <- r.Header.Get(TrafficAccessTokenHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(gateway.Close)

	client := newTestClient(t, signer, func(context.Context) (string, error) { return "bearer", nil })
	now := current
	client.now = func() time.Time { return now }
	httpClient := &http.Client{Transport: newTestTransport(t, client, gateway)}

	doGet(t, httpClient, gateway.URL)
	now = current.Add(79 * time.Second)
	doGet(t, httpClient, gateway.URL)
	now = current.Add(80 * time.Second)
	doGet(t, httpClient, gateway.URL)

	want := []string{"token-1", "token-1", "token-2"}
	for _, wantToken := range want {
		if got := <-seenTokens; got != wantToken {
			t.Errorf("gateway token = %q, want %q", got, wantToken)
		}
	}
	if got := signingCalls.Load(); got != 2 {
		t.Fatalf("signing calls = %d, want 2", got)
	}
}

func TestTransportFailsClosedAfterRefreshFailureAndExpiration(t *testing.T) {
	issuedAt := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	var signingCalls atomic.Int32
	signer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if signingCalls.Add(1) == 1 {
			writeTokenResponse(t, w, "short-token", issuedAt.Add(10*time.Second))
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(signer.Close)

	var gatewayCalls atomic.Int32
	gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gatewayCalls.Add(1)
		if got := r.Header.Get(TrafficAccessTokenHeader); got != "short-token" {
			t.Errorf("fallback traffic token = %q, want short-token", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(gateway.Close)

	now := issuedAt
	client := newTestClient(t, signer, func(context.Context) (string, error) { return "bearer", nil })
	client.now = func() time.Time { return now }
	httpClient := &http.Client{Transport: newTestTransport(t, client, gateway)}

	doGet(t, httpClient, gateway.URL)
	now = issuedAt.Add(9 * time.Second)
	doGet(t, httpClient, gateway.URL)
	now = issuedAt.Add(10 * time.Second)
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, gateway.URL, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	response, err := httpClient.Do(request)
	if response != nil {
		closeResponse(t, response)
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired Do() error = %v, want ErrTokenExpired", err)
	}
	if got := gatewayCalls.Load(); got != 2 {
		t.Fatalf("gateway calls = %d, want 2", got)
	}
}

func TestTransportRejectsCrossOriginRedirect(t *testing.T) {
	issuedAt := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	signer := newTokenServer(t, "redirect-token", issuedAt.Add(time.Hour))
	var redirectedCalls atomic.Int32
	redirected := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedCalls.Add(1)
	}))
	t.Cleanup(redirected.Close)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirected.URL, http.StatusFound)
	}))
	t.Cleanup(origin.Close)

	client := newTestClient(t, signer, func(context.Context) (string, error) { return "bearer", nil })
	client.now = func() time.Time { return issuedAt }
	httpClient := &http.Client{Transport: newTestTransport(t, client, origin)}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	response, err := httpClient.Do(request)
	if response != nil {
		closeResponse(t, response)
	}
	if !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("redirect error = %v, want ErrOriginMismatch", err)
	}
	if got := redirectedCalls.Load(); got != 0 {
		t.Fatalf("redirect target calls = %d, want 0", got)
	}
}

func doGet(t *testing.T, client *http.Client, target string) {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	closeResponse(t, response)
}

func closeResponse(t *testing.T, response *http.Response) {
	t.Helper()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Errorf("read response body: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Errorf("close response body: %v", err)
	}
}
