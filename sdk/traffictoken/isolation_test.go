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
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransportCacheIsIsolatedPerClient(t *testing.T) {
	issuedAt := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	var signingCalls atomic.Int32
	signer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := signingCalls.Add(1)
		writeTokenResponse(t, w, fmt.Sprintf("instance-token-%d", call), issuedAt.Add(time.Hour))
	}))
	t.Cleanup(signer.Close)

	seenTokens := make(chan string, 2)
	gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenTokens <- r.Header.Get(TrafficAccessTokenHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(gateway.Close)

	first := newTestClient(t, signer, func(context.Context) (string, error) { return "bearer", nil })
	second := newTestClient(t, signer, func(context.Context) (string, error) { return "bearer", nil })
	first.now = func() time.Time { return issuedAt }
	second.now = func() time.Time { return issuedAt }
	doGet(t, &http.Client{Transport: newTestTransport(t, first, gateway)}, gateway.URL)
	doGet(t, &http.Client{Transport: newTestTransport(t, second, gateway)}, gateway.URL)

	if firstToken, secondToken := <-seenTokens, <-seenTokens; firstToken == secondToken {
		t.Fatalf("independent clients used the same issued token %q", firstToken)
	}
	if got := signingCalls.Load(); got != 2 {
		t.Fatalf("signing calls = %d, want 2", got)
	}
}
