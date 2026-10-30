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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRefreshSurvivesInitiatingCallerCancellation(t *testing.T) {
	issuedAt := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	signer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		writeTokenResponse(t, w, "surviving-token", issuedAt.Add(time.Hour))
	}))
	t.Cleanup(signer.Close)
	client := newTestClient(t, signer, func(context.Context) (string, error) { return "bearer", nil })
	client.now = func() time.Time { return issuedAt }
	leaderCtx, cancelLeader := context.WithCancel(t.Context())
	defer cancelLeader()
	leader := make(chan refreshResult, 1)
	go refreshInto(leaderCtx, client, leader)
	<-started
	waiterCtx := newObservedContext(t.Context())
	waiter := make(chan refreshResult, 1)
	go refreshInto(waiterCtx, client, waiter)
	<-waiterCtx.observed

	cancelLeader()
	if result := <-leader; !errors.Is(result.err, context.Canceled) {
		t.Errorf("initiating caller error = %v, want context.Canceled", result.err)
	}
	close(release)
	result := <-waiter
	if result.err != nil || result.token.Token != "surviving-token" {
		t.Fatalf("waiter result = %+v, want surviving token", result)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("signing requests = %d, want 1", got)
	}
}
