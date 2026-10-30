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
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRefreshCoalescesConcurrentCalls(t *testing.T) {
	issuedAt := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	var requestCount atomic.Int32

	signer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		close(requestStarted)
		<-releaseRequest
		writeTokenResponse(t, w, "coalesced-token", issuedAt.Add(time.Hour))
	}))
	t.Cleanup(signer.Close)

	client := newTestClient(t, signer, func(context.Context) (string, error) { return "api-token", nil })
	client.now = func() time.Time { return issuedAt }

	const callers = 8
	results := make(chan refreshResult, callers)
	go refreshInto(context.Background(), client, results)
	<-requestStarted

	observed := make([]chan struct{}, 0, callers-1)
	for range callers - 1 {
		ctx := newObservedContext(context.Background())
		observed = append(observed, ctx.observed)
		go refreshInto(ctx, client, results)
	}
	for _, waiterObserved := range observed {
		<-waiterObserved
	}
	close(releaseRequest)

	for range callers {
		result := <-results
		if result.err != nil {
			t.Fatalf("Refresh() error = %v", result.err)
		}
		if result.token.Token != "coalesced-token" {
			t.Errorf("Refresh() token = %q, want coalesced-token", result.token.Token)
		}
	}
	if got := requestCount.Load(); got != 1 {
		t.Fatalf("signing requests = %d, want 1", got)
	}
}

func TestRefreshLetsCanceledWaiterLeaveSharedWork(t *testing.T) {
	issuedAt := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})

	signer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(requestStarted)
		<-releaseRequest
		writeTokenResponse(t, w, "surviving-token", issuedAt.Add(time.Hour))
	}))
	t.Cleanup(signer.Close)

	client := newTestClient(t, signer, func(context.Context) (string, error) { return "api-token", nil })
	client.now = func() time.Time { return issuedAt }
	leader := make(chan refreshResult, 1)
	go refreshInto(context.Background(), client, leader)
	<-requestStarted

	waiterBase, cancelWaiter := context.WithCancel(context.Background())
	waiterCtx := newObservedContext(waiterBase)
	waiter := make(chan refreshResult, 1)
	go refreshInto(waiterCtx, client, waiter)
	<-waiterCtx.observed
	cancelWaiter()
	if result := <-waiter; !errors.Is(result.err, context.Canceled) {
		t.Fatalf("canceled Refresh() error = %v, want context.Canceled", result.err)
	}

	close(releaseRequest)
	result := <-leader
	if result.err != nil {
		t.Fatalf("leader Refresh() error = %v", result.err)
	}
	if result.token.Token != "surviving-token" {
		t.Fatalf("leader token = %q, want surviving-token", result.token.Token)
	}
}

func TestRefreshDoesNotRedirectSigningBearer(t *testing.T) {
	var redirectedCalls atomic.Int32
	redirected := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedCalls.Add(1)
	}))
	t.Cleanup(redirected.Close)
	signer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer api-token" {
			t.Errorf("Authorization = %q", got)
		}
		http.Redirect(w, r, redirected.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(signer.Close)

	client := newTestClient(t, signer, func(context.Context) (string, error) { return "api-token", nil })
	_, err := client.Refresh(context.Background())
	var statusError *HTTPStatusError
	if !errors.As(err, &statusError) || statusError.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("Refresh() error = %v, want HTTP 307 status error", err)
	}
	if got := redirectedCalls.Load(); got != 0 {
		t.Fatalf("redirected signing calls = %d, want 0", got)
	}
}

func TestRefreshBoundsSigningWork(t *testing.T) {
	requestCanceled := make(chan struct{})
	signer := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		close(requestCanceled)
	}))
	t.Cleanup(signer.Close)
	signingClient := signer.Client()
	signingClient.Timeout = 20 * time.Millisecond
	client, err := New(Config{
		ManagerURL:          signer.URL,
		Namespace:           "team-a",
		SandboxID:           "sandbox-id",
		BearerTokenProvider: func(context.Context) (string, error) { return "api-token", nil },
		SigningClient:       signingClient,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := client.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh() error = nil, want timeout")
	}
	<-requestCanceled
}

func TestRefreshReadsBearerFileForEveryIssuance(t *testing.T) {
	issuedAt := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	path := t.TempDir() + "/token"
	writeFile(t, path, "first-bearer\n")

	seenAuthorization := make(chan string, 2)
	signer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuthorization <- r.Header.Get("Authorization")
		writeTokenResponse(t, w, fmt.Sprintf("token-%d", len(seenAuthorization)), issuedAt.Add(time.Hour))
	}))
	t.Cleanup(signer.Close)

	client := newTestClient(t, signer, BearerTokenFile(path))
	client.now = func() time.Time { return issuedAt }
	if _, err := client.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh() error = %v", err)
	}
	writeFile(t, path, "second-bearer")
	if _, err := client.Refresh(context.Background()); err != nil {
		t.Fatalf("second Refresh() error = %v", err)
	}

	if got := <-seenAuthorization; got != "Bearer first-bearer" {
		t.Errorf("first Authorization = %q", got)
	}
	if got := <-seenAuthorization; got != "Bearer second-bearer" {
		t.Errorf("second Authorization = %q", got)
	}
}

type refreshResult struct {
	token Token
	err   error
}

func refreshInto(ctx context.Context, client *Client, results chan<- refreshResult) {
	token, err := client.Refresh(ctx)
	results <- refreshResult{token: token, err: err}
}

type observedContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func newObservedContext(parent context.Context) *observedContext {
	return &observedContext{Context: parent, observed: make(chan struct{})}
}

func (c *observedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}
