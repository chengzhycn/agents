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

package e2b

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	authenticationclient "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"

	"github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/sandbox-manager/infra"
	"github.com/openkruise/agents/sdk/traffictoken"
)

func TestTrafficTokenTransportThroughLiveRefreshRoute(t *testing.T) {
	// Given a delivered short-ID Sandbox with no surviving Claim dependency.
	controller, sandboxID, provider, teardown := setupServiceAccountTrafficTokenRoute(t)
	defer teardown()
	sandbox, err := controller.manager.GetInfra().GetSandbox(t.Context(), infra.GetSandboxOptions{
		Namespace: "sandbox-system", SandboxID: sandboxID,
	})
	require.NoError(t, err)
	shortID := "claim-traffic-short-id"
	updated := &v1alpha1.Sandbox{}
	key := types.NamespacedName{Namespace: sandbox.GetNamespace(), Name: sandbox.GetName()}
	backend := controller.manager.GetInfra().GetCache().GetClient()
	require.NoError(t, backend.Get(t.Context(), key, updated))
	updated.Labels[v1alpha1.LabelSandboxID] = shortID
	require.NoError(t, backend.Update(t.Context(), updated))
	require.Eventually(t, func() bool {
		_, lookupErr := controller.manager.GetInfra().GetSandbox(t.Context(), infra.GetSandboxOptions{
			Namespace: updated.Namespace, SandboxID: shortID,
		})
		return lookupErr == nil
	}, time.Second, 10*time.Millisecond)

	var reviews atomic.Int32
	kubernetes := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reviews.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" {
			http.Error(w, "unexpected Kubernetes request", http.StatusNotFound)
			return
		}
		var review authenticationv1.TokenReview
		if decodeErr := json.NewDecoder(r.Body).Decode(&review); decodeErr != nil {
			t.Errorf("decode TokenReview (%s): %v", r.Header.Get("Content-Type"), decodeErr)
			http.Error(w, "invalid review", http.StatusBadRequest)
			return
		}
		result := authenticatedTokenReview(testServiceAccountUsername, testServiceAccountUID)
		if review.Spec.Token != "renewable-service-account-token" {
			result.Status.Authenticated = false
		}
		result.TypeMeta = metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}
		w.Header().Set("Content-Type", "application/json")
		if encodeErr := json.NewEncoder(w).Encode(result); encodeErr != nil {
			t.Errorf("encode TokenReview: %v", encodeErr)
		}
	}))
	t.Cleanup(kubernetes.Close)
	authentication, err := authenticationclient.NewForConfig(&rest.Config{
		Host: kubernetes.URL,
		ContentConfig: rest.ContentConfig{
			ContentType: "application/json", AcceptContentTypes: "application/json",
		},
		TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: kubernetes.Certificate().Raw,
		})},
	})
	require.NoError(t, err)
	controller.tokenReviewer = authentication.TokenReviews()
	manager := httptest.NewTLSServer(controller.mux)
	t.Cleanup(manager.Close)
	var gatewayRequests atomic.Int32
	gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gatewayRequests.Add(1)
		require.NotEmpty(t, r.Header.Get(traffictoken.TrafficAccessTokenHeader))
		require.Empty(t, r.Header.Get("Authorization"))
		require.Equal(t, "independent-runtime-token", r.Header.Get("X-Access-Token"))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(gateway.Close)
	tokens, err := traffictoken.New(traffictoken.Config{
		ManagerURL: manager.URL, Namespace: updated.Namespace, SandboxID: shortID,
		SandboxUID: string(updated.UID), SigningClient: manager.Client(),
		BearerTokenProvider: func(context.Context) (string, error) {
			return "renewable-service-account-token", nil
		},
	})
	require.NoError(t, err)
	transport, err := tokens.NewTransport(gateway.URL, gateway.Client().Transport)
	require.NoError(t, err)
	runtimeClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	// When two data-plane requests use the same transport.
	for range 2 {
		request, requestErr := http.NewRequestWithContext(t.Context(), http.MethodGet, gateway.URL+"/files", nil)
		require.NoError(t, requestErr)
		request.Header.Set("X-Access-Token", "independent-runtime-token")
		response, requestErr := runtimeClient.Do(request)
		require.NoError(t, requestErr)
		require.Equal(t, http.StatusNoContent, response.StatusCode)
		_, readErr := io.Copy(io.Discard, response.Body)
		require.NoError(t, readErr)
		require.NoError(t, response.Body.Close())
	}

	// Then only the first request reviews the SA and signs a token.
	require.Equal(t, int32(1), reviews.Load())
	require.Equal(t, int32(1), provider.calls.Load())
	require.Equal(t, int32(2), gatewayRequests.Load())
}
