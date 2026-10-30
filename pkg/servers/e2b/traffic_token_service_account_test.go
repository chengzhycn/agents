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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/claimidentity"
	"github.com/openkruise/agents/pkg/identity"
	"github.com/openkruise/agents/pkg/sandbox-manager/infra"
	"github.com/openkruise/agents/pkg/sandboxid"
)

const (
	testServiceAccountUsername = "system:serviceaccount:sandbox-system:workload"
	testServiceAccountUID      = "service-account-uid"
)

type fakeTokenReviewer struct {
	calls  int
	review func(string) (*authenticationv1.TokenReview, error)
}

func (f *fakeTokenReviewer) Create(_ context.Context, review *authenticationv1.TokenReview, _ metav1.CreateOptions) (*authenticationv1.TokenReview, error) {
	f.calls++
	return f.review(review.Spec.Token)
}

func TestTrafficAccessTokenRouteAuthenticatesServiceAccountBearer(t *testing.T) {
	controller, sandboxID, provider, teardown := setupServiceAccountTrafficTokenRoute(t)
	defer teardown()
	reviewer := &fakeTokenReviewer{review: func(token string) (*authenticationv1.TokenReview, error) {
		switch token {
		case "valid":
			return authenticatedTokenReview(testServiceAccountUsername, testServiceAccountUID), nil
		case "wrong-binding":
			return authenticatedTokenReview("system:serviceaccount:sandbox-system:other", "other-uid"), nil
		case "review-error":
			return nil, errors.New("token review unavailable")
		case "status-error":
			return &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{Error: "invalid token"}}, nil
		case "non-service-account":
			return authenticatedTokenReview("regular-user", "user-uid"), nil
		case "empty-uid":
			return authenticatedTokenReview(testServiceAccountUsername, ""), nil
		default:
			return &authenticationv1.TokenReview{}, nil
		}
	}}
	controller.tokenReviewer = reviewer

	tests := []struct {
		name           string
		token          string
		apiKey         string
		namespaceQuery string
		repeatAuth     bool
		wantStatus     int
		wantReview     bool
	}{
		{name: "authorized service account", token: "valid", namespaceQuery: "?namespace=sandbox-system", wantStatus: http.StatusOK, wantReview: true},
		{name: "invalid bearer", token: "invalid", namespaceQuery: "?namespace=sandbox-system", wantStatus: http.StatusUnauthorized, wantReview: true},
		{name: "token review status error", token: "status-error", namespaceQuery: "?namespace=sandbox-system", wantStatus: http.StatusUnauthorized, wantReview: true},
		{name: "non service account", token: "non-service-account", namespaceQuery: "?namespace=sandbox-system", wantStatus: http.StatusUnauthorized, wantReview: true},
		{name: "empty uid", token: "empty-uid", namespaceQuery: "?namespace=sandbox-system", wantStatus: http.StatusUnauthorized, wantReview: true},
		{name: "malformed bearer", token: "valid extra", namespaceQuery: "?namespace=sandbox-system", wantStatus: http.StatusUnauthorized},
		{name: "multiple authorization headers", token: "valid", namespaceQuery: "?namespace=sandbox-system", repeatAuth: true, wantStatus: http.StatusUnauthorized},
		{name: "mixed credentials", token: "valid", apiKey: InitKey, namespaceQuery: "?namespace=sandbox-system", wantStatus: http.StatusUnauthorized},
		{name: "missing namespace", token: "valid", wantStatus: http.StatusUnauthorized},
		{name: "duplicate namespace", token: "valid", namespaceQuery: "?namespace=sandbox-system&namespace=other", wantStatus: http.StatusUnauthorized},
		{name: "wrong binding is concealed", token: "wrong-binding", namespaceQuery: "?namespace=sandbox-system", wantStatus: http.StatusNotFound, wantReview: true},
		{name: "review unavailable", token: "review-error", namespaceQuery: "?namespace=sandbox-system", wantStatus: http.StatusServiceUnavailable, wantReview: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := reviewer.calls
			request := httptest.NewRequest(http.MethodPost, "/kruise/api/sandboxes/"+sandboxID+"/traffic-access-token"+tt.namespaceQuery, nil)
			request.Header.Set("Authorization", "Bearer "+tt.token)
			if tt.repeatAuth {
				request.Header.Add("Authorization", "Bearer second")
			}
			if tt.apiKey != "" {
				request.Header.Set("X-API-KEY", tt.apiKey)
			}
			response := httptest.NewRecorder()

			controller.mux.ServeHTTP(response, request)

			assert.Equal(t, tt.wantStatus, response.Code)
			if tt.wantReview {
				assert.Equal(t, before+1, reviewer.calls)
			} else {
				assert.Equal(t, before, reviewer.calls)
			}
		})
	}
	assert.Equal(t, int32(1), provider.calls.Load())
}

func TestTrafficAccessTokenRouteConcealsMissingTargetLikeWrongBinding(t *testing.T) {
	controller, sandboxID, _, teardown := setupServiceAccountTrafficTokenRoute(t)
	defer teardown()
	controller.tokenReviewer = &fakeTokenReviewer{review: func(string) (*authenticationv1.TokenReview, error) {
		return authenticatedTokenReview("system:serviceaccount:sandbox-system:other", "other-uid"), nil
	}}

	request := func(id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/kruise/api/sandboxes/"+id+"/traffic-access-token?namespace=sandbox-system", nil)
		req.Header.Set("Authorization", "Bearer token")
		req.Header.Set("X-Request-ID", "0123456789abcdef0123456789abcdef")
		response := httptest.NewRecorder()
		controller.mux.ServeHTTP(response, req)
		return response
	}

	wrongBinding := request(sandboxID)
	missing := request("missing-sandbox")
	assert.Equal(t, http.StatusNotFound, wrongBinding.Code)
	assert.Equal(t, wrongBinding.Body.String(), missing.Body.String())
}

func setupServiceAccountTrafficTokenRoute(t *testing.T) (*Controller, string, *e2bTrafficTokenProvider, func()) {
	t.Helper()
	controller, client, teardown := Setup(t)
	provider := &e2bTrafficTokenProvider{}
	identity.RegisterProvider(provider)
	t.Cleanup(func() { identity.RegisterProvider(identity.NewDefaultIdentityProvider()) })
	sandbox := &v1alpha1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "service-account-refresh",
			Namespace: "sandbox-system",
			UID:       "service-account-refresh-uid",
			Labels:    map[string]string{v1alpha1.LabelSandboxIsClaimed: v1alpha1.True},
			Annotations: map[string]string{
				v1alpha1.AnnotationOwner:         "claim-uid",
				identity.AnnotationEnableJwtAuth: v1alpha1.True,
				claimidentity.UsernameAnnotation: testServiceAccountUsername,
				claimidentity.UIDAnnotation:      testServiceAccountUID,
			},
		},
		Status: v1alpha1.SandboxStatus{
			Phase:      v1alpha1.SandboxRunning,
			Conditions: []metav1.Condition{{Type: string(v1alpha1.SandboxConditionReady), Status: metav1.ConditionTrue}},
		},
	}
	CreateSandboxWithStatus(t, client, sandbox)
	sandboxID := sandboxid.Resolve(sandbox)
	require.Eventually(t, func() bool {
		_, err := controller.manager.GetInfra().GetSandbox(t.Context(), infra.GetSandboxOptions{Namespace: sandbox.Namespace, SandboxID: sandboxID})
		return err == nil
	}, time.Second, 10*time.Millisecond)
	return controller, sandboxID, provider, teardown
}

func authenticatedTokenReview(username, uid string) *authenticationv1.TokenReview {
	return &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{
		Authenticated: true,
		User:          authenticationv1.UserInfo{Username: username, UID: uid},
	}}
}
