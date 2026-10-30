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

package sandbox_manager

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/claimidentity"
	"github.com/openkruise/agents/pkg/identity"
	"github.com/openkruise/agents/pkg/sandbox-manager/config"
	managererrors "github.com/openkruise/agents/pkg/sandbox-manager/errors"
	"github.com/openkruise/agents/pkg/sandbox-manager/infra"
	"github.com/openkruise/agents/pkg/sandboxid"
)

const (
	managerTestSAUsername = "system:serviceaccount:test:workload"
	managerTestSAUID      = "workload-uid"
)

func TestSandboxManagerRefreshTrafficAccessTokenAuthorizesServiceAccountBinding(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*v1alpha1.Sandbox, *ServiceAccountIdentity)
		wantCode   managererrors.ErrorCode
		wantIssuer int32
	}{
		{name: "matching binding", wantIssuer: 1},
		{name: "username mismatch", mutate: func(_ *v1alpha1.Sandbox, identity *ServiceAccountIdentity) {
			identity.Username = "system:serviceaccount:test:other"
		}, wantCode: managererrors.ErrorNotAllowed},
		{name: "uid mismatch", mutate: func(_ *v1alpha1.Sandbox, identity *ServiceAccountIdentity) { identity.UID = "other-uid" }, wantCode: managererrors.ErrorNotAllowed},
		{name: "owner missing", mutate: func(sandbox *v1alpha1.Sandbox, _ *ServiceAccountIdentity) {
			delete(sandbox.Annotations, v1alpha1.AnnotationOwner)
		}, wantCode: managererrors.ErrorNotAllowed},
		{name: "object uid missing", mutate: func(sandbox *v1alpha1.Sandbox, _ *ServiceAccountIdentity) { sandbox.UID = "" }, wantCode: managererrors.ErrorNotAllowed},
		{name: "binding missing", mutate: func(sandbox *v1alpha1.Sandbox, _ *ServiceAccountIdentity) {
			delete(sandbox.Annotations, claimidentity.UIDAnnotation)
		}, wantCode: managererrors.ErrorNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, client, sandbox, sandboxID := setupBoundTrafficTokenSandbox(t, tt.name)
			principal := ServiceAccountIdentity{Username: managerTestSAUsername, UID: managerTestSAUID}
			if tt.mutate != nil {
				tt.mutate(sandbox, &principal)
				require.NoError(t, client.Update(t.Context(), sandbox))
				require.Eventually(t, func() bool {
					observed, err := manager.infra.GetSandbox(t.Context(), infra.GetSandboxOptions{Namespace: sandbox.Namespace, SandboxID: sandboxID})
					return err == nil && observed.GetUID() == sandbox.UID && observed.GetAnnotations()[claimidentity.UIDAnnotation] == sandbox.Annotations[claimidentity.UIDAnnotation]
				}, time.Second, 10*time.Millisecond)
			}
			provider := &trafficTokenTestProvider{}
			identity.RegisterProvider(provider)
			t.Cleanup(func() { identity.RegisterProvider(identity.NewDefaultIdentityProvider()) })

			result, err := manager.RefreshTrafficAccessToken(t.Context(), RefreshTrafficAccessTokenOptions{
				Namespace:      sandbox.Namespace,
				SandboxID:      sandboxID,
				ServiceAccount: &principal,
			})

			if tt.wantCode != "" {
				require.Error(t, err)
				assert.Equal(t, tt.wantCode, managererrors.GetErrCode(err))
				assert.Empty(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "refreshed-token", result.Token)
			}
			assert.Equal(t, tt.wantIssuer, provider.calls.Load())
		})
	}
}

func TestSandboxManagerRefreshTrafficAccessTokenRejectsChangedIssuanceSnapshot(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*testing.T, ctrlclient.Client, *v1alpha1.Sandbox)
		wantCode managererrors.ErrorCode
	}{
		{name: "owner", mutate: func(t *testing.T, client ctrlclient.Client, sandbox *v1alpha1.Sandbox) {
			sandbox.Annotations[v1alpha1.AnnotationOwner] = "replacement-claim"
			require.NoError(t, client.Update(t.Context(), sandbox))
		}, wantCode: managererrors.ErrorNotAllowed},
		{name: "jwt disabled", mutate: func(t *testing.T, client ctrlclient.Client, sandbox *v1alpha1.Sandbox) {
			delete(sandbox.Annotations, identity.AnnotationEnableJwtAuth)
			require.NoError(t, client.Update(t.Context(), sandbox))
		}, wantCode: managererrors.ErrorConflict},
		{name: "lifecycle state", mutate: func(t *testing.T, client ctrlclient.Client, sandbox *v1alpha1.Sandbox) {
			sandbox.Status.Phase = v1alpha1.SandboxFailed
			require.NoError(t, client.Status().Update(t.Context(), sandbox))
		}, wantCode: managererrors.ErrorConflict},
		{name: "binding", mutate: func(t *testing.T, client ctrlclient.Client, sandbox *v1alpha1.Sandbox) {
			sandbox.Annotations[claimidentity.UIDAnnotation] = "replacement-uid"
			require.NoError(t, client.Update(t.Context(), sandbox))
		}},
		{name: "public id", mutate: func(t *testing.T, client ctrlclient.Client, sandbox *v1alpha1.Sandbox) {
			sandbox.Labels[v1alpha1.LabelSandboxID] = "replacement-id"
			require.NoError(t, client.Update(t.Context(), sandbox))
		}},
		{name: "object uid", mutate: func(t *testing.T, client ctrlclient.Client, sandbox *v1alpha1.Sandbox) {
			require.NoError(t, client.Delete(t.Context(), sandbox))
			replacement := sandbox.DeepCopy()
			replacement.ResourceVersion = ""
			replacement.UID = types.UID("replacement-uid")
			CreateSandboxWithStatus(t, client, replacement)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, client, sandbox, sandboxID := setupBoundTrafficTokenSandbox(t, "snapshot-"+tt.name)
			initialOwner := sandbox.Annotations[v1alpha1.AnnotationOwner]
			provider := &blockingTrafficTokenTestProvider{started: make(chan struct{}), unblock: make(chan struct{})}
			identity.RegisterProvider(provider)
			t.Cleanup(func() { identity.RegisterProvider(identity.NewDefaultIdentityProvider()) })
			resultC := make(chan error, 1)
			go func() {
				_, err := manager.RefreshTrafficAccessToken(t.Context(), RefreshTrafficAccessTokenOptions{
					Namespace: sandbox.Namespace, SandboxID: sandboxID,
					ServiceAccount: &ServiceAccountIdentity{Username: managerTestSAUsername, UID: managerTestSAUID},
				})
				resultC <- err
			}()
			<-provider.started

			tt.mutate(t, client, sandbox)
			require.Eventually(t, func() bool {
				observed, err := manager.infra.GetSandbox(t.Context(), infra.GetSandboxOptions{Namespace: sandbox.Namespace, SandboxID: sandboxID})
				if err != nil {
					return true
				}
				state, _ := observed.GetState()
				return observed.GetUID() != sandbox.UID || observed.GetSandboxID() != sandboxID ||
					observed.GetAnnotations()[claimidentity.UIDAnnotation] != managerTestSAUID ||
					observed.GetAnnotations()[v1alpha1.AnnotationOwner] != initialOwner ||
					observed.GetAnnotations()[identity.AnnotationEnableJwtAuth] != v1alpha1.True ||
					state != v1alpha1.SandboxStateRunning
			}, time.Second, 10*time.Millisecond)
			close(provider.unblock)

			err := <-resultC
			require.Error(t, err)
			if tt.wantCode != "" {
				assert.Equal(t, tt.wantCode, managererrors.GetErrCode(err))
			} else {
				assert.Contains(t, []managererrors.ErrorCode{managererrors.ErrorNotFound, managererrors.ErrorNotAllowed}, managererrors.GetErrCode(err))
			}
		})
	}
}

func TestSandboxManagerRefreshTrafficAccessTokenDoesNotShareAcrossServiceAccounts(t *testing.T) {
	manager, client, sandbox, sandboxID := setupBoundTrafficTokenSandbox(t, "principal-isolation")
	provider := &blockingTrafficTokenTestProvider{started: make(chan struct{}), unblock: make(chan struct{})}
	identity.RegisterProvider(provider)
	t.Cleanup(func() { identity.RegisterProvider(identity.NewDefaultIdentityProvider()) })
	type refreshResult struct {
		token infra.TrafficAccessToken
		err   error
	}
	firstResult := make(chan refreshResult, 1)
	go func() {
		token, err := manager.RefreshTrafficAccessToken(t.Context(), RefreshTrafficAccessTokenOptions{
			Namespace: sandbox.Namespace, SandboxID: sandboxID,
			ServiceAccount: &ServiceAccountIdentity{Username: managerTestSAUsername, UID: managerTestSAUID},
		})
		firstResult <- refreshResult{token: token, err: err}
	}()
	<-provider.started

	secondPrincipal := ServiceAccountIdentity{Username: "system:serviceaccount:test:replacement", UID: "replacement-uid"}
	sandbox.Annotations[claimidentity.UsernameAnnotation] = secondPrincipal.Username
	sandbox.Annotations[claimidentity.UIDAnnotation] = secondPrincipal.UID
	require.NoError(t, client.Update(t.Context(), sandbox))
	require.Eventually(t, func() bool {
		observed, err := manager.infra.GetSandbox(t.Context(), infra.GetSandboxOptions{Namespace: sandbox.Namespace, SandboxID: sandboxID})
		return err == nil && observed.GetAnnotations()[claimidentity.UIDAnnotation] == secondPrincipal.UID
	}, time.Second, 10*time.Millisecond)

	secondToken, secondErr := manager.RefreshTrafficAccessToken(t.Context(), RefreshTrafficAccessTokenOptions{
		Namespace: sandbox.Namespace, SandboxID: sandboxID, ServiceAccount: &secondPrincipal,
	})
	require.NoError(t, secondErr)
	assert.Equal(t, "coalesced-token", secondToken.Token)
	close(provider.unblock)
	first := <-firstResult
	require.Error(t, first.err)
	assert.Equal(t, managererrors.ErrorNotAllowed, managererrors.GetErrCode(first.err))
	assert.Empty(t, first.token)
	assert.Equal(t, int32(2), provider.calls.Load())
}

func setupBoundTrafficTokenSandbox(t *testing.T, name string) (*SandboxManager, ctrlclient.Client, *v1alpha1.Sandbox, string) {
	t.Helper()
	manager, client := setupTestManager(t, config.SandboxManagerOptions{})
	manager.trafficTokenOptions = identity.TokenOptions{RequestedValidity: time.Hour}
	manager.trafficTokenSingleflight = newTrafficTokenSingleflight()
	sandbox := getSandboxForApiTest(name)
	sandbox.UID = types.UID("uid-" + name)
	sandbox.Annotations[identity.AnnotationEnableJwtAuth] = v1alpha1.True
	sandbox.Annotations[claimidentity.UsernameAnnotation] = managerTestSAUsername
	sandbox.Annotations[claimidentity.UIDAnnotation] = managerTestSAUID
	sandbox.Status.Conditions = []metav1.Condition{{Type: string(v1alpha1.SandboxConditionReady), Status: metav1.ConditionTrue}}
	CreateSandboxWithStatus(t, client, sandbox)
	sandboxID := sandboxid.Resolve(sandbox)
	require.Eventually(t, func() bool {
		_, err := manager.infra.GetSandbox(t.Context(), infra.GetSandboxOptions{Namespace: sandbox.Namespace, SandboxID: sandboxID})
		return err == nil
	}, time.Second, 10*time.Millisecond)
	return manager, client, sandbox, sandboxID
}
