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

package validating

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/claimidentity"
)

func TestSandboxClaimBindingValidatorHandleCreate(t *testing.T) {
	trustedUser := authenticationv1.UserInfo{Username: "system:serviceaccount:tenant-a:runtime", UID: "uid-a"}
	tests := []struct {
		name     string
		claim    *agentsv1alpha1.SandboxClaim
		userInfo authenticationv1.UserInfo
		allowed  bool
	}{
		{
			name: "matching trusted binding",
			claim: claimWithAnnotations(map[string]string{
				claimidentity.UsernameAnnotation: trustedUser.Username,
				claimidentity.UIDAnnotation:      trustedUser.UID,
			}),
			userInfo: trustedUser,
			allowed:  true,
		},
		{name: "missing service account binding", claim: claimWithAnnotations(nil), userInfo: trustedUser, allowed: false},
		{
			name: "mismatched service account binding",
			claim: claimWithAnnotations(map[string]string{
				claimidentity.UsernameAnnotation: trustedUser.Username,
				claimidentity.UIDAnnotation:      "wrong",
			}),
			userInfo: trustedUser,
			allowed:  false,
		},
		{name: "ordinary user remains unbound", claim: claimWithAnnotations(nil), userInfo: authenticationv1.UserInfo{Username: "alice", UID: "user-uid"}, allowed: true},
		{
			name: "ordinary user cannot supply binding",
			claim: claimWithAnnotations(map[string]string{
				claimidentity.UsernameAnnotation: trustedUser.Username,
				claimidentity.UIDAnnotation:      trustedUser.UID,
			}),
			userInfo: authenticationv1.UserInfo{Username: "alice", UID: "user-uid"},
			allowed:  false,
		},
		{
			name:     "spec annotations cannot contain username",
			claim:    claimWithSpecAnnotations(map[string]string{claimidentity.UsernameAnnotation: trustedUser.Username}),
			userInfo: authenticationv1.UserInfo{Username: "alice", UID: "user-uid"},
			allowed:  false,
		},
		{
			name:     "spec annotations cannot contain uid",
			claim:    claimWithSpecAnnotations(map[string]string{claimidentity.UIDAnnotation: trustedUser.UID}),
			userInfo: authenticationv1.UserInfo{Username: "alice", UID: "user-uid"},
			allowed:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := newClaimValidator().Handle(context.Background(), claimRequest(t, claimRequestInput{
				operation: admissionv1.Create,
				claim:     tt.claim,
				userInfo:  tt.userInfo,
			}))
			require.Equal(t, tt.allowed, response.Allowed)
		})
	}
}

func TestSandboxClaimBindingValidatorHandleUpdate(t *testing.T) {
	bound := claimWithAnnotations(map[string]string{
		claimidentity.UsernameAnnotation: "system:serviceaccount:tenant-a:runtime",
		claimidentity.UIDAnnotation:      "uid-a",
	})
	tests := []struct {
		name    string
		old     *agentsv1alpha1.SandboxClaim
		updated *agentsv1alpha1.SandboxClaim
		allowed bool
	}{
		{name: "unchanged binding", old: bound, updated: bound.DeepCopy(), allowed: true},
		{name: "legacy unbound claim", old: claimWithAnnotations(nil), updated: claimWithAnnotations(nil), allowed: true},
		{name: "username changed", old: bound, updated: claimWithAnnotations(map[string]string{claimidentity.UsernameAnnotation: "system:serviceaccount:tenant-b:runtime", claimidentity.UIDAnnotation: "uid-a"}), allowed: false},
		{name: "uid removed", old: bound, updated: claimWithAnnotations(map[string]string{claimidentity.UsernameAnnotation: "system:serviceaccount:tenant-a:runtime"}), allowed: false},
		{name: "binding added", old: claimWithAnnotations(nil), updated: bound.DeepCopy(), allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := newClaimValidator().Handle(context.Background(), claimRequest(t, claimRequestInput{
				operation: admissionv1.Update,
				oldClaim:  tt.old,
				claim:     tt.updated,
				userInfo:  authenticationv1.UserInfo{Username: "admin"},
			}))
			require.Equal(t, tt.allowed, response.Allowed)
		})
	}
}

func newClaimValidator() *SandboxClaimBindingValidator {
	scheme := runtime.NewScheme()
	if err := agentsv1alpha1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	return &SandboxClaimBindingValidator{Decoder: admission.NewDecoder(scheme)}
}

func claimWithAnnotations(annotations map[string]string) *agentsv1alpha1.SandboxClaim {
	return &agentsv1alpha1.SandboxClaim{ObjectMeta: metav1.ObjectMeta{Annotations: annotations}}
}

func claimWithSpecAnnotations(annotations map[string]string) *agentsv1alpha1.SandboxClaim {
	return &agentsv1alpha1.SandboxClaim{Spec: agentsv1alpha1.SandboxClaimSpec{Annotations: annotations}}
}

type claimRequestInput struct {
	operation admissionv1.Operation
	oldClaim  *agentsv1alpha1.SandboxClaim
	claim     *agentsv1alpha1.SandboxClaim
	userInfo  authenticationv1.UserInfo
}

func claimRequest(t *testing.T, input claimRequestInput) admission.Request {
	t.Helper()
	raw, err := json.Marshal(input.claim)
	require.NoError(t, err)
	oldRaw, err := json.Marshal(input.oldClaim)
	require.NoError(t, err)
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: input.operation,
		Object:    runtime.RawExtension{Raw: raw},
		OldObject: runtime.RawExtension{Raw: oldRaw},
		UserInfo:  input.userInfo,
	}}
}
