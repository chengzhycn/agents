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

package mutating

import (
	"context"
	"encoding/json"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/claimidentity"
)

func TestSandboxClaimBindingMutatorHandle(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		userInfo    authenticationv1.UserInfo
		want        map[string]string
		wantPatch   bool
	}{
		{
			name: "service account identity overwrites supplied metadata",
			annotations: map[string]string{
				claimidentity.UsernameAnnotation: "system:serviceaccount:wrong:wrong",
				claimidentity.UIDAnnotation:      "wrong-uid",
			},
			userInfo: authenticationv1.UserInfo{Username: "system:serviceaccount:tenant-a:runtime", UID: "uid-a"},
			want: map[string]string{
				claimidentity.UsernameAnnotation: "system:serviceaccount:tenant-a:runtime",
				claimidentity.UIDAnnotation:      "uid-a",
			},
			wantPatch: true,
		},
		{
			name: "non service account removes supplied metadata",
			annotations: map[string]string{
				"example.com/keep":               "yes",
				claimidentity.UsernameAnnotation: "system:serviceaccount:wrong:wrong",
				claimidentity.UIDAnnotation:      "wrong-uid",
			},
			userInfo:  authenticationv1.UserInfo{Username: "alice", UID: "user-uid"},
			want:      map[string]string{"example.com/keep": "yes"},
			wantPatch: true,
		},
		{
			name: "service account without uid removes supplied metadata",
			annotations: map[string]string{
				claimidentity.UsernameAnnotation: "system:serviceaccount:wrong:wrong",
				claimidentity.UIDAnnotation:      "wrong-uid",
			},
			userInfo:  authenticationv1.UserInfo{Username: "system:serviceaccount:tenant-a:runtime"},
			want:      nil,
			wantPatch: true,
		},
		{
			name: "matching trusted identity is idempotent",
			annotations: map[string]string{
				claimidentity.UsernameAnnotation: "system:serviceaccount:tenant-a:runtime",
				claimidentity.UIDAnnotation:      "uid-a",
			},
			userInfo: authenticationv1.UserInfo{Username: "system:serviceaccount:tenant-a:runtime", UID: "uid-a"},
			want: map[string]string{
				claimidentity.UsernameAnnotation: "system:serviceaccount:tenant-a:runtime",
				claimidentity.UIDAnnotation:      "uid-a",
			},
			wantPatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claim := &agentsv1alpha1.SandboxClaim{}
			claim.Annotations = tt.annotations
			raw, err := json.Marshal(claim)
			require.NoError(t, err)
			req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Object:    runtime.RawExtension{Raw: raw},
				UserInfo:  tt.userInfo,
			}}
			scheme := runtime.NewScheme()
			require.NoError(t, agentsv1alpha1.AddToScheme(scheme))
			handler := &SandboxClaimBindingMutator{Decoder: admission.NewDecoder(scheme)}

			response := handler.Handle(context.Background(), req)

			require.True(t, response.Allowed)
			require.Equal(t, tt.wantPatch, len(response.Patches) > 0)
			mutatedRaw := raw
			if tt.wantPatch {
				require.NoError(t, response.Complete(req))
				patch, patchErr := jsonpatch.DecodePatch(response.Patch)
				require.NoError(t, patchErr)
				mutatedRaw, err = patch.Apply(raw)
				require.NoError(t, err)
			}
			mutated := &agentsv1alpha1.SandboxClaim{}
			require.NoError(t, json.Unmarshal(mutatedRaw, mutated))
			require.Equal(t, tt.want, mutated.Annotations)
		})
	}
}
