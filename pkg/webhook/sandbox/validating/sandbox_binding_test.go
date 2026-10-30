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
	"maps"
	"testing"

	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/claimidentity"
	"github.com/openkruise/agents/pkg/utils"
)

func TestSandboxBindingValidatorHandleCreate(t *testing.T) {
	controller := utils.GetSandboxControllerUsername()
	tests := []struct {
		name        string
		annotations map[string]string
		username    string
		allowed     bool
	}{
		{name: "controller establishes complete binding", annotations: completeBinding("claim-uid"), username: controller, allowed: true},
		{name: "non controller cannot establish binding", annotations: completeBinding("claim-uid"), username: "admin", allowed: false},
		{name: "controller cannot establish partial binding", annotations: map[string]string{agentsv1alpha1.AnnotationOwner: "claim-uid", claimidentity.UsernameAnnotation: "system:serviceaccount:tenant-a:runtime"}, username: controller, allowed: false},
		{name: "controller binding requires owner", annotations: map[string]string{claimidentity.UsernameAnnotation: "system:serviceaccount:tenant-a:runtime", claimidentity.UIDAnnotation: "uid-a"}, username: controller, allowed: false},
		{name: "controller binding requires canonical username", annotations: map[string]string{agentsv1alpha1.AnnotationOwner: "claim-uid", claimidentity.UsernameAnnotation: "invalid", claimidentity.UIDAnnotation: "uid-a"}, username: controller, allowed: false},
		{name: "legacy unbound sandbox", annotations: map[string]string{agentsv1alpha1.AnnotationOwner: "api-user"}, username: "admin", allowed: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := newSandboxValidator().Handle(context.Background(), sandboxRequest(t, sandboxRequestInput{
				operation: admissionv1.Create,
				sandbox:   sandboxWithAnnotations(tt.annotations),
				username:  tt.username,
			}))
			require.Equal(t, tt.allowed, response.Allowed)
		})
	}
}

func TestSandboxBindingValidatorHandleUpdate(t *testing.T) {
	controller := utils.GetSandboxControllerUsername()
	bound := sandboxWithAnnotations(completeBinding("claim-uid"))
	tests := []struct {
		name     string
		old      *agentsv1alpha1.Sandbox
		updated  *agentsv1alpha1.Sandbox
		username string
		allowed  bool
	}{
		{name: "non controller updates unrelated metadata", old: bound, updated: sandboxWithAnnotations(withAnnotation(completeBinding("claim-uid"), "example.com/key", "value")), username: "admin", allowed: true},
		{name: "non controller cannot change bound owner", old: bound, updated: sandboxWithAnnotations(completeBinding("other-claim")), username: "admin", allowed: false},
		{name: "controller changes complete binding", old: bound, updated: sandboxWithAnnotations(map[string]string{agentsv1alpha1.AnnotationOwner: "other-claim", claimidentity.UsernameAnnotation: "system:serviceaccount:tenant-b:runtime", claimidentity.UIDAnnotation: "uid-b"}), username: controller, allowed: true},
		{name: "controller removes binding for recycle", old: bound, updated: sandboxWithAnnotations(nil), username: controller, allowed: true},
		{name: "controller cannot leave partial binding", old: bound, updated: sandboxWithAnnotations(map[string]string{agentsv1alpha1.AnnotationOwner: "claim-uid", claimidentity.UsernameAnnotation: "system:serviceaccount:tenant-a:runtime"}), username: controller, allowed: false},
		{name: "unbound owner remains mutable", old: sandboxWithAnnotations(map[string]string{agentsv1alpha1.AnnotationOwner: "api-user-a"}), updated: sandboxWithAnnotations(map[string]string{agentsv1alpha1.AnnotationOwner: "api-user-b"}), username: "admin", allowed: true},
		{name: "non controller cannot add binding", old: sandboxWithAnnotations(map[string]string{agentsv1alpha1.AnnotationOwner: "api-user"}), updated: bound, username: "admin", allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := newSandboxValidator().Handle(context.Background(), sandboxRequest(t, sandboxRequestInput{
				operation:  admissionv1.Update,
				oldSandbox: tt.old,
				sandbox:    tt.updated,
				username:   tt.username,
			}))
			require.Equal(t, tt.allowed, response.Allowed)
		})
	}
}

func newSandboxValidator() *SandboxBindingValidator {
	scheme := runtime.NewScheme()
	if err := agentsv1alpha1.AddToScheme(scheme); err != nil {
		panic(err)
	}
	return &SandboxBindingValidator{Decoder: admission.NewDecoder(scheme)}
}

func completeBinding(owner string) map[string]string {
	return map[string]string{
		agentsv1alpha1.AnnotationOwner:   owner,
		claimidentity.UsernameAnnotation: "system:serviceaccount:tenant-a:runtime",
		claimidentity.UIDAnnotation:      "uid-a",
	}
}

func withAnnotation(annotations map[string]string, key, value string) map[string]string {
	result := maps.Clone(annotations)
	result[key] = value
	return result
}

func sandboxWithAnnotations(annotations map[string]string) *agentsv1alpha1.Sandbox {
	return &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{Annotations: annotations}}
}

type sandboxRequestInput struct {
	operation  admissionv1.Operation
	oldSandbox *agentsv1alpha1.Sandbox
	sandbox    *agentsv1alpha1.Sandbox
	username   string
}

func sandboxRequest(t *testing.T, input sandboxRequestInput) admission.Request {
	t.Helper()
	raw, err := json.Marshal(input.sandbox)
	require.NoError(t, err)
	oldRaw, err := json.Marshal(input.oldSandbox)
	require.NoError(t, err)
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: input.operation,
		Object:    runtime.RawExtension{Raw: raw},
		OldObject: runtime.RawExtension{Raw: oldRaw},
		UserInfo:  authenticationv1.UserInfo{Username: input.username},
	}}
}
