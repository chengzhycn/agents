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
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/claimidentity"
)

type SandboxClaimBindingValidator struct {
	Decoder admission.Decoder
}

// +kubebuilder:webhook:path=/validate-sandboxclaim-identity,mutating=false,failurePolicy=fail,sideEffects=None,admissionReviewVersions=v1;v1beta1,groups=agents.kruise.io,resources=sandboxclaims,verbs=create;update,versions=v1alpha1,name=v-sc-identity.kb.io

func (h *SandboxClaimBindingValidator) Path() string {
	return "/validate-sandboxclaim-identity"
}

func (h *SandboxClaimBindingValidator) Enabled() bool {
	return true
}

func (h *SandboxClaimBindingValidator) Handle(_ context.Context, req admission.Request) admission.Response {
	claim := &agentsv1alpha1.SandboxClaim{}
	if err := h.Decoder.Decode(req, claim); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	errors := validateSpecAnnotations(claim)
	switch req.Operation {
	case admissionv1.Create:
		errors = append(errors, validateCreatedBinding(claim, req)...)
	case admissionv1.Update:
		oldClaim := &agentsv1alpha1.SandboxClaim{}
		if err := h.Decoder.DecodeRaw(req.OldObject, oldClaim); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}
		errors = append(errors, validateImmutableBinding(oldClaim, claim)...)
	}
	if len(errors) > 0 {
		return admission.Errored(http.StatusUnprocessableEntity, errors.ToAggregate())
	}
	return admission.Allowed("")
}

func validateSpecAnnotations(claim *agentsv1alpha1.SandboxClaim) field.ErrorList {
	annotationsPath := field.NewPath("spec", "annotations")
	var errors field.ErrorList
	for _, key := range []string{claimidentity.UsernameAnnotation, claimidentity.UIDAnnotation} {
		if _, exists := claim.Spec.Annotations[key]; exists {
			errors = append(errors, field.Forbidden(annotationsPath.Key(key), "reserved identity annotation must not be supplied"))
		}
	}
	return errors
}

func validateCreatedBinding(claim *agentsv1alpha1.SandboxClaim, req admission.Request) field.ErrorList {
	wantUsername, wantUID := "", ""
	if claimidentity.IsServiceAccountUsername(req.UserInfo.Username) && req.UserInfo.UID != "" {
		wantUsername, wantUID = req.UserInfo.Username, req.UserInfo.UID
	}
	annotationsPath := field.NewPath("metadata", "annotations")
	var errors field.ErrorList
	if got := claim.Annotations[claimidentity.UsernameAnnotation]; got != wantUsername {
		errors = append(errors, field.Invalid(annotationsPath.Key(claimidentity.UsernameAnnotation), got, "must match the admitted ServiceAccount username"))
	}
	if got := claim.Annotations[claimidentity.UIDAnnotation]; got != wantUID {
		errors = append(errors, field.Invalid(annotationsPath.Key(claimidentity.UIDAnnotation), got, "must match the admitted ServiceAccount UID"))
	}
	return errors
}

func validateImmutableBinding(oldClaim, claim *agentsv1alpha1.SandboxClaim) field.ErrorList {
	annotationsPath := field.NewPath("metadata", "annotations")
	var errors field.ErrorList
	for _, key := range []string{claimidentity.UsernameAnnotation, claimidentity.UIDAnnotation} {
		if oldClaim.Annotations[key] != claim.Annotations[key] {
			errors = append(errors, field.Forbidden(annotationsPath.Key(key), "identity annotation is immutable"))
		}
	}
	return errors
}
