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
	"github.com/openkruise/agents/pkg/utils"
)

type SandboxBindingValidator struct {
	Decoder admission.Decoder
}

// +kubebuilder:webhook:path=/validate-sandbox-claim-identity,mutating=false,failurePolicy=fail,sideEffects=None,admissionReviewVersions=v1;v1beta1,groups=agents.kruise.io,resources=sandboxes,verbs=create;update,versions=v1alpha1,name=v-sb-identity.kb.io

func (h *SandboxBindingValidator) Path() string {
	return "/validate-sandbox-claim-identity"
}

func (h *SandboxBindingValidator) Enabled() bool {
	return true
}

func (h *SandboxBindingValidator) Handle(_ context.Context, req admission.Request) admission.Response {
	sandbox := &agentsv1alpha1.Sandbox{}
	if err := h.Decoder.Decode(req, sandbox); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	errors := validateBinding(sandbox)
	oldSandbox := &agentsv1alpha1.Sandbox{}
	if req.Operation == admissionv1.Update {
		if err := h.Decoder.DecodeRaw(req.OldObject, oldSandbox); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}
	}
	if bindingChanged(oldSandbox, sandbox) && req.UserInfo.Username != utils.GetSandboxControllerUsername() {
		errors = append(errors, field.Forbidden(field.NewPath("metadata", "annotations"), "only the sandbox controller may establish or change a claim identity binding"))
	}
	if len(errors) > 0 {
		return admission.Errored(http.StatusUnprocessableEntity, errors.ToAggregate())
	}
	return admission.Allowed("")
}

func validateBinding(sandbox *agentsv1alpha1.Sandbox) field.ErrorList {
	owner := sandbox.Annotations[agentsv1alpha1.AnnotationOwner]
	username := sandbox.Annotations[claimidentity.UsernameAnnotation]
	uid := sandbox.Annotations[claimidentity.UIDAnnotation]
	if username == "" && uid == "" {
		return nil
	}

	annotationsPath := field.NewPath("metadata", "annotations")
	var errors field.ErrorList
	if owner == "" {
		errors = append(errors, field.Required(annotationsPath.Key(agentsv1alpha1.AnnotationOwner), "owner is required for a claim identity binding"))
	}
	if !claimidentity.IsServiceAccountUsername(username) {
		errors = append(errors, field.Invalid(annotationsPath.Key(claimidentity.UsernameAnnotation), username, "must be a canonical ServiceAccount username"))
	}
	if uid == "" {
		errors = append(errors, field.Required(annotationsPath.Key(claimidentity.UIDAnnotation), "ServiceAccount UID is required for a claim identity binding"))
	}
	return errors
}

func bindingChanged(oldSandbox, sandbox *agentsv1alpha1.Sandbox) bool {
	oldUsername := oldSandbox.Annotations[claimidentity.UsernameAnnotation]
	oldUID := oldSandbox.Annotations[claimidentity.UIDAnnotation]
	username := sandbox.Annotations[claimidentity.UsernameAnnotation]
	uid := sandbox.Annotations[claimidentity.UIDAnnotation]
	if oldUsername != username || oldUID != uid {
		return true
	}
	if username == "" && uid == "" {
		return false
	}
	return oldSandbox.Annotations[agentsv1alpha1.AnnotationOwner] != sandbox.Annotations[agentsv1alpha1.AnnotationOwner]
}
