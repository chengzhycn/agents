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
	"net/http"
	"reflect"

	admissionv1 "k8s.io/api/admission/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/claimidentity"
)

type SandboxClaimBindingMutator struct {
	Decoder admission.Decoder
}

// +kubebuilder:webhook:path=/default-sandboxclaim-identity,mutating=true,failurePolicy=fail,sideEffects=None,admissionReviewVersions=v1;v1beta1,groups=agents.kruise.io,resources=sandboxclaims,verbs=create,versions=v1alpha1,name=md-sc-identity.kb.io

func (h *SandboxClaimBindingMutator) Path() string {
	return "/default-sandboxclaim-identity"
}

func (h *SandboxClaimBindingMutator) Enabled() bool {
	return true
}

func (h *SandboxClaimBindingMutator) Handle(_ context.Context, req admission.Request) admission.Response {
	claim := &agentsv1alpha1.SandboxClaim{}
	if err := h.Decoder.Decode(req, claim); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	if req.Operation != admissionv1.Create {
		return admission.Allowed("")
	}

	original := claim.DeepCopy()
	if claimidentity.IsServiceAccountUsername(req.UserInfo.Username) && req.UserInfo.UID != "" {
		if claim.Annotations == nil {
			claim.Annotations = make(map[string]string)
		}
		claim.Annotations[claimidentity.UsernameAnnotation] = req.UserInfo.Username
		claim.Annotations[claimidentity.UIDAnnotation] = req.UserInfo.UID
	} else {
		delete(claim.Annotations, claimidentity.UsernameAnnotation)
		delete(claim.Annotations, claimidentity.UIDAnnotation)
	}
	if reflect.DeepEqual(claim, original) {
		return admission.Allowed("")
	}

	mutated, err := json.Marshal(claim)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, mutated)
}
