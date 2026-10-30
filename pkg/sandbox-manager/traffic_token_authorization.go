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
	"context"
	"errors"
	"net/url"

	"github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/claimidentity"
	managererrors "github.com/openkruise/agents/pkg/sandbox-manager/errors"
	"github.com/openkruise/agents/pkg/sandbox-manager/infra"
)

type ServiceAccountIdentity struct {
	Username string
	UID      string
}

type trafficTokenAuthorizationSnapshot struct {
	namespace              string
	sandboxID              string
	sandboxUID             string
	owner                  string
	user                   string
	serviceAccountUsername string
	serviceAccountUID      string
}

func (m *SandboxManager) authorizeTrafficTokenRefresh(ctx context.Context, opts RefreshTrafficAccessTokenOptions) (trafficTokenAuthorizationSnapshot, error) {
	if opts.SandboxID == "" {
		return trafficTokenAuthorizationSnapshot{}, managererrors.NewError(managererrors.ErrorBadRequest, "sandbox ID is required")
	}
	if opts.ServiceAccount != nil {
		if opts.User != "" || opts.Namespace == "" || opts.ServiceAccount.Username == "" || opts.ServiceAccount.UID == "" {
			return trafficTokenAuthorizationSnapshot{}, managererrors.NewError(managererrors.ErrorBadRequest, "service account identity and namespace are required")
		}
		sandbox, err := m.infra.GetSandbox(ctx, infra.GetSandboxOptions{Namespace: opts.Namespace, SandboxID: opts.SandboxID})
		if err != nil {
			return trafficTokenAuthorizationSnapshot{}, trafficTokenLookupError(opts.SandboxID, err)
		}
		snapshot := trafficTokenAuthorizationSnapshot{
			namespace: opts.Namespace, sandboxID: opts.SandboxID, sandboxUID: string(sandbox.GetUID()),
			owner:                  sandbox.GetAnnotations()[v1alpha1.AnnotationOwner],
			serviceAccountUsername: opts.ServiceAccount.Username, serviceAccountUID: opts.ServiceAccount.UID,
		}
		if err := validateTrafficTokenSnapshot(sandbox, snapshot); err != nil {
			return trafficTokenAuthorizationSnapshot{}, err
		}
		return snapshot, nil
	}

	if opts.User == "" {
		return trafficTokenAuthorizationSnapshot{}, managererrors.NewError(managererrors.ErrorBadRequest, "user is required")
	}
	sandbox, err := m.GetSandbox(ctx, opts.User, nil, infra.GetSandboxOptions{Namespace: opts.Namespace, SandboxID: opts.SandboxID})
	if err != nil {
		return trafficTokenAuthorizationSnapshot{}, err
	}
	snapshot := trafficTokenAuthorizationSnapshot{
		namespace: sandbox.GetNamespace(), sandboxID: opts.SandboxID, sandboxUID: string(sandbox.GetUID()),
		owner: sandbox.GetAnnotations()[v1alpha1.AnnotationOwner], user: opts.User,
	}
	if err := validateTrafficTokenSnapshot(sandbox, snapshot); err != nil {
		return trafficTokenAuthorizationSnapshot{}, err
	}
	return snapshot, nil
}

func validateTrafficTokenSnapshot(sandbox infra.Sandbox, snapshot trafficTokenAuthorizationSnapshot) error {
	if sandbox.GetNamespace() != snapshot.namespace || sandbox.GetSandboxID() != snapshot.sandboxID || string(sandbox.GetUID()) != snapshot.sandboxUID {
		return managererrors.NewError(managererrors.ErrorNotAllowed, "sandbox identity changed")
	}
	annotations := sandbox.GetAnnotations()
	if snapshot.owner == "" || annotations[v1alpha1.AnnotationOwner] != snapshot.owner {
		return managererrors.NewError(managererrors.ErrorNotAllowed, "sandbox %s has no matching owner", snapshot.sandboxID)
	}
	if snapshot.serviceAccountUsername != "" {
		if snapshot.sandboxUID == "" || annotations[claimidentity.UsernameAnnotation] != snapshot.serviceAccountUsername || annotations[claimidentity.UIDAnnotation] != snapshot.serviceAccountUID {
			return managererrors.NewError(managererrors.ErrorNotAllowed, "sandbox %s has no matching service account binding", snapshot.sandboxID)
		}
	} else if snapshot.user == "" || snapshot.owner != snapshot.user {
		return managererrors.NewError(managererrors.ErrorNotAllowed, "sandbox %s is not owned", snapshot.sandboxID)
	}

	route, err := sandbox.GetRoute()
	if err != nil {
		return managererrors.NewError(managererrors.ErrorUnavailable, "failed to resolve sandbox route: %v", err)
	}
	if route.Owner != snapshot.owner {
		return managererrors.NewError(managererrors.ErrorNotAllowed, "sandbox %s has no matching owner", snapshot.sandboxID)
	}
	state, reason := sandbox.GetState()
	if state != v1alpha1.SandboxStateRunning && state != v1alpha1.SandboxStatePaused {
		return managererrors.NewError(managererrors.ErrorConflict, "sandbox %s cannot refresh traffic access token in state %s (%s)", snapshot.sandboxID, state, reason)
	}
	if !route.RequireTrafficAuth {
		return managererrors.NewError(managererrors.ErrorConflict, "sandbox %s does not enable traffic JWT authentication", snapshot.sandboxID)
	}
	return nil
}

func (m *SandboxManager) revalidateTrafficTokenSnapshot(ctx context.Context, snapshot trafficTokenAuthorizationSnapshot) error {
	sandbox, err := m.infra.GetSandbox(ctx, infra.GetSandboxOptions{Namespace: snapshot.namespace, SandboxID: snapshot.sandboxID})
	if err != nil {
		return trafficTokenLookupError(snapshot.sandboxID, err)
	}
	return validateTrafficTokenSnapshot(sandbox, snapshot)
}

func trafficTokenLookupError(sandboxID string, err error) error {
	if errors.Is(err, infra.ErrSandboxNotFound) || errors.Is(err, infra.ErrSandboxIDAmbiguous) {
		return managererrors.WrapError(managererrors.ErrorNotFound, err, "sandbox %s not found", sandboxID)
	}
	return managererrors.WrapError(managererrors.ErrorInternal, err, "failed to get sandbox %s", sandboxID)
}

func (s trafficTokenAuthorizationSnapshot) flightKey() string {
	return url.Values{
		"namespace": {s.namespace}, "sandboxID": {s.sandboxID}, "sandboxUID": {s.sandboxUID},
		"owner": {s.owner}, "user": {s.user}, "serviceAccountUsername": {s.serviceAccountUsername},
		"serviceAccountUID": {s.serviceAccountUID},
	}.Encode()
}
