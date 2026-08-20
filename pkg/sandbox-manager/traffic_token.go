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
	"sync"

	"github.com/openkruise/agents/api/v1alpha1"
	managererrors "github.com/openkruise/agents/pkg/sandbox-manager/errors"
	"github.com/openkruise/agents/pkg/sandbox-manager/infra"
	"k8s.io/klog/v2"
)

// RefreshTrafficAccessTokenOptions identifies the caller and Sandbox for an
// explicit traffic-token refresh.
type RefreshTrafficAccessTokenOptions struct {
	Namespace string
	SandboxID string
	User      string
}

// RefreshTrafficAccessToken issues a new token without mutating the Sandbox.
func (m *SandboxManager) RefreshTrafficAccessToken(ctx context.Context, opts RefreshTrafficAccessTokenOptions) (infra.TrafficAccessToken, error) {
	return m.issueTrafficAccessToken(ctx, opts)
}

func (m *SandboxManager) issueTrafficAccessToken(ctx context.Context, opts RefreshTrafficAccessTokenOptions) (infra.TrafficAccessToken, error) {
	if opts.User == "" {
		return infra.TrafficAccessToken{}, managererrors.NewError(managererrors.ErrorBadRequest, "user is required")
	}
	if opts.SandboxID == "" {
		return infra.TrafficAccessToken{}, managererrors.NewError(managererrors.ErrorBadRequest, "sandbox ID is required")
	}

	sandbox, err := m.GetSandbox(ctx, opts.User, nil, infra.GetSandboxOptions{
		Namespace: opts.Namespace,
		SandboxID: opts.SandboxID,
	})
	if err != nil {
		return infra.TrafficAccessToken{}, err
	}
	if err := validateTrafficTokenSandbox(sandbox, opts.User); err != nil {
		return infra.TrafficAccessToken{}, err
	}
	if m.trafficTokenSingleflight == nil {
		return infra.TrafficAccessToken{}, managererrors.NewError(managererrors.ErrorInternal, "traffic access token singleflight is not configured")
	}

	flightKey := string(sandbox.GetUID())
	if flightKey != "" {
		// A reusable Sandbox CR can serve multiple deliveries. Include the
		// delivery ID so a recycled CR cannot join the previous delivery's flight.
		flightKey += "\x00" + opts.SandboxID
	} else {
		flightKey = opts.SandboxID
	}
	flight, leader := m.trafficTokenSingleflight.acquire(flightKey)
	if !leader {
		// Only the leader owns flight completion. A follower may stop waiting or
		// consume the published result, but must not clear or close the shared
		// flight; the leader does that after issuance returns.
		select {
		case <-ctx.Done():
			klog.FromContext(ctx).Error(ctx.Err(), "failed waiting for traffic access token issuance", "sandboxID", opts.SandboxID)
			return infra.TrafficAccessToken{}, managererrors.NewError(managererrors.ErrorUnavailable, "waiting for traffic access token issuance: %v", ctx.Err())
		case <-flight.done:
			if flight.err != nil {
				return infra.TrafficAccessToken{}, flight.err
			}
			return flight.result, nil
		}
	}

	result, issueErr := m.infra.IssueTrafficAccessToken(ctx, infra.IssueTrafficAccessTokenOptions{
		Namespace:    opts.Namespace,
		SandboxID:    opts.SandboxID,
		TokenOptions: m.trafficTokenOptions,
		Validate: func(sandbox infra.Sandbox) error {
			return validateTrafficTokenSandbox(sandbox, opts.User)
		},
	})
	if issueErr != nil && managererrors.GetErrCode(issueErr) == managererrors.ErrorUnknown {
		if errors.Is(issueErr, infra.ErrSandboxNotFound) {
			issueErr = managererrors.NewError(managererrors.ErrorNotFound, "sandbox %s not found", opts.SandboxID)
		} else {
			issueErr = managererrors.NewError(managererrors.ErrorUnavailable, "failed to issue traffic access token: %v", issueErr)
		}
	}
	m.trafficTokenSingleflight.complete(flightKey, flight, result, issueErr)
	if issueErr != nil {
		return infra.TrafficAccessToken{}, issueErr
	}
	return result, nil
}

func validateTrafficTokenSandbox(sandbox infra.Sandbox, user string) error {
	route, err := sandbox.GetRoute()
	if err != nil {
		return managererrors.NewError(managererrors.ErrorUnavailable, "failed to resolve sandbox route: %v", err)
	}
	if route.Owner != user {
		return managererrors.NewError(managererrors.ErrorNotAllowed, "sandbox %s is not owned", sandbox.GetSandboxID())
	}
	state, reason := sandbox.GetState()
	if state != v1alpha1.SandboxStateRunning && state != v1alpha1.SandboxStatePaused {
		return managererrors.NewError(managererrors.ErrorConflict, "sandbox %s cannot refresh traffic access token in state %s (%s)", sandbox.GetSandboxID(), state, reason)
	}
	if !route.RequireTrafficAuth {
		return managererrors.NewError(managererrors.ErrorConflict, "sandbox %s does not enable traffic JWT authentication", sandbox.GetSandboxID())
	}
	return nil
}

type trafficTokenFlight struct {
	done   chan struct{}
	result infra.TrafficAccessToken
	err    error
}

type trafficTokenSingleflight struct {
	mu      sync.Mutex
	flights map[string]*trafficTokenFlight
}

func newTrafficTokenSingleflight() *trafficTokenSingleflight {
	return &trafficTokenSingleflight{flights: make(map[string]*trafficTokenFlight)}
}

func (s *trafficTokenSingleflight) acquire(key string) (flight *trafficTokenFlight, leader bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if flight := s.flights[key]; flight != nil {
		return flight, false
	}
	flight = &trafficTokenFlight{done: make(chan struct{})}
	s.flights[key] = flight
	return flight, true
}

func (s *trafficTokenSingleflight) complete(key string, flight *trafficTokenFlight, result infra.TrafficAccessToken, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	flight.result = result
	flight.err = err
	if s.flights[key] == flight {
		delete(s.flights, key)
	}
	close(flight.done)
}
