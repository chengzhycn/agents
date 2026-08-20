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
	"time"

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
	if m.trafficTokenLimiter == nil {
		return infra.TrafficAccessToken{}, managererrors.NewError(managererrors.ErrorInternal, "traffic access token limiter is not configured")
	}

	limiterKey := string(sandbox.GetUID())
	if limiterKey != "" {
		// A reusable Sandbox CR can serve multiple deliveries. Include the
		// delivery ID so a recycled CR cannot receive its previous token.
		limiterKey += "\x00" + opts.SandboxID
	} else {
		limiterKey = opts.SandboxID
	}
	flight, cached, leader := m.trafficTokenLimiter.acquire(limiterKey)
	if flight == nil {
		return cached, nil
	}
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
	m.trafficTokenLimiter.complete(limiterKey, flight, result, issueErr)
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

type trafficTokenLimitEntry struct {
	flight      *trafficTokenFlight
	lastSuccess time.Time
	result      infra.TrafficAccessToken
}

type trafficTokenFlight struct {
	done   chan struct{}
	result infra.TrafficAccessToken
	err    error
}

type trafficTokenLimiter struct {
	mu            sync.Mutex
	entries       map[string]trafficTokenLimitEntry
	minInterval   time.Duration
	now           func() time.Time
	lastCleanupAt time.Time
}

func newTrafficTokenLimiter(minInterval time.Duration, now func() time.Time) *trafficTokenLimiter {
	return &trafficTokenLimiter{entries: make(map[string]trafficTokenLimitEntry), minInterval: minInterval, now: now}
}

func (l *trafficTokenLimiter) acquire(key string) (flight *trafficTokenFlight, cached infra.TrafficAccessToken, leader bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.cleanup(now)
	entry := l.entries[key]
	if entry.flight != nil {
		return entry.flight, infra.TrafficAccessToken{}, false
	}
	if elapsed := now.Sub(entry.lastSuccess); !entry.lastSuccess.IsZero() &&
		elapsed < l.minInterval && entry.result.Expiration.After(now.Add(l.minInterval)) {
		return nil, entry.result, false
	}
	flight = &trafficTokenFlight{done: make(chan struct{})}
	entry.flight = flight
	l.entries[key] = entry
	return flight, infra.TrafficAccessToken{}, true
}

func (l *trafficTokenLimiter) complete(key string, flight *trafficTokenFlight, result infra.TrafficAccessToken, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	flight.result = result
	flight.err = err
	entry := l.entries[key]
	if entry.flight == flight {
		entry.flight = nil
		if err == nil {
			// Reuse a recent successful result so another tokenless client can
			// connect without triggering duplicate issuance.
			entry.lastSuccess = l.now()
			entry.result = result
		}
		l.entries[key] = entry
	}
	close(flight.done)
}

func (l *trafficTokenLimiter) cleanup(now time.Time) {
	if !l.lastCleanupAt.IsZero() && now.Sub(l.lastCleanupAt) < l.minInterval {
		return
	}
	for key, entry := range l.entries {
		if entry.flight == nil && now.Sub(entry.lastSuccess) >= l.minInterval {
			delete(l.entries, key)
		}
	}
	l.lastCleanupAt = now
}
