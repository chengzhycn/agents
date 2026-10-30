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

package traffictoken

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const defaultSigningTimeout = 10 * time.Second

var (
	// ErrTokenExpired indicates that refresh failed after the cached token expired.
	ErrTokenExpired = errors.New("traffic access token expired")
	// ErrOriginMismatch indicates that a request targeted an origin other than the transport binding.
	ErrOriginMismatch = errors.New("traffic token transport origin mismatch")
)

// BearerTokenProvider returns a current bearer credential for one signing request.
type BearerTokenProvider func(context.Context) (string, error)

// Config identifies one Sandbox and its trusted signing endpoint.
type Config struct {
	ManagerURL          string
	Namespace           string
	SandboxID           string
	SandboxUID          string
	BearerTokenProvider BearerTokenProvider
	SigningClient       *http.Client
}

// Token is a traffic JWT and its server-reported expiration.
type Token struct {
	Token      string
	Expiration time.Time
}

type cacheBinding struct {
	namespace  string
	sandboxID  string
	sandboxUID string
}

type cachedToken struct {
	token     Token
	refreshAt time.Time
}

type refreshFlight struct {
	done   chan struct{}
	result Token
	err    error
}

// Client owns the refresh cache and signing lifecycle for one Sandbox instance.
type Client struct {
	managerURL    *url.URL
	binding       cacheBinding
	provider      BearerTokenProvider
	signingClient *http.Client
	now           func() time.Time

	mu     sync.Mutex
	cache  cachedToken
	flight *refreshFlight
}

// New validates config and creates an instance-isolated refresh client.
func New(config Config) (*Client, error) {
	managerURL, err := parseManagerURL(config.ManagerURL)
	if err != nil {
		return nil, err
	}
	if config.Namespace == "" {
		return nil, errors.New("namespace is required")
	}
	if config.SandboxID == "" {
		return nil, errors.New("sandbox ID is required")
	}
	if config.BearerTokenProvider == nil {
		return nil, errors.New("bearer token provider is required")
	}

	signingClient := newSigningClient(config.SigningClient)
	return &Client{
		managerURL: managerURL,
		binding: cacheBinding{
			namespace:  config.Namespace,
			sandboxID:  config.SandboxID,
			sandboxUID: config.SandboxUID,
		},
		provider:      config.BearerTokenProvider,
		signingClient: signingClient,
		now:           time.Now,
	}, nil
}

// Refresh explicitly obtains a new token, coalescing with an overlapping refresh.
func (c *Client) Refresh(ctx context.Context) (Token, error) {
	return c.token(ctx, true)
}

func (c *Client) token(ctx context.Context, force bool) (Token, error) {
	if err := ctx.Err(); err != nil {
		return Token{}, err
	}

	c.mu.Lock()
	if !force && c.cache.token.Token != "" && c.now().Before(c.cache.refreshAt) {
		result := c.cache.token
		c.mu.Unlock()
		return result, nil
	}
	flight := c.flight
	if flight == nil {
		flight = &refreshFlight{done: make(chan struct{})}
		c.flight = flight
		workCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.signingClient.Timeout)
		go c.runRefresh(workCtx, cancel, flight)
	}
	c.mu.Unlock()

	select {
	case <-ctx.Done():
		return Token{}, ctx.Err()
	case <-flight.done:
		return flight.result, flight.err
	}
}

func (c *Client) runRefresh(ctx context.Context, cancel context.CancelFunc, flight *refreshFlight) {
	defer cancel()
	result, err := c.fetch(ctx)

	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		lifetime := result.Expiration.Sub(c.now())
		margin := min(lifetime/5, 5*time.Minute)
		c.cache = cachedToken{token: result, refreshAt: result.Expiration.Add(-margin)}
	}
	flight.result = result
	flight.err = err
	c.flight = nil
	close(flight.done)
}

func parseManagerURL(raw string) (*url.URL, error) {
	managerURL, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse manager URL: %w", err)
	}
	if managerURL.Scheme != "https" || managerURL.Host == "" {
		return nil, errors.New("manager URL must be an absolute HTTPS URL")
	}
	if managerURL.User != nil || managerURL.RawQuery != "" || managerURL.Fragment != "" || managerURL.Opaque != "" {
		return nil, errors.New("manager URL must not contain userinfo, query, or fragment")
	}
	return managerURL, nil
}

func newSigningClient(configured *http.Client) *http.Client {
	if configured == nil {
		configured = &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	}
	client := *configured
	if client.Timeout <= 0 {
		client.Timeout = defaultSigningTimeout
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client
}

func (c *Client) currentValidToken() (Token, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cache.token, c.cache.token.Token != "" && c.now().Before(c.cache.token.Expiration)
}

func (c *Client) tokenForRequest(ctx context.Context) (Token, error) {
	result, err := c.token(ctx, false)
	if err == nil {
		return result, nil
	}
	current, valid := c.currentValidToken()
	if valid {
		return current, nil
	}
	if current.Token != "" {
		return Token{}, fmt.Errorf("%w: refresh failed: %w", ErrTokenExpired, err)
	}
	return Token{}, err
}

func (c *Client) refreshURL() string {
	endpoint := *c.managerURL
	path := strings.TrimSuffix(endpoint.Path, "/") +
		"/kruise/api/sandboxes/" + c.binding.sandboxID + "/traffic-access-token"
	rawPath := strings.TrimSuffix(endpoint.EscapedPath(), "/") +
		"/kruise/api/sandboxes/" + url.PathEscape(c.binding.sandboxID) + "/traffic-access-token"
	endpoint.Path = path
	endpoint.RawPath = rawPath
	query := endpoint.Query()
	query.Set("namespace", c.binding.namespace)
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}
