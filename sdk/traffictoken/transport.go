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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// TrafficAccessTokenHeader is the raw traffic JWT header expected by sandbox-gateway.
const TrafficAccessTokenHeader = "e2b-traffic-access-token"

// Transport injects refreshed traffic JWTs into requests for exactly one origin.
type Transport struct {
	client *Client
	next   http.RoundTripper
	scheme string
	host   string
}

// NewTransport creates an origin-bound transport over next.
func (c *Client) NewTransport(allowedOrigin string, next http.RoundTripper) (*Transport, error) {
	origin, err := parseOrigin(allowedOrigin)
	if err != nil {
		return nil, err
	}
	if next == nil {
		next = http.DefaultTransport
	}
	return &Transport{client: c, next: next, scheme: origin.Scheme, host: origin.Host}, nil
}

// RoundTrip refreshes the token when needed and sends an immutable request clone.
func (t *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !strings.EqualFold(request.URL.Scheme, t.scheme) || !strings.EqualFold(request.URL.Host, t.host) {
		return nil, fmt.Errorf("%w: got %s://%s", ErrOriginMismatch, request.URL.Scheme, request.URL.Host)
	}
	token, err := t.client.tokenForRequest(request.Context())
	if err != nil {
		return nil, err
	}
	clone := request.Clone(request.Context())
	clone.Header.Set(TrafficAccessTokenHeader, token.Token)
	return t.next.RoundTrip(clone)
}

func parseOrigin(raw string) (*url.URL, error) {
	origin, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse allowed origin: %w", err)
	}
	if (origin.Scheme != "http" && origin.Scheme != "https") || origin.Host == "" {
		return nil, errors.New("allowed origin must be an absolute HTTP or HTTPS origin")
	}
	if origin.User != nil || (origin.Path != "" && origin.Path != "/") || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("allowed origin must not contain userinfo, path, query, or fragment")
	}
	return origin, nil
}
