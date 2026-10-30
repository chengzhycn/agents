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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxSigningResponseBytes = 1 << 20

type tokenResponse struct {
	Token      string `json:"trafficAccessToken"`
	Expiration string `json:"trafficAccessTokenExpiration"`
}

// HTTPStatusError reports a non-success response from the signing endpoint.
type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("traffic token signing returned HTTP %d", e.StatusCode)
}

func (c *Client) fetch(ctx context.Context) (result Token, err error) {
	bearer, err := c.provider(ctx)
	if err != nil {
		return Token{}, fmt.Errorf("resolve signing bearer token: %w", err)
	}
	bearer = strings.TrimSpace(bearer)
	if bearer == "" {
		return Token{}, errors.New("signing bearer token is empty")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.refreshURL(), nil)
	if err != nil {
		return Token{}, fmt.Errorf("create signing request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	response, err := c.signingClient.Do(request)
	if err != nil {
		return Token{}, fmt.Errorf("send signing request: %w", err)
	}
	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()
	if response.StatusCode != http.StatusOK {
		statusError := &HTTPStatusError{StatusCode: response.StatusCode}
		if _, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, maxSigningResponseBytes)); readErr != nil {
			return Token{}, errors.Join(statusError, fmt.Errorf("read signing error response: %w", readErr))
		}
		return Token{}, statusError
	}

	var payload tokenResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxSigningResponseBytes))
	if err := decoder.Decode(&payload); err != nil {
		return Token{}, fmt.Errorf("decode signing response: %w", err)
	}
	if payload.Token == "" {
		return Token{}, errors.New("signing response token is empty")
	}
	expiration, err := time.Parse(time.RFC3339Nano, payload.Expiration)
	if err != nil {
		return Token{}, fmt.Errorf("parse signing response expiration: %w", err)
	}
	expiration = expiration.UTC()
	if !expiration.After(c.now()) {
		return Token{}, errors.New("signing response token is expired")
	}
	return Token{Token: payload.Token, Expiration: expiration}, nil
}
