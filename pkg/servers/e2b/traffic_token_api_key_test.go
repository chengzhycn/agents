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

package e2b

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkruise/agents/pkg/servers/e2b/keys"
)

func TestTrafficTokenCredentialsPreserveAPIKeyAndDisabledAuth(t *testing.T) {
	controller, _, teardown := Setup(t)
	defer teardown()

	request := httptest.NewRequest(http.MethodPost, "/traffic-access-token", nil)
	request.Header.Set("X-API-KEY", InitKey)
	ctx, apiErr := controller.CheckTrafficTokenCredentials(context.Background(), request)
	require.Nil(t, apiErr)
	require.NotNil(t, GetUserFromContext(ctx))
	assert.Equal(t, keys.AdminKeyID, GetUserFromContext(ctx).ID)

	controller.keys = nil
	ctx, apiErr = controller.CheckTrafficTokenCredentials(context.Background(), httptest.NewRequest(http.MethodPost, "/traffic-access-token", nil))
	require.Nil(t, apiErr)
	assert.Same(t, AnonymousUser, GetUserFromContext(ctx))
}
