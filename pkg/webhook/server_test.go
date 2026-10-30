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

package webhook

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
)

type registrationTestManager struct {
	manager.Manager
	client client.Client
	scheme *runtime.Scheme
}

func (m *registrationTestManager) GetClient() client.Client {
	return m.client
}

func (m *registrationTestManager) GetScheme() *runtime.Scheme {
	return m.scheme
}

func TestHandlerGettersIncludeClaimIdentityProtection(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, agentsv1alpha1.AddToScheme(scheme))
	mgr := &registrationTestManager{client: fake.NewClientBuilder().WithScheme(scheme).Build(), scheme: scheme}
	paths := make(map[string]bool, len(HandlerGetters))

	for _, getter := range HandlerGetters {
		paths[getter(mgr).Path()] = true
	}

	require.True(t, paths["/default-sandboxclaim-identity"])
	require.True(t, paths["/validate-sandboxclaim-identity"])
	require.True(t, paths["/validate-sandbox-claim-identity"])
}
