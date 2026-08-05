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

package sandboxcr

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/cache"
	"github.com/openkruise/agents/pkg/sandbox-manager/infra"
	"github.com/openkruise/agents/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildTrafficPolicy(t *testing.T) {
	owner := &agentsv1alpha1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{Name: "test-sandbox", UID: "test-uid"},
	}
	tests := []struct {
		name                string
		allowInternetAccess bool
		allowOutCIDRs       []string
		allowOutDomains     []string
		denyOut             []string
		expectNil           bool
		actions             []agentsv1alpha1.RuleAction
		cidrs               [][]string
		fqdns               [][]string
	}{
		{
			name:                "true with no rules has no local policy",
			allowInternetAccess: true,
			expectNil:           true,
		},
		{
			name:                "true allow only appends allow all",
			allowInternetAccess: true,
			allowOutCIDRs:       []string{"1.2.3.4/32"},
			actions: []agentsv1alpha1.RuleAction{
				agentsv1alpha1.RuleActionAllow,
				agentsv1alpha1.RuleActionAllow,
			},
			cidrs: [][]string{
				{"1.2.3.4/32"},
				{"0.0.0.0/0"},
			},
		},
		{
			name:                "true narrow deny appends allow all",
			allowInternetAccess: true,
			denyOut:             []string{"10.0.0.0/8"},
			actions:             []agentsv1alpha1.RuleAction{agentsv1alpha1.RuleActionReject, agentsv1alpha1.RuleActionAllow},
			cidrs:               [][]string{{"10.0.0.0/8"}, {"0.0.0.0/0"}},
		},
		{
			name:                "true allow wins before deny and allow all",
			allowInternetAccess: true,
			allowOutCIDRs:       []string{"1.2.3.4/32"},
			allowOutDomains:     []string{"api.example.com"},
			denyOut:             []string{"10.0.0.0/8"},
			actions: []agentsv1alpha1.RuleAction{
				agentsv1alpha1.RuleActionAllow,
				agentsv1alpha1.RuleActionReject,
				agentsv1alpha1.RuleActionAllow,
			},
			cidrs: [][]string{
				{"1.2.3.4/32"},
				{"10.0.0.0/8"},
				{"0.0.0.0/0"},
			},
			fqdns: [][]string{
				{"api.example.com"},
				nil,
				nil,
			},
		},
		{
			name:                "true deny all has no unreachable tail",
			allowInternetAccess: true,
			denyOut:             []string{"0.0.0.0/0"},
			actions:             []agentsv1alpha1.RuleAction{agentsv1alpha1.RuleActionReject},
			cidrs:               [][]string{{"0.0.0.0/0"}},
		},
		{
			name:                "false allow only relies on global fallback",
			allowInternetAccess: false,
			allowOutDomains:     []string{"api.example.com"},
			actions:             []agentsv1alpha1.RuleAction{agentsv1alpha1.RuleActionAllow},
			fqdns:               [][]string{{"api.example.com"}},
		},
		{
			name:                "false narrow deny relies on global fallback",
			allowInternetAccess: false,
			denyOut:             []string{"8.8.4.4"},
			actions:             []agentsv1alpha1.RuleAction{agentsv1alpha1.RuleActionReject},
			cidrs:               [][]string{{"8.8.4.4/32"}},
		},
		{
			name:                "true explicit allow all is not duplicated",
			allowInternetAccess: true,
			allowOutCIDRs:       []string{"0.0.0.0/0"},
			actions:             []agentsv1alpha1.RuleAction{agentsv1alpha1.RuleActionAllow},
			cidrs:               [][]string{{"0.0.0.0/0"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := buildTrafficPolicy(tt.allowInternetAccess, tt.allowOutCIDRs, tt.allowOutDomains, tt.denyOut, "default", "test-sandbox-id", owner)
			if tt.expectNil {
				assert.Nil(t, tp)
				return
			}
			require.NotNil(t, tp)
			require.NotNil(t, tp.Spec.Egress)
			rules := tp.Spec.Egress.Rules
			assert.Len(t, rules, len(tt.actions))

			for i, expectedAction := range tt.actions {
				require.Less(t, i, len(rules), "fewer rules than expected")
				assert.Equal(t, expectedAction, rules[i].Action, "rule %d action mismatch", i)
				if i < len(tt.cidrs) {
					var gotCIDRs []string
					for _, peer := range rules[i].To {
						if peer.CIDR != "" {
							gotCIDRs = append(gotCIDRs, peer.CIDR)
						}
					}
					assert.Equal(t, tt.cidrs[i], gotCIDRs, "rule %d peer CIDRs mismatch", i)
				}
				if i < len(tt.fqdns) {
					var gotFQDNs []string
					for _, peer := range rules[i].To {
						if peer.FQDN != "" {
							gotFQDNs = append(gotFQDNs, peer.FQDN)
						}
					}
					assert.Equal(t, tt.fqdns[i], gotFQDNs, "rule %d peer FQDNs mismatch", i)
				}
			}

			// Verify metadata
			assert.Equal(t, "e2b-test-sandbox", tp.Name)
			assert.Equal(t, "default", tp.Namespace)
			assert.Equal(t, "test-sandbox", tp.Spec.Selector.MatchLabels[agentsv1alpha1.LabelSandboxName])
			assert.Equal(t, int32(100), tp.Spec.Priority)
			// Verify OwnerReference is set
			require.Len(t, tp.OwnerReferences, 1)
			assert.Equal(t, "Sandbox", tp.OwnerReferences[0].Kind)
			assert.Equal(t, "test-sandbox", tp.OwnerReferences[0].Name)
			assert.Equal(t, "test-uid", string(tp.OwnerReferences[0].UID))
		})
	}
}

func TestIsGlobalDenyFallback(t *testing.T) {
	valid := func() *agentsv1alpha1.GlobalTrafficPolicy {
		return &agentsv1alpha1.GlobalTrafficPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: e2bGlobalDenyFallbackName},
			Spec: agentsv1alpha1.TrafficPolicySpec{
				Priority: 900,
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{
					agentsv1alpha1.LabelAllowInternetAccess: agentsv1alpha1.False,
				}},
				Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
					Action: agentsv1alpha1.RuleActionReject,
					To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}},
				}}},
			},
		}
	}
	tests := []struct {
		name   string
		mutate func(*agentsv1alpha1.GlobalTrafficPolicy)
		want   bool
	}{
		{name: "exact addon policy", want: true},
		{name: "wrong name", mutate: func(p *agentsv1alpha1.GlobalTrafficPolicy) { p.Name = "other" }},
		{name: "terminating", mutate: func(p *agentsv1alpha1.GlobalTrafficPolicy) {
			now := metav1.Now()
			p.DeletionTimestamp = &now
		}},
		{name: "extra selector label", mutate: func(p *agentsv1alpha1.GlobalTrafficPolicy) { p.Spec.Selector.MatchLabels["extra"] = "value" }},
		{name: "selector expression", mutate: func(p *agentsv1alpha1.GlobalTrafficPolicy) {
			p.Spec.Selector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "extra", Operator: metav1.LabelSelectorOpExists}}
		}},
		{name: "allow before reject", mutate: func(p *agentsv1alpha1.GlobalTrafficPolicy) {
			p.Spec.Egress.Rules = append([]agentsv1alpha1.TrafficPolicyRule{{Action: agentsv1alpha1.RuleActionAllow}}, p.Spec.Egress.Rules...)
		}},
		{name: "port constrained", mutate: func(p *agentsv1alpha1.GlobalTrafficPolicy) {
			p.Spec.Egress.Rules[0].Ports = []agentsv1alpha1.TrafficPolicyPort{{Protocol: "TCP"}}
		}},
		{name: "source constrained", mutate: func(p *agentsv1alpha1.GlobalTrafficPolicy) {
			p.Spec.Egress.Rules[0].From = []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/8"}}
		}},
		{name: "extra destination", mutate: func(p *agentsv1alpha1.GlobalTrafficPolicy) {
			p.Spec.Egress.Rules[0].To = append(p.Spec.Egress.Rules[0].To, agentsv1alpha1.TrafficPolicyPeer{CIDR: "10.0.0.0/8"})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := valid()
			if tt.mutate != nil {
				tt.mutate(policy)
			}
			assert.Equal(t, tt.want, isGlobalDenyFallback(policy))
		})
	}
}

// TestCreateSelectNetworkPolicy_RoundTrip verifies that network config
// written via CreateNetworkPolicy can be fully read back via
// SelectNetworkPolicy. The read-back returns the explicit TrafficPolicy
// configuration (no auto-injected entries).
// Round-trip safety is guaranteed by buildTrafficPolicy's faithful encoding.
func TestCreateSelectNetworkPolicy_RoundTrip(t *testing.T) {
	tests := []struct {
		name           string
		network        infra.SandboxNetworkConfig
		expectAllowOut []string
		expectDenyOut  []string
	}{
		{
			name: "whitelist + denyOut round-trip preserves both",
			network: infra.SandboxNetworkConfig{
				AllowInternetAccess: true,
				AllowOut:            []string{"1.2.3.4", "api.example.com"},
				DenyOut:             []string{"10.0.0.0/8", "172.16.0.0/12"},
			},
			expectAllowOut: []string{"1.2.3.4", "api.example.com"},
			expectDenyOut:  []string{"10.0.0.0/8", "172.16.0.0/12"},
		},
		{
			name: "whitelist only round-trip",
			network: infra.SandboxNetworkConfig{
				AllowInternetAccess: true,
				AllowOut:            []string{"1.2.3.4"},
			},
			expectAllowOut: []string{"1.2.3.4"},
			expectDenyOut:  nil,
		},
		{
			name: "blacklist only round-trip",
			network: infra.SandboxNetworkConfig{
				AllowInternetAccess: true,
				DenyOut:             []string{"8.8.8.8/32"},
			},
			expectAllowOut: nil,
			expectDenyOut:  []string{"8.8.8.8/32"},
		},
		{
			name: "whitelist + bare IP denyOut gets normalized",
			network: infra.SandboxNetworkConfig{
				AllowInternetAccess: true,
				AllowOut:            []string{"1.1.1.1"},
				DenyOut:             []string{"8.8.4.4"},
			},
			expectAllowOut: []string{"1.1.1.1"},
			expectDenyOut:  []string{"8.8.4.4"},
		},
		{
			name: "FQDN only round-trip preserves domains",
			network: infra.SandboxNetworkConfig{
				AllowInternetAccess: true,
				AllowOut:            []string{"api.example.com"},
			},
			expectAllowOut: []string{"api.example.com"},
			expectDenyOut:  nil,
		},
		{
			name: "mixed CIDR + FQDN + denyOut round-trip",
			network: infra.SandboxNetworkConfig{
				AllowInternetAccess: true,
				AllowOut:            []string{"1.2.3.4", "api.example.com"},
				DenyOut:             []string{"10.0.0.0/8"},
			},
			expectAllowOut: []string{"1.2.3.4", "api.example.com"},
			expectDenyOut:  []string{"10.0.0.0/8"},
		},
		{
			name: "allowOut 0.0.0.0/0 round-trip preserves allow-all",
			network: infra.SandboxNetworkConfig{
				AllowInternetAccess: true,
				AllowOut:            []string{"0.0.0.0/0"},
			},
			expectAllowOut: []string{"0.0.0.0/0"},
			expectDenyOut:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			infraInstance, fc := NewTestInfra(t)

			sbx := createTestSandbox("network-rt-sandbox", "test-user", agentsv1alpha1.SandboxRunning, true)
			CreateSandboxWithStatus(t, fc, sbx)

			// Wait for cache to sync
			var sandbox infra.Sandbox
			require.Eventually(t, func() bool {
				var err error
				sandbox, err = infraInstance.GetSandbox(t.Context(), infra.GetSandboxOptions{
					SandboxID: utils.GetSandboxID(sbx),
					Namespace: sbx.Namespace,
				})
				return err == nil
			}, time.Second, 10*time.Millisecond)

			// Create network CRs
			require.NoError(t, sandbox.CreateNetworkPolicy(t.Context(), tt.network))

			// Read back
			result, err := sandbox.SelectNetworkPolicy(t.Context())
			require.NoError(t, err)
			require.NotNil(t, result, "SelectNetworkPolicy should return non-nil config")

			assert.ElementsMatch(t, tt.expectAllowOut, result.AllowOut)
			assert.ElementsMatch(t, tt.expectDenyOut, result.DenyOut)
		})
	}
}

// TestUpdateSelectNetworkPolicy_RoundTrip verifies that UpdateNetworkPolicy
// (replace semantics) also preserves denyOut in whitelist mode and FQDN entries.
func TestUpdateSelectNetworkPolicy_RoundTrip(t *testing.T) {
	infraInstance, fc := NewTestInfra(t)

	sbx := createTestSandbox("network-update-sandbox", "test-user", agentsv1alpha1.SandboxRunning, true)
	CreateSandboxWithStatus(t, fc, sbx)

	var sandbox infra.Sandbox
	require.Eventually(t, func() bool {
		var err error
		sandbox, err = infraInstance.GetSandbox(t.Context(), infra.GetSandboxOptions{
			SandboxID: utils.GetSandboxID(sbx),
			Namespace: sbx.Namespace,
		})
		return err == nil
	}, time.Second, 10*time.Millisecond)

	// Step 1: Create with allowOut only
	require.NoError(t, sandbox.CreateNetworkPolicy(t.Context(), infra.SandboxNetworkConfig{
		AllowInternetAccess: true,
		AllowOut:            []string{"1.2.3.4"},
	}))

	result, err := sandbox.SelectNetworkPolicy(t.Context())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []string{"1.2.3.4"}, result.AllowOut)
	assert.Nil(t, result.DenyOut)

	// Step 2: Update to allowOut + denyOut (whitelist mode with deny)
	require.NoError(t, sandbox.UpdateNetworkPolicy(t.Context(), infra.SandboxNetworkConfig{
		AllowInternetAccess: true,
		AllowOut:            []string{"1.2.3.4"},
		DenyOut:             []string{"10.0.0.0/8"},
	}))

	result, err = sandbox.SelectNetworkPolicy(t.Context())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []string{"1.2.3.4"}, result.AllowOut)
	assert.ElementsMatch(t, []string{"10.0.0.0/8"}, result.DenyOut)

	// Step 3: Update to add FQDN entries
	require.NoError(t, sandbox.UpdateNetworkPolicy(t.Context(), infra.SandboxNetworkConfig{
		AllowInternetAccess: true,
		AllowOut:            []string{"1.2.3.4", "api.example.com"},
		DenyOut:             []string{"10.0.0.0/8"},
	}))

	result, err = sandbox.SelectNetworkPolicy(t.Context())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.ElementsMatch(t, []string{"1.2.3.4", "api.example.com"}, result.AllowOut)
	assert.ElementsMatch(t, []string{"10.0.0.0/8"}, result.DenyOut)

	// Step 4: Update to clear all (empty config)
	require.NoError(t, sandbox.UpdateNetworkPolicy(t.Context(), infra.SandboxNetworkConfig{AllowInternetAccess: true}))

	result, err = sandbox.SelectNetworkPolicy(t.Context())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.AllowInternetAccess)
	assert.Empty(t, result.AllowOut)
	assert.Empty(t, result.DenyOut)
}

// TestUpdateNetworkPolicy_CreateWhenNoExisting verifies that UpdateNetworkPolicy
// creates a new TrafficPolicy when none exists for the sandbox (the "create"
// branch), as opposed to the "update existing" and "delete" branches already
// covered by TestUpdateSelectNetworkPolicy_RoundTrip.
func TestUpdateNetworkPolicy_CreateWhenNoExisting(t *testing.T) {
	tests := []struct {
		name           string
		network        infra.SandboxNetworkConfig
		expectAllowOut []string
		expectDenyOut  []string
	}{
		{
			name: "whitelist mode creates new TP",
			network: infra.SandboxNetworkConfig{
				AllowInternetAccess: true,
				AllowOut:            []string{"1.2.3.4"},
				DenyOut:             []string{"10.0.0.0/8"},
			},
			expectAllowOut: []string{"1.2.3.4"},
			expectDenyOut:  []string{"10.0.0.0/8"},
		},
		{
			name: "blacklist mode creates new TP",
			network: infra.SandboxNetworkConfig{
				AllowInternetAccess: true,
				DenyOut:             []string{"8.8.8.8/32"},
			},
			expectAllowOut: nil,
			expectDenyOut:  []string{"8.8.8.8/32"},
		},
		{
			name: "FQDN mode creates new TP",
			network: infra.SandboxNetworkConfig{
				AllowInternetAccess: true,
				AllowOut:            []string{"api.example.com"},
			},
			expectAllowOut: []string{"api.example.com"},
			expectDenyOut:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			infraInstance, fc := NewTestInfra(t)

			sbx := createTestSandbox("network-update-create-sandbox", "test-user", agentsv1alpha1.SandboxRunning, true)
			CreateSandboxWithStatus(t, fc, sbx)

			var sandbox infra.Sandbox
			require.Eventually(t, func() bool {
				var err error
				sandbox, err = infraInstance.GetSandbox(t.Context(), infra.GetSandboxOptions{
					SandboxID: utils.GetSandboxID(sbx),
					Namespace: sbx.Namespace,
				})
				return err == nil
			}, time.Second, 10*time.Millisecond)

			// Call UpdateNetworkPolicy directly without prior CreateNetworkPolicy,
			// exercising the "create new TP" branch.
			require.NoError(t, sandbox.UpdateNetworkPolicy(t.Context(), tt.network))

			// Read back to verify the TP was created.
			result, err := sandbox.SelectNetworkPolicy(t.Context())
			require.NoError(t, err)
			require.NotNil(t, result, "SelectNetworkPolicy should return non-nil config")

			assert.ElementsMatch(t, tt.expectAllowOut, result.AllowOut)
			assert.ElementsMatch(t, tt.expectDenyOut, result.DenyOut)
		})
	}
}

// TestUpdateNetworkPolicy_PreservesExternalAnnotations verifies that
// UpdateNetworkPolicy does not clobber annotations injected by other
// controllers or webhooks (e.g., last-applied-configuration, cert-manager).
func TestUpdateNetworkPolicy_PreservesExternalAnnotations(t *testing.T) {
	infraInstance, fc := NewTestInfra(t)

	sbx := createTestSandbox("network-annotation-sandbox", "test-user", agentsv1alpha1.SandboxRunning, true)
	CreateSandboxWithStatus(t, fc, sbx)

	var sandbox infra.Sandbox
	require.Eventually(t, func() bool {
		var err error
		sandbox, err = infraInstance.GetSandbox(t.Context(), infra.GetSandboxOptions{
			SandboxID: utils.GetSandboxID(sbx),
			Namespace: sbx.Namespace,
		})
		return err == nil
	}, time.Second, 10*time.Millisecond)

	// Step 1: Create initial TrafficPolicy.
	require.NoError(t, sandbox.CreateNetworkPolicy(t.Context(), infra.SandboxNetworkConfig{
		AllowInternetAccess: true,
		AllowOut:            []string{"1.2.3.4"},
	}))

	// Step 2: Simulate an external controller/webhook adding annotations.
	sandboxID := utils.GetSandboxID(sbx)
	tpList := &agentsv1alpha1.TrafficPolicyList{}
	require.NoError(t, fc.List(t.Context(), tpList,
		ctrlclient.InNamespace(sbx.Namespace),
		ctrlclient.MatchingFields{cache.IndexTrafficPolicySandboxID: sandboxID},
	))
	require.Len(t, tpList.Items, 1)
	tp := &tpList.Items[0]
	tp.Annotations["cert-manager.io/certificate-name"] = "my-cert"
	tp.Annotations["kubectl.kubernetes.io/last-applied-configuration"] = `{"kind":"TrafficPolicy"}`
	require.NoError(t, fc.Update(t.Context(), tp))

	// Step 3: Update network policy with new config.
	require.NoError(t, sandbox.UpdateNetworkPolicy(t.Context(), infra.SandboxNetworkConfig{
		AllowInternetAccess: true,
		AllowOut:            []string{"1.2.3.4"},
		DenyOut:             []string{"10.0.0.0/8"},
	}))

	// Step 4: Verify external annotations are preserved.
	tpList = &agentsv1alpha1.TrafficPolicyList{}
	require.NoError(t, fc.List(t.Context(), tpList,
		ctrlclient.InNamespace(sbx.Namespace),
		ctrlclient.MatchingFields{cache.IndexTrafficPolicySandboxID: sandboxID},
	))
	require.Len(t, tpList.Items, 1)
	updated := &tpList.Items[0]

	// External annotations must be preserved.
	assert.Equal(t, "my-cert", updated.Annotations["cert-manager.io/certificate-name"],
		"external annotation should be preserved after update")
	assert.Contains(t, updated.Annotations, "kubectl.kubernetes.io/last-applied-configuration",
		"last-applied-configuration annotation should be preserved after update")

	// Sandbox ID annotation must still be present.
	assert.Equal(t, sandboxID, updated.Annotations[agentsv1alpha1.AnnotationSandboxID],
		"sandbox ID annotation should be present after update")

	// Spec should be updated.
	result, err := sandbox.SelectNetworkPolicy(t.Context())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []string{"1.2.3.4"}, result.AllowOut)
	assert.ElementsMatch(t, []string{"10.0.0.0/8"}, result.DenyOut)
}

func TestUpdateNetworkPolicy_GlobalFallbackCapability(t *testing.T) {
	infraInstance, fc := NewTestInfra(t)
	sbx := createTestSandbox("network-global-fallback", "test-user", agentsv1alpha1.SandboxRunning, true)
	sbx.Spec.Template = &corev1.PodTemplateSpec{}
	CreateSandboxWithStatus(t, fc, sbx)

	var sandbox infra.Sandbox
	require.Eventually(t, func() bool {
		var err error
		sandbox, err = infraInstance.GetSandbox(t.Context(), infra.GetSandboxOptions{
			SandboxID: utils.GetSandboxID(sbx),
			Namespace: sbx.Namespace,
		})
		return err == nil
	}, time.Second, 10*time.Millisecond)

	desired := infra.SandboxNetworkConfig{AllowInternetAccess: false}
	err := sandbox.UpdateNetworkPolicy(t.Context(), desired)
	require.Error(t, err)
	assert.True(t, errors.Is(err, infra.ErrNetworkPolicyUnavailable))

	require.NoError(t, fc.Create(t.Context(), &agentsv1alpha1.GlobalTrafficPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "e2b-deny-internet"},
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Priority: 900,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				agentsv1alpha1.LabelAllowInternetAccess: agentsv1alpha1.False,
			}},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
				Action: agentsv1alpha1.RuleActionReject,
				To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "0.0.0.0/0"}},
			}}},
		},
	}))
	require.NoError(t, sandbox.UpdateNetworkPolicy(t.Context(), desired))

	state, err := sandbox.SelectNetworkPolicy(t.Context())
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.False(t, state.AllowInternetAccess)
	assert.Equal(t, agentsv1alpha1.False, sandbox.GetLabels()[agentsv1alpha1.LabelAllowInternetAccess])
	assert.Equal(t, agentsv1alpha1.False, sandbox.GetPodLabels()[agentsv1alpha1.LabelAllowInternetAccess])
	assert.NotEmpty(t, sandbox.GetAnnotations()[agentsv1alpha1.AnnotationE2BNetworkConfig])
	assert.NotEmpty(t, sandbox.GetAnnotations()[agentsv1alpha1.AnnotationE2BNetworkConfigHash])
}

func TestDesiredNetworkMetadataStable(t *testing.T) {
	desired := infra.SandboxNetworkConfig{
		AllowInternetAccess: true,
		AllowOut:            []string{"api.example.com", "1.2.3.4"},
		DenyOut:             []string{"10.0.0.0/8"},
	}
	raw1, hash1, err := desiredNetworkMetadata(desired)
	require.NoError(t, err)
	raw2, hash2, err := desiredNetworkMetadata(desired)
	require.NoError(t, err)
	assert.Equal(t, raw1, raw2)
	assert.Equal(t, hash1, hash2)
	assert.JSONEq(t, `{"allowInternetAccess":true,"allowOut":["api.example.com","1.2.3.4"],"denyOut":["10.0.0.0/8"]}`, raw1)
}

func TestNetworkOperationSerializesUpdates(t *testing.T) {
	infraInstance, fc := NewTestInfra(t)
	sbx := createTestSandbox("network-operation-lock", "test-user", agentsv1alpha1.SandboxRunning, true)
	CreateSandboxWithStatus(t, fc, sbx)

	var sandbox infra.Sandbox
	require.Eventually(t, func() bool {
		var err error
		sandbox, err = infraInstance.GetSandbox(t.Context(), infra.GetSandboxOptions{
			SandboxID: utils.GetSandboxID(sbx),
			Namespace: sbx.Namespace,
		})
		return err == nil
	}, time.Second, 10*time.Millisecond)
	concrete := sandbox.(*Sandbox)

	firstID, err := concrete.acquireNetworkOperation(t.Context())
	require.NoError(t, err)
	_, err = concrete.acquireNetworkOperation(t.Context())
	require.Error(t, err)
	assert.True(t, errors.Is(err, infra.ErrNetworkPolicyConflict))
	require.NoError(t, concrete.releaseNetworkOperation(t.Context(), firstID))

	secondID, err := concrete.acquireNetworkOperation(t.Context())
	require.NoError(t, err)
	assert.NotEqual(t, firstID, secondID)
	require.NoError(t, concrete.releaseNetworkOperation(t.Context(), secondID))
}

func TestNetworkOperationUsesLiveSandbox(t *testing.T) {
	live := createTestSandboxWithDefaults("network-live-cas", "default")
	operation := networkOperation{ID: "active-operation", ExpiresAt: time.Now().Add(time.Minute)}
	raw, err := json.Marshal(operation)
	require.NoError(t, err)
	live.Annotations = map[string]string{}
	live.Annotations[agentsv1alpha1.AnnotationE2BNetworkOperation] = string(raw)
	stale := live.DeepCopy()
	delete(stale.Annotations, agentsv1alpha1.AnnotationE2BNetworkOperation)
	provider, fc := newRetryUpdateTestCache(t, live, stale, nil)
	sandbox := AsSandbox(stale, provider)

	_, err = sandbox.acquireNetworkOperation(t.Context())
	require.Error(t, err)
	assert.True(t, errors.Is(err, infra.ErrNetworkPolicyConflict))

	require.NoError(t, sandbox.persistNetworkMetadata(t.Context(), infra.SandboxNetworkConfig{AllowInternetAccess: true}, operation.ID))
	require.NoError(t, sandbox.releaseNetworkOperation(t.Context(), operation.ID))
	fresh := &agentsv1alpha1.Sandbox{}
	require.NoError(t, fc.Get(t.Context(), ctrlclient.ObjectKeyFromObject(live), fresh))
	assert.Empty(t, fresh.Annotations[agentsv1alpha1.AnnotationE2BNetworkOperation])
	assert.NotEmpty(t, fresh.Annotations[agentsv1alpha1.AnnotationE2BNetworkConfigHash])
}

func TestTriggerRecycleClearsAndBlocksNetworkUpdates(t *testing.T) {
	infraInstance, fc := NewTestInfra(t)
	sbx := createTestSandbox("network-recycle", "test-user", agentsv1alpha1.SandboxRunning, true)
	sbx.Spec.Template = &corev1.PodTemplateSpec{}
	CreateSandboxWithStatus(t, fc, sbx)

	var sandbox infra.Sandbox
	require.Eventually(t, func() bool {
		var err error
		sandbox, err = infraInstance.GetSandbox(t.Context(), infra.GetSandboxOptions{
			SandboxID: utils.GetSandboxID(sbx),
			Namespace: sbx.Namespace,
		})
		return err == nil
	}, time.Second, 10*time.Millisecond)
	require.NoError(t, sandbox.UpdateNetworkPolicy(t.Context(), infra.SandboxNetworkConfig{
		AllowInternetAccess: true,
		DenyOut:             []string{"10.0.0.0/8"},
	}))
	require.NoError(t, sandbox.TriggerRecycle(t.Context()))

	concrete := sandbox.(*Sandbox)
	policies, err := concrete.listNetworkTrafficPolicies(t.Context())
	require.NoError(t, err)
	assert.Empty(t, policies)
	fresh := &agentsv1alpha1.Sandbox{}
	require.NoError(t, fc.Get(t.Context(), ctrlclient.ObjectKeyFromObject(sbx), fresh))
	assert.Equal(t, agentsv1alpha1.True, fresh.Annotations[agentsv1alpha1.AnnotationCleanup])

	err = sandbox.UpdateNetworkPolicy(t.Context(), infra.SandboxNetworkConfig{AllowInternetAccess: true})
	require.Error(t, err)
	assert.True(t, errors.Is(err, infra.ErrNetworkPolicyConflict))
}
