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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/sandbox-manager/infra"
	"github.com/openkruise/agents/pkg/utils/expectations"
	"github.com/openkruise/agents/pkg/utils/network"
)

const (
	e2bPerSandboxTrafficPolicyPriority int32 = 100
	e2bGlobalDenyFallbackName                = "e2b-deny-internet"
)

// sandboxOwnerRef returns an OwnerReference that points to the given Sandbox CR.
// Setting this on TrafficPolicy CRs ensures they are garbage-collected
// when the owning Sandbox is deleted (including timeout-driven deletion by the controller).
func sandboxOwnerRef(owner *agentsv1alpha1.Sandbox) metav1.OwnerReference {
	controller := true
	blockOwnerDeletion := false
	return metav1.OwnerReference{
		APIVersion:         agentsv1alpha1.GroupVersion.String(),
		Kind:               "Sandbox",
		Name:               owner.Name,
		UID:                owner.UID,
		Controller:         &controller,
		BlockOwnerDeletion: &blockOwnerDeletion,
	}
}

// buildTrafficPolicy builds a TrafficPolicy CR that encodes both CIDR/IP and
// domain rules. Domain entries use the FQDN peer field
func buildTrafficPolicy(allowInternetAccess bool, allowOutCIDRs, allowOutDomains, denyOut []string, namespace, sandboxID string, sandbox *agentsv1alpha1.Sandbox) *agentsv1alpha1.TrafficPolicy {
	if len(allowOutCIDRs) == 0 && len(allowOutDomains) == 0 && len(denyOut) == 0 {
		return nil
	}

	hasAllowOut := len(allowOutCIDRs) > 0 || len(allowOutDomains) > 0
	hasIPv4AllowAll := false
	rules := make([]agentsv1alpha1.TrafficPolicyRule, 0, 3)

	if hasAllowOut {
		// Allow entries precede rejects so explicit exceptions win on overlap.
		allowPeers := make([]agentsv1alpha1.TrafficPolicyPeer, 0, len(allowOutCIDRs)+len(allowOutDomains))
		for _, cidr := range allowOutCIDRs {
			allowPeers = append(allowPeers, agentsv1alpha1.TrafficPolicyPeer{CIDR: cidr})
			hasIPv4AllowAll = hasIPv4AllowAll || cidr == "0.0.0.0/0"
		}
		for _, fqdn := range allowOutDomains {
			allowPeers = append(allowPeers, agentsv1alpha1.TrafficPolicyPeer{FQDN: fqdn})
		}
		rules = append(rules, agentsv1alpha1.TrafficPolicyRule{
			Action: agentsv1alpha1.RuleActionAllow,
			To:     allowPeers,
		})
	}

	denyAll := false
	if len(denyOut) > 0 {
		denyPeers := make([]agentsv1alpha1.TrafficPolicyPeer, 0, len(denyOut))
		for _, entry := range denyOut {
			normalized := network.NormalizeToCIDR(entry)
			denyPeers = append(denyPeers, agentsv1alpha1.TrafficPolicyPeer{CIDR: normalized})
			denyAll = denyAll || normalized == "0.0.0.0/0"
		}
		rules = append(rules, agentsv1alpha1.TrafficPolicyRule{
			Action: agentsv1alpha1.RuleActionReject,
			To:     denyPeers,
		})
	}
	if allowInternetAccess && !denyAll && !hasIPv4AllowAll {
		rules = append(rules, agentsv1alpha1.TrafficPolicyRule{
			Action: agentsv1alpha1.RuleActionAllow,
			To: []agentsv1alpha1.TrafficPolicyPeer{
				{CIDR: "0.0.0.0/0"},
			},
		})
	}

	return &agentsv1alpha1.TrafficPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2b-" + sandbox.Name,
			Namespace: namespace,
			Annotations: map[string]string{
				agentsv1alpha1.AnnotationSandboxID: sandboxID,
			},
			OwnerReferences: []metav1.OwnerReference{sandboxOwnerRef(sandbox)},
		},
		Spec: agentsv1alpha1.TrafficPolicySpec{
			Priority: e2bPerSandboxTrafficPolicyPriority,
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					agentsv1alpha1.LabelSandboxName: sandbox.Name,
				},
			},
			Egress: &agentsv1alpha1.TrafficPolicyDirection{
				Rules: rules,
			},
		},
	}
}

func isGlobalDenyFallback(policy *agentsv1alpha1.GlobalTrafficPolicy) bool {
	if !policy.DeletionTimestamp.IsZero() ||
		policy.Name != e2bGlobalDenyFallbackName ||
		policy.Spec.Priority != 900 ||
		len(policy.Spec.Selector.MatchLabels) != 1 ||
		policy.Spec.Selector.MatchLabels[agentsv1alpha1.LabelAllowInternetAccess] != agentsv1alpha1.False ||
		len(policy.Spec.Selector.MatchExpressions) != 0 ||
		policy.Spec.Ingress != nil ||
		policy.Spec.Egress == nil ||
		len(policy.Spec.Egress.Rules) != 1 {
		return false
	}
	rule := policy.Spec.Egress.Rules[0]
	return rule.Action == agentsv1alpha1.RuleActionReject &&
		len(rule.From) == 0 &&
		len(rule.Ports) == 0 &&
		len(rule.To) == 1 &&
		rule.To[0].CIDR == "0.0.0.0/0" &&
		rule.To[0].FQDN == "" &&
		rule.To[0].Service == nil &&
		rule.To[0].Workload == nil
}

func validateGlobalDenyFallback(ctx context.Context, reader client.Reader) error {
	policies := &agentsv1alpha1.GlobalTrafficPolicyList{}
	if err := reader.List(ctx, policies); err != nil {
		return fmt.Errorf("%w: failed to list GlobalTrafficPolicies: %v", infra.ErrNetworkPolicyUnavailable, err)
	}
	for i := range policies.Items {
		if isGlobalDenyFallback(&policies.Items[i]) {
			return nil
		}
	}
	return fmt.Errorf("%w: expected priority 900 reject-all policy selecting %s=false", infra.ErrNetworkPolicyUnavailable, agentsv1alpha1.LabelAllowInternetAccess)
}

// ValidateNetworkPolicy verifies cluster capabilities before a sandbox is claimed or cloned.
func (i *Infra) ValidateNetworkPolicy(ctx context.Context, config infra.SandboxNetworkConfig) error {
	if config.AllowInternetAccess {
		return nil
	}
	return validateGlobalDenyFallback(ctx, i.APIReader)
}

func (s *Sandbox) ensureGlobalDenyFallback(ctx context.Context) error {
	return validateGlobalDenyFallback(ctx, s.Cache.GetAPIReader())
}

func desiredNetworkMetadata(config infra.SandboxNetworkConfig) (string, string, error) {
	raw, err := json.Marshal(config)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal desired network state: %w", err)
	}
	sum := sha256.Sum256(raw)
	return string(raw), hex.EncodeToString(sum[:]), nil
}

func (s *Sandbox) retryNetworkUpdate(ctx context.Context, modifier ModifierFunc) (bool, error) {
	updated := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest := &agentsv1alpha1.Sandbox{}
		if err := s.Cache.GetAPIReader().Get(ctx, client.ObjectKeyFromObject(s.Sandbox), latest); err != nil {
			return err
		}
		copied := latest.DeepCopy()
		shouldUpdate, err := modifier(copied)
		if err != nil {
			return err
		}
		if !shouldUpdate {
			s.Sandbox = latest
			updated = false
			return nil
		}
		if err := s.Cache.GetClient().Update(ctx, copied); err != nil {
			return err
		}
		s.Sandbox = copied
		expectations.ResourceVersionExpectationExpect(copied)
		updated = true
		return nil
	})
	return updated, err
}

func (s *Sandbox) persistNetworkMetadata(ctx context.Context, config infra.SandboxNetworkConfig, operationID string) error {
	raw, hash, err := desiredNetworkMetadata(config)
	if err != nil {
		return err
	}
	value := agentsv1alpha1.True
	if !config.AllowInternetAccess {
		value = agentsv1alpha1.False
	}
	_, err = s.retryNetworkUpdate(ctx, func(latest *agentsv1alpha1.Sandbox) (bool, error) {
		if currentNetworkOperationID(latest.Annotations[agentsv1alpha1.AnnotationE2BNetworkOperation]) != operationID {
			return false, fmt.Errorf("%w: network operation ownership changed", infra.ErrNetworkPolicyConflict)
		}
		changed := false
		if latest.Labels == nil {
			latest.Labels = map[string]string{}
		}
		if latest.Labels[agentsv1alpha1.LabelAllowInternetAccess] != value {
			latest.Labels[agentsv1alpha1.LabelAllowInternetAccess] = value
			changed = true
		}
		if latest.Spec.Template != nil {
			if latest.Spec.Template.Labels == nil {
				latest.Spec.Template.Labels = map[string]string{}
			}
			if latest.Spec.Template.Labels[agentsv1alpha1.LabelAllowInternetAccess] != value {
				latest.Spec.Template.Labels[agentsv1alpha1.LabelAllowInternetAccess] = value
				changed = true
			}
		}
		if latest.Annotations == nil {
			latest.Annotations = map[string]string{}
		}
		if latest.Annotations[agentsv1alpha1.AnnotationE2BNetworkConfig] != raw {
			latest.Annotations[agentsv1alpha1.AnnotationE2BNetworkConfig] = raw
			changed = true
		}
		if latest.Annotations[agentsv1alpha1.AnnotationE2BNetworkConfigHash] != hash {
			latest.Annotations[agentsv1alpha1.AnnotationE2BNetworkConfigHash] = hash
			changed = true
		}
		return changed, nil
	})
	if err != nil {
		return fmt.Errorf("failed to persist sandbox network metadata: %w", err)
	}
	return nil
}

func (s *Sandbox) listNetworkTrafficPolicies(ctx context.Context) ([]agentsv1alpha1.TrafficPolicy, error) {
	all := &agentsv1alpha1.TrafficPolicyList{}
	if err := s.Cache.GetAPIReader().List(ctx, all, client.InNamespace(s.GetNamespace())); err != nil {
		return nil, fmt.Errorf("failed to list TrafficPolicies: %w", err)
	}
	sandboxID := s.GetSandboxID()
	policies := make([]agentsv1alpha1.TrafficPolicy, 0, 1)
	for i := range all.Items {
		if all.Items[i].Annotations[agentsv1alpha1.AnnotationSandboxID] == sandboxID {
			policies = append(policies, *all.Items[i].DeepCopy())
		}
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].Name < policies[j].Name })
	return policies, nil
}

type networkOperation struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func currentNetworkOperationID(raw string) string {
	operation := networkOperation{}
	if json.Unmarshal([]byte(raw), &operation) != nil {
		return ""
	}
	return operation.ID
}

func (s *Sandbox) ensureNetworkOperation(ctx context.Context, operationID string) error {
	if err := s.refreshFromAPIReader(ctx); err != nil {
		return fmt.Errorf("failed to verify sandbox network operation: %w", err)
	}
	if currentNetworkOperationID(s.GetAnnotations()[agentsv1alpha1.AnnotationE2BNetworkOperation]) != operationID {
		return fmt.Errorf("%w: network operation ownership changed", infra.ErrNetworkPolicyConflict)
	}
	return nil
}

func (s *Sandbox) acquireNetworkOperation(ctx context.Context) (string, error) {
	operation := networkOperation{
		ID:        uuid.NewString(),
		ExpiresAt: time.Now().Add(2 * DefaultCleanupTimeout),
	}
	raw, err := json.Marshal(operation)
	if err != nil {
		return "", fmt.Errorf("failed to marshal network operation: %w", err)
	}
	_, err = s.retryNetworkUpdate(ctx, func(latest *agentsv1alpha1.Sandbox) (bool, error) {
		if latest.Annotations == nil {
			latest.Annotations = map[string]string{}
		}
		if latest.Annotations[agentsv1alpha1.AnnotationCleanup] == agentsv1alpha1.True {
			return false, fmt.Errorf("%w: sandbox is recycling", infra.ErrNetworkPolicyConflict)
		}
		if currentRaw := latest.Annotations[agentsv1alpha1.AnnotationE2BNetworkOperation]; currentRaw != "" {
			current := networkOperation{}
			if json.Unmarshal([]byte(currentRaw), &current) == nil && time.Now().Before(current.ExpiresAt) {
				return false, fmt.Errorf("%w: operation %s is still active", infra.ErrNetworkPolicyConflict, current.ID)
			}
		}
		latest.Annotations[agentsv1alpha1.AnnotationE2BNetworkOperation] = string(raw)
		return true, nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to acquire sandbox network operation: %w", err)
	}
	return operation.ID, nil
}

func (s *Sandbox) releaseNetworkOperation(ctx context.Context, operationID string) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), DefaultCleanupTimeout)
	defer cancel()
	_, err := s.retryNetworkUpdate(cleanupCtx, func(latest *agentsv1alpha1.Sandbox) (bool, error) {
		currentRaw := latest.Annotations[agentsv1alpha1.AnnotationE2BNetworkOperation]
		if currentRaw == "" {
			return false, nil
		}
		current := networkOperation{}
		if json.Unmarshal([]byte(currentRaw), &current) != nil || current.ID != operationID {
			return false, nil
		}
		delete(latest.Annotations, agentsv1alpha1.AnnotationE2BNetworkOperation)
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("failed to release sandbox network operation: %w", err)
	}
	return nil
}

// CreateNetworkPolicy creates a TrafficPolicy CR for the sandbox.
func (s *Sandbox) CreateNetworkPolicy(ctx context.Context, netConfig infra.SandboxNetworkConfig) error {
	return s.UpdateNetworkPolicy(ctx, netConfig)
}

func (s *Sandbox) upsertNetworkTrafficPolicy(ctx context.Context, desired *agentsv1alpha1.TrafficPolicy, existingItems []agentsv1alpha1.TrafficPolicy, desiredHash, operationID string) (string, func() error, error) {
	if err := s.ensureNetworkOperation(ctx, operationID); err != nil {
		return "", nil, err
	}
	k8sClient := s.Cache.GetClient()
	desired.Annotations[agentsv1alpha1.AnnotationE2BNetworkConfigHash] = desiredHash
	desired.Annotations[agentsv1alpha1.AnnotationE2BNetworkOperation] = operationID
	if len(existingItems) > 0 {
		existing := &existingItems[0]
		base := existing.DeepCopy()
		existing.Spec = desired.Spec
		existing.OwnerReferences = desired.OwnerReferences
		if existing.Annotations == nil {
			existing.Annotations = map[string]string{}
		}
		for key, value := range desired.Annotations {
			existing.Annotations[key] = value
		}
		if apiequality.Semantic.DeepEqual(base.Spec, existing.Spec) &&
			apiequality.Semantic.DeepEqual(base.OwnerReferences, existing.OwnerReferences) &&
			apiequality.Semantic.DeepEqual(base.Annotations, existing.Annotations) {
			return existing.Name, func() error { return nil }, nil
		}
		if err := k8sClient.Patch(ctx, existing, client.MergeFrom(base)); err != nil {
			return "", nil, fmt.Errorf("failed to update TrafficPolicy %s: %w", existing.Name, err)
		}
		rollback := func() error {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), DefaultCleanupTimeout)
			defer cancel()
			current := &agentsv1alpha1.TrafficPolicy{}
			if err := s.Cache.GetAPIReader().Get(cleanupCtx, client.ObjectKeyFromObject(existing), current); err != nil {
				return client.IgnoreNotFound(err)
			}
			if current.Annotations[agentsv1alpha1.AnnotationE2BNetworkOperation] != operationID {
				return nil
			}
			current.Spec = base.Spec
			current.OwnerReferences = base.OwnerReferences
			current.Annotations = base.Annotations
			return k8sClient.Update(cleanupCtx, current)
		}
		return existing.Name, rollback, nil
	}

	if err := k8sClient.Create(ctx, desired); err == nil {
		rollback := func() error {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), DefaultCleanupTimeout)
			defer cancel()
			current := &agentsv1alpha1.TrafficPolicy{}
			if err := s.Cache.GetAPIReader().Get(cleanupCtx, client.ObjectKeyFromObject(desired), current); err != nil {
				return client.IgnoreNotFound(err)
			}
			if current.Annotations[agentsv1alpha1.AnnotationE2BNetworkOperation] != operationID {
				return nil
			}
			return client.IgnoreNotFound(k8sClient.Delete(cleanupCtx, current))
		}
		return desired.Name, rollback, nil
	} else if !apierrors.IsAlreadyExists(err) {
		return "", nil, fmt.Errorf("failed to create TrafficPolicy: %w", err)
	}

	existing := &agentsv1alpha1.TrafficPolicy{}
	if err := s.Cache.GetAPIReader().Get(ctx, client.ObjectKeyFromObject(desired), existing); err != nil {
		return "", nil, fmt.Errorf("failed to read existing TrafficPolicy %s after create conflict: %w", desired.Name, err)
	}
	return s.upsertNetworkTrafficPolicy(ctx, desired, []agentsv1alpha1.TrafficPolicy{*existing}, desiredHash, operationID)
}

func (s *Sandbox) deleteNetworkTrafficPolicies(ctx context.Context, keepName, operationID string) error {
	if err := s.ensureNetworkOperation(ctx, operationID); err != nil {
		return err
	}
	items, err := s.listNetworkTrafficPolicies(ctx)
	if err != nil {
		return err
	}
	for i := range items {
		if items[i].Name == keepName {
			continue
		}
		if err := client.IgnoreNotFound(s.Cache.GetClient().Delete(ctx, &items[i])); err != nil {
			return fmt.Errorf("failed to delete TrafficPolicy %s: %w", items[i].Name, err)
		}
	}
	return nil
}

func (s *Sandbox) verifyNetworkStateHash(ctx context.Context, activePolicyName, desiredHash, operationID string) error {
	if err := s.refreshFromAPIReader(ctx); err != nil {
		return fmt.Errorf("failed to verify Sandbox network state: %w", err)
	}
	if s.GetAnnotations()[agentsv1alpha1.AnnotationE2BNetworkConfigHash] != desiredHash {
		return fmt.Errorf("%w: Sandbox desired hash changed", infra.ErrNetworkPolicyConflict)
	}
	if currentNetworkOperationID(s.GetAnnotations()[agentsv1alpha1.AnnotationE2BNetworkOperation]) != operationID {
		return fmt.Errorf("%w: network operation ownership changed", infra.ErrNetworkPolicyConflict)
	}
	if activePolicyName == "" {
		items, err := s.listNetworkTrafficPolicies(ctx)
		if err != nil {
			return err
		}
		if len(items) != 0 {
			return fmt.Errorf("%w: expected no local TrafficPolicy", infra.ErrNetworkPolicyConflict)
		}
		return nil
	}
	policy := &agentsv1alpha1.TrafficPolicy{}
	if err := s.Cache.GetAPIReader().Get(ctx, client.ObjectKey{Namespace: s.GetNamespace(), Name: activePolicyName}, policy); err != nil {
		return fmt.Errorf("failed to verify TrafficPolicy %s: %w", activePolicyName, err)
	}
	if policy.Annotations[agentsv1alpha1.AnnotationE2BNetworkConfigHash] != desiredHash {
		return fmt.Errorf("%w: TrafficPolicy desired hash changed", infra.ErrNetworkPolicyConflict)
	}
	return nil
}

// UpdateNetworkPolicy updates the TrafficPolicy CR for the sandbox.
func (s *Sandbox) UpdateNetworkPolicy(ctx context.Context, netConfig infra.SandboxNetworkConfig) (err error) {
	operationCtx, cancel := context.WithTimeout(ctx, DefaultCleanupTimeout)
	defer cancel()
	operationID, err := s.acquireNetworkOperation(operationCtx)
	if err != nil {
		return err
	}
	defer func() {
		if releaseErr := s.releaseNetworkOperation(ctx, operationID); releaseErr != nil {
			err = errors.Join(err, releaseErr)
		}
	}()
	return s.updateNetworkPolicyLocked(operationCtx, netConfig, operationID)
}

func (s *Sandbox) updateNetworkPolicyLocked(ctx context.Context, netConfig infra.SandboxNetworkConfig, operationID string) error {
	log := klog.FromContext(ctx).WithValues("sandbox", klog.KObj(s))
	sandboxID := s.GetSandboxID()
	namespace := s.GetNamespace()

	if !netConfig.AllowInternetAccess {
		if err := s.ensureGlobalDenyFallback(ctx); err != nil {
			return err
		}
	}
	allowCIDRs, allowDomains := network.SplitAllowOut(netConfig.AllowOut)

	// --- Reconcile TrafficPolicy ---
	tpItems, err := s.listNetworkTrafficPolicies(ctx)
	if err != nil {
		return err
	}

	newTP := buildTrafficPolicy(netConfig.AllowInternetAccess, allowCIDRs, allowDomains, netConfig.DenyOut, namespace, sandboxID, s.Sandbox)
	_, desiredHash, err := desiredNetworkMetadata(netConfig)
	if err != nil {
		return err
	}

	if newTP == nil {
		var rollback func() error
		if !netConfig.AllowInternetAccess {
			// Replace any permissive local policy before binding the lower-priority GTP.
			staging := buildTrafficPolicy(false, nil, nil, []string{"0.0.0.0/0"}, namespace, sandboxID, s.Sandbox)
			if _, rollback, err = s.upsertNetworkTrafficPolicy(ctx, staging, tpItems, desiredHash, operationID); err != nil {
				return err
			}
		}
		if err := s.persistNetworkMetadata(ctx, netConfig, operationID); err != nil {
			if rollback != nil {
				if rollbackErr := rollback(); rollbackErr != nil {
					return fmt.Errorf("%w; failed to roll back staging TrafficPolicy: %v", err, rollbackErr)
				}
			}
			return err
		}
		if !netConfig.AllowInternetAccess {
			if err := s.ensureGlobalDenyFallback(ctx); err != nil {
				// Keep reject-all staging when the shared fallback is disappearing.
				return err
			}
		}
		if err := s.deleteNetworkTrafficPolicies(ctx, "", operationID); err != nil {
			// A failed false transition intentionally leaves reject-all staging in place.
			return err
		}
		if err := s.verifyNetworkStateHash(ctx, "", desiredHash, operationID); err != nil {
			return err
		}
		log.Info("network CRs reconciled")
		return nil
	}

	policyToInstall := newTP
	if netConfig.AllowInternetAccess {
		// Do not install the final allow-all tail while the old false label still
		// selects the GTP. A restrictive local policy bridges the label switch.
		policyToInstall = buildTrafficPolicy(false, allowCIDRs, allowDomains, netConfig.DenyOut, namespace, sandboxID, s.Sandbox)
	}
	activeName, rollback, err := s.upsertNetworkTrafficPolicy(ctx, policyToInstall, tpItems, desiredHash, operationID)
	if err != nil {
		return err
	}
	if err := s.persistNetworkMetadata(ctx, netConfig, operationID); err != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			return fmt.Errorf("%w; failed to roll back TrafficPolicy: %v", err, rollbackErr)
		}
		return err
	}
	if netConfig.AllowInternetAccess && !apiequality.Semantic.DeepEqual(policyToInstall.Spec, newTP.Spec) {
		currentItems, listErr := s.listNetworkTrafficPolicies(ctx)
		if listErr != nil {
			return listErr
		}
		activeName, _, err = s.upsertNetworkTrafficPolicy(ctx, newTP, currentItems, desiredHash, operationID)
		if err != nil {
			// The restrictive staging policy remains active on failure.
			return err
		}
	}
	if err := s.deleteNetworkTrafficPolicies(ctx, activeName, operationID); err != nil {
		return err
	}
	if err := s.verifyNetworkStateHash(ctx, activeName, desiredHash, operationID); err != nil {
		return err
	}

	log.Info("network CRs reconciled")
	return nil
}

// SelectNetworkPolicy queries the existing TrafficPolicy CR and returns the
// all network configuration. Both CIDR and FQDN entries are read back
// from the single TrafficPolicy CR.
func (s *Sandbox) SelectNetworkPolicy(ctx context.Context) (*infra.SandboxNetworkConfig, error) {
	log := klog.FromContext(ctx).WithValues("sandbox", klog.KObj(s))
	if err := s.refreshFromAPIReader(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh Sandbox before reading network state: %w", err)
	}

	config := &infra.SandboxNetworkConfig{AllowInternetAccess: true}
	if value, ok := s.GetLabels()[agentsv1alpha1.LabelAllowInternetAccess]; ok {
		config.AllowInternetAccess = value != agentsv1alpha1.False
	}
	if raw := s.GetAnnotations()[agentsv1alpha1.AnnotationE2BNetworkConfig]; raw != "" {
		if err := json.Unmarshal([]byte(raw), config); err != nil {
			return nil, fmt.Errorf("failed to decode desired network state: %w", err)
		}
		return config, nil
	}

	// Read TrafficPolicy to extract allowOut (CIDRs + FQDNs) and denyOut (CIDRs)
	tpItems, err := s.listNetworkTrafficPolicies(ctx)
	if err != nil {
		return nil, err
	}
	if len(tpItems) == 0 {
		log.Info("no TrafficPolicy found; returning label-derived legacy network state")
		return config, nil
	}
	tp := &tpItems[0]
	if tp.Spec.Egress == nil {
		return config, nil
	}
	for _, rule := range tp.Spec.Egress.Rules {
		switch rule.Action {
		case agentsv1alpha1.RuleActionAllow:
			for _, peer := range rule.To {
				if peer.CIDR != "" {
					config.AllowOut = append(config.AllowOut, peer.CIDR)
				}
				if peer.FQDN != "" {
					config.AllowOut = append(config.AllowOut, peer.FQDN)
				}
			}
		case agentsv1alpha1.RuleActionReject:
			for _, peer := range rule.To {
				if peer.CIDR != "" {
					config.DenyOut = append(config.DenyOut, peer.CIDR)
				}
			}
		}
	}

	return config, nil
}
