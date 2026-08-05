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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"k8s.io/klog/v2"

	managererrors "github.com/openkruise/agents/pkg/sandbox-manager/errors"
	"github.com/openkruise/agents/pkg/sandbox-manager/infra"
	"github.com/openkruise/agents/pkg/servers/e2b/models"
	"github.com/openkruise/agents/pkg/servers/web"
	"github.com/openkruise/agents/pkg/utils/network"
)

// maxNetworkEntriesPerList caps entries per allowOut/denyOut list to prevent
// oversized TrafficPolicy CRs from exhausting apiserver resources.
const maxNetworkEntriesPerList = 20

func buildSandboxNetworkConfig(allowInternetAccess *bool, netConfig *models.SandboxNetworkConfig) infra.SandboxNetworkConfig {
	config := infra.SandboxNetworkConfig{AllowInternetAccess: true}
	if allowInternetAccess != nil {
		config.AllowInternetAccess = *allowInternetAccess
	}
	if netConfig != nil {
		config.AllowOut = netConfig.AllowOut
		config.DenyOut = netConfig.DenyOut
	}
	return config
}

// validateAllowOut checks that allowOut entries are valid CIDR, IP, or FQDN.
// Wildcard domains are not supported.
func validateAllowOut(allowOut []string) error {
	if len(allowOut) > maxNetworkEntriesPerList {
		return fmt.Errorf("allowOut list exceeds maximum of %d entries", maxNetworkEntriesPerList)
	}
	for _, entry := range allowOut {
		if strings.Contains(entry, "*") {
			return fmt.Errorf("invalid allowOut entry: %q wildcard domains are not supported, use a concrete domain instead", entry)
		}
		if !network.IsCIDROrIP(entry) && !network.IsFQDN(entry) {
			return fmt.Errorf("invalid allowOut entry: %q is not a valid CIDR, IP, or domain", entry)
		}
	}
	return nil
}

// validateDenyOut checks that all denyOut entries are valid CIDR or bare IP addresses.
func validateDenyOut(denyOut []string) error {
	if len(denyOut) > maxNetworkEntriesPerList {
		return fmt.Errorf("denyOut list exceeds maximum of %d entries", maxNetworkEntriesPerList)
	}
	for _, entry := range denyOut {
		if !network.IsCIDROrIP(entry) {
			return fmt.Errorf("domains are not supported in denyOut: %q is not a valid CIDR or IP address", entry)
		}
	}
	return nil
}

func deduplicateNetworkEntries(entries []string) []string {
	if len(entries) < 2 {
		return entries
	}
	seen := make(map[string]struct{}, len(entries))
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		if _, exists := seen[entry]; exists {
			continue
		}
		seen[entry] = struct{}{}
		result = append(result, entry)
	}
	return result
}

// validateAndBuildNetworkConfig is the single entry point for validating raw
// network parameters and producing a normalized SandboxNetworkConfig ready for CR creation.
func validateAndBuildNetworkConfig(netConfig *models.SandboxNetworkConfig) (*models.SandboxNetworkConfig, error) {
	// Step 1: Return nil if no network rules are needed
	if netConfig == nil || (len(netConfig.AllowOut) == 0 && len(netConfig.DenyOut) == 0) {
		return nil, nil
	}

	normalized := &models.SandboxNetworkConfig{
		AllowOut: deduplicateNetworkEntries(netConfig.AllowOut),
		DenyOut:  deduplicateNetworkEntries(netConfig.DenyOut),
	}

	// Validate allowOut — entries must be CIDR, IP, or FQDN.
	if err := validateAllowOut(normalized.AllowOut); err != nil {
		return nil, err
	}

	// Validate denyOut — domains are not supported in deny lists.
	if err := validateDenyOut(normalized.DenyOut); err != nil {
		return nil, err
	}

	return normalized, nil
}

// UpdateSandboxNetwork replaces the sandbox's network rules with the new configuration.
func (sc *Controller) UpdateSandboxNetwork(r *http.Request) (web.ApiResponse[struct{}], *web.ApiError) {
	ctx := r.Context()
	log := klog.FromContext(ctx)
	sandboxID := r.PathValue("sandboxID")

	var req models.SandboxNetworkUpdateConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return web.ApiResponse[struct{}]{}, &web.ApiError{
			Code:    http.StatusBadRequest,
			Message: fmt.Sprintf("Failed to decode request body: %v", err),
		}
	}

	// Validate and build the network config in one step.
	netConfig, err := validateAndBuildNetworkConfig(&models.SandboxNetworkConfig{
		AllowOut: req.AllowOut,
		DenyOut:  req.DenyOut,
	})
	if err != nil {
		return web.ApiResponse[struct{}]{}, &web.ApiError{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		}
	}

	sbx, apiErr := sc.getSandboxOfUser(ctx, sandboxID, liveSandboxStates)
	if apiErr != nil {
		return web.ApiResponse[struct{}]{}, apiErr
	}

	cfg := buildSandboxNetworkConfig(req.AllowInternetAccess, netConfig)
	if err := sc.manager.UpdateSandboxNetwork(ctx, sbx, cfg); err != nil {
		log.Error(err, "failed to reconcile network CRs")
		return web.ApiResponse[struct{}]{}, &web.ApiError{
			Code:    mapManagerErrorStatus(err),
			Message: fmt.Sprintf("Failed to update network: %v", err),
		}
	}

	log.Info("sandbox network updated", "sandboxID", sandboxID)
	return web.ApiResponse[struct{}]{
		Code: http.StatusNoContent,
	}, nil
}

func mapManagerErrorStatus(err error) int {
	switch managererrors.GetErrCode(err) {
	case managererrors.ErrorUnavailable:
		return http.StatusServiceUnavailable
	case managererrors.ErrorConflict:
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
