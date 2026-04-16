package filter

import (
	"fmt"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/sandbox-gateway/registry"
	"github.com/openkruise/agents/pkg/servers/e2b/adapters"
)

var logger *zap.Logger

func init() {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	logger, _ = config.Build()
}

func FilterFactory(c interface{}, callbacks api.FilterCallbackHandler) api.StreamFilter {
	cfg := c.(*FilterConfig)
	return &sandboxFilter{
		callbacks: callbacks,
		config:    cfg.Config,
		adapter:   cfg.Adapter,
	}
}

type sandboxFilter struct {
	api.PassThroughStreamFilter
	callbacks api.FilterCallbackHandler
	config    *Config
	adapter   adapters.E2BMapper
}

func (f *sandboxFilter) DecodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
	// Extract request info for the adapter
	authority := header.Host()
	path := header.Path()
	scheme := header.Scheme()

	// Build headers map from the request for the adapter
	headers := make(map[string]string)
	header.Range(func(key, value string) bool {
		headers[key] = value
		return true
	})

	// Use the unified adapter to extract sandbox ID and port
	sandboxID, sandboxPort, extraHeaders, err := f.adapter.Map(scheme, authority, path, 0, headers)
	if err != nil {
		logger.Debug("Adapter could not extract sandbox info, continuing",
			zap.String("authority", authority),
			zap.String("path", path),
			zap.Error(err))
		return api.Continue
	}

	logger.Debug("DecodeHeaders: adapter mapped request",
		zap.String("sandboxID", sandboxID),
		zap.Int("sandboxPort", sandboxPort),
		zap.Any("extraHeaders", extraHeaders))

	// Look up the pod IP from registry
	route, ok := registry.GetRegistry().Get(sandboxID)
	if !ok {
		logger.Warn("Sandbox not found in registry", zap.String("sandboxID", sandboxID))
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(
			502,
			"sandbox not found: "+sandboxID,
			nil,
			-1,
			"sandbox_not_found",
		)
		return api.LocalReply
	}

	if route.State != agentsv1alpha1.SandboxStateRunning {
		logger.Warn("Sandbox is not running", zap.String("sandboxID", sandboxID), zap.String("state", route.State))
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(
			502,
			"healthy sandbox not found: "+sandboxID,
			nil,
			-1,
			"sandbox_not_running",
		)
		return api.LocalReply
	}

	// Apply extra headers from the adapter (e.g., :path rewrite for kruise custom protocol)
	for k, v := range extraHeaders {
		header.Set(k, v)
	}

	upstreamHost := fmt.Sprintf("%s:%d", route.IP, sandboxPort)
	f.callbacks.StreamInfo().DynamicMetadata().Set("envoy.lb.original_dst", "host", upstreamHost)

	logger.Debug("Upstream override set successfully", zap.String("upstreamHost", upstreamHost))
	return api.Continue
}
