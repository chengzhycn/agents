package filter

import (
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/sandbox-gateway/registry"
)

var logger *zap.Logger

func init() {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	logger, _ = config.Build()
}

func FilterFactory(c interface{}, callbacks api.FilterCallbackHandler) api.StreamFilter {
	cfg := c.(*Config)
	return &sandboxFilter{
		callbacks: callbacks,
		config:    cfg,
	}
}

type sandboxFilter struct {
	api.PassThroughStreamFilter
	callbacks api.FilterCallbackHandler
	config    *Config
}

func (f *sandboxFilter) DecodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
	// First, try to get sandbox ID from sandbox header
	sandboxHeaderName := f.config.GetSandboxHeaderName()
	sandboxID, _ := header.Get(sandboxHeaderName)
	var port string

	if sandboxID != "" {
		// Sandbox header found, get port from port header
		port, _ = header.Get(f.config.SandboxPortHeader)
		if port == "" {
			port = f.config.DefaultPort
			logger.Debug("Using default port for sandbox header mode", zap.String("port", port))
		}
		logger.Debug("DecodeHeaders: using sandbox header",
			zap.String("sandboxHeaderName", sandboxHeaderName),
			zap.String("sandboxID", sandboxID),
			zap.String("port", port))
	} else {
		// Sandbox header not found, try host header
		hostHeaderName := f.config.GetHostHeaderName()
		var hostValue string
		if hostHeaderName == DefaultHostHeaderName {
			hostValue = header.Host()
		} else {
			hostValue, _ = header.Get(hostHeaderName)
		}

		if hostValue == "" {
			logger.Debug("No sandbox header or host header found, continuing")
			return api.Continue
		}

		// Extract sandbox ID and port from host format: <port>-<namespace>--<name>.domain
		sandboxID, port = f.config.ExtractHostInfo(hostValue)
		if sandboxID == "" {
			logger.Debug("Host header doesn't match expected format, continuing", zap.String("hostValue", hostValue))
			// When parsing fails, continue to allow normal routing
			return api.Continue
		}
		if port == "" {
			port = f.config.DefaultPort
			logger.Debug("Using default port for host header mode", zap.String("port", port))
		}
		logger.Debug("DecodeHeaders: using host header",
			zap.String("hostHeaderName", hostHeaderName),
			zap.String("hostValue", hostValue),
			zap.String("sandboxID", sandboxID),
			zap.String("port", port))
	}

	// Look up the pod IP from registry
	route, ok := registry.GetRegistry().Get(sandboxID)
	if !ok {
		logger.Warn("Sandbox not found in registry", zap.String("sandboxID", sandboxID))
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(
			404,
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

	upstreamHost := route.IP + ":" + port
	f.callbacks.StreamInfo().DynamicMetadata().Set("envoy.lb.original_dst", "host", upstreamHost)

	logger.Debug("Upstream override set successfully", zap.String("upstreamHost", upstreamHost))
	return api.Continue
}
