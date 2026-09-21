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

package logging

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const (
	EnvLogLevel       = "SANDBOX_GATEWAY_LOG_LEVEL"
	debugLogVerbosity = 6
	defaultLogLevel   = "info"
)

var (
	level     = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	rawLogger = ctrlzap.NewRaw(
		ctrlzap.Level(level),
		ctrlzap.RawZapOpts(zap.AddCaller()),
		ctrlzap.StacktraceLevel(zapcore.DPanicLevel),
	)
	logger              = zapr.NewLogger(rawLogger)
	klogFlags           = flag.NewFlagSet("sandbox-gateway-klog", flag.ContinueOnError)
	levelMu             sync.Mutex
	setupOnce           sync.Once
	environmentLevelSet bool
	setupLoggers        = func() {
		ctrl.SetLogger(logger)
		klog.SetLoggerWithOptions(
			logger,
			klog.ContextualLogger(true),
			klog.FlushLogger(func() { _ = rawLogger.Sync() }),
			klog.WriteKlogBuffer(writeKlogBuffer),
		)
	}
)

func init() {
	klog.InitFlags(klogFlags)
}

func Setup() error {
	configuredLevel := ""
	configuredLevel, environmentLevelSet = os.LookupEnv(EnvLogLevel)
	if !environmentLevelSet {
		configuredLevel = defaultLogLevel
	}
	if err := setLevel(configuredLevel); err != nil {
		return fmt.Errorf("configure gateway logging: %w", err)
	}
	setupOnce.Do(setupLoggers)
	return nil
}

func Logger() *zap.Logger {
	return rawLogger
}

func Logr() logr.Logger {
	return logger
}

func SetLevel(value string) error {
	if environmentLevelSet {
		return nil
	}
	return setLevel(value)
}

func setLevel(value string) error {
	parsed, err := parseLevel(value)
	if err != nil {
		return err
	}

	levelMu.Lock()
	defer levelMu.Unlock()

	verbosity := 0
	if parsed == zapcore.DebugLevel {
		parsed = zapcore.Level(-debugLogVerbosity)
		verbosity = debugLogVerbosity
	}
	if err := klogFlags.Set("v", strconv.Itoa(verbosity)); err != nil {
		return fmt.Errorf("set klog verbosity: %w", err)
	}
	level.SetLevel(parsed)
	return nil
}

func writeKlogBuffer(data []byte) {
	message := strings.TrimSpace(string(data))
	if message == "" {
		return
	}
	switch message[0] {
	case 'F', 'E':
		rawLogger.Error(message)
	case 'W':
		rawLogger.Warn(message)
	default:
		rawLogger.Info(message)
	}
}

func parseLevel(value string) (zapcore.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return zapcore.DebugLevel, nil
	case "info":
		return zapcore.InfoLevel, nil
	case "warn":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	default:
		return 0, fmt.Errorf("invalid log level %q: want debug, info, warn, or error", value)
	}
}
