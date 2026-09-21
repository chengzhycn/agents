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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"k8s.io/klog/v2"
)

func TestSetLevel(t *testing.T) {
	t.Cleanup(func() {
		environmentLevelSet = false
		require.NoError(t, setLevel("info"))
	})
	environmentLevelSet = false

	tests := []struct {
		name          string
		value         string
		wantLevel     zapcore.Level
		wantVerbosity string
		wantV5Enabled bool
		wantV6Enabled bool
		wantError     bool
	}{
		{name: "debug", value: "debug", wantLevel: zapcore.Level(-debugLogVerbosity), wantVerbosity: "6", wantV5Enabled: true, wantV6Enabled: true},
		{name: "info", value: "info", wantLevel: zapcore.InfoLevel, wantVerbosity: "0"},
		{name: "warn", value: "warn", wantLevel: zapcore.WarnLevel, wantVerbosity: "0"},
		{name: "error", value: "error", wantLevel: zapcore.ErrorLevel, wantVerbosity: "0"},
		{name: "case and whitespace", value: " DEBUG ", wantLevel: zapcore.Level(-debugLogVerbosity), wantVerbosity: "6", wantV5Enabled: true, wantV6Enabled: true},
		{name: "invalid", value: "trace", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetLevel(tt.value)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantLevel, level.Level())
			assert.Equal(t, tt.wantVerbosity, klogFlags.Lookup("v").Value.String())
			assert.Equal(t, tt.wantV5Enabled, Logr().V(5).Enabled())
			assert.Equal(t, tt.wantV6Enabled, Logr().V(6).Enabled())
			assert.Equal(t, tt.wantV5Enabled, klog.V(5).Enabled())
			assert.Equal(t, tt.wantV6Enabled, klog.V(6).Enabled())
		})
	}
}

func TestSetLevelEnvironmentOverride(t *testing.T) {
	t.Cleanup(func() {
		environmentLevelSet = false
		require.NoError(t, setLevel("info"))
	})
	environmentLevelSet = true
	require.NoError(t, setLevel("warn"))
	require.NoError(t, SetLevel("debug"))
	assert.Equal(t, zapcore.WarnLevel, level.Level())
}

func TestWriteKlogBuffer(t *testing.T) {
	original := rawLogger
	core, observed := observer.New(zapcore.DebugLevel)
	rawLogger = zap.New(core)
	t.Cleanup(func() {
		rawLogger = original
	})

	writeKlogBuffer([]byte("I0921 info"))
	writeKlogBuffer([]byte("W0921 warning"))
	writeKlogBuffer([]byte("E0921 error"))

	entries := observed.All()
	require.Len(t, entries, 3)
	assert.Equal(t, zapcore.InfoLevel, entries[0].Level)
	assert.Equal(t, zapcore.WarnLevel, entries[1].Level)
	assert.Equal(t, zapcore.ErrorLevel, entries[2].Level)
}

func TestMemberlistWriter(t *testing.T) {
	core, observed := observer.New(zapcore.Level(-debugLogVerbosity))
	writer := &memberlistWriter{logger: zap.New(core)}

	_, err := writer.Write([]byte("[DEBUG] memberlist: probing\n[INFO] memberlist: joined\n[WARN] memberlist: suspect\n[ERR] memberlist: failed\nErr: Could not set the deadline\n"))
	require.NoError(t, err)

	entries := observed.All()
	require.Len(t, entries, 5)
	assert.Equal(t, zapcore.DebugLevel, entries[0].Level)
	assert.Equal(t, "probing", entries[0].Message)
	assert.Equal(t, zapcore.InfoLevel, entries[1].Level)
	assert.Equal(t, zapcore.WarnLevel, entries[2].Level)
	assert.Equal(t, zapcore.ErrorLevel, entries[3].Level)
	assert.Equal(t, zapcore.ErrorLevel, entries[4].Level)
	for _, entry := range entries {
		assert.Equal(t, "memberlist", entry.ContextMap()["component"])
	}
}
