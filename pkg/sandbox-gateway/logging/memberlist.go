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
	"log"
	"strings"

	"go.uber.org/zap"
)

type memberlistWriter struct {
	logger *zap.Logger
}

func MemberlistLogger() *log.Logger {
	return log.New(&memberlistWriter{logger: rawLogger}, "", 0)
}

func (w *memberlistWriter) Write(p []byte) (int, error) {
	for line := range strings.SplitSeq(string(p), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		message, severity := parseMemberlistLine(line)
		switch severity {
		case "error":
			w.logger.Error(message, zap.String("component", "memberlist"))
		case "warn":
			w.logger.Warn(message, zap.String("component", "memberlist"))
		case "info":
			w.logger.Info(message, zap.String("component", "memberlist"))
		default:
			w.logger.Debug(message, zap.String("component", "memberlist"))
		}
	}
	return len(p), nil
}

func parseMemberlistLine(line string) (string, string) {
	prefixes := []struct {
		prefix   string
		severity string
	}{
		{prefix: "[ERROR]", severity: "error"},
		{prefix: "[ERR]", severity: "error"},
		{prefix: "[WARN]", severity: "warn"},
		{prefix: "[INFO]", severity: "info"},
		{prefix: "[DEBUG]", severity: "debug"},
		{prefix: "Err:", severity: "error"},
	}
	for _, item := range prefixes {
		if strings.HasPrefix(line, item.prefix) {
			message := strings.TrimSpace(strings.TrimPrefix(line, item.prefix))
			message = strings.TrimSpace(strings.TrimPrefix(message, "memberlist:"))
			return message, item.severity
		}
	}
	return line, "debug"
}
