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

package traffictoken

import (
	"context"
	"testing"
)

func TestNewRejectsUnsafeOrIncompleteConfig(t *testing.T) {
	valid := Config{
		ManagerURL:          "https://manager.example.test/base",
		Namespace:           "team-a",
		SandboxID:           "sandbox-id",
		BearerTokenProvider: func(context.Context) (string, error) { return "token", nil },
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "HTTP manager URL", mutate: func(config *Config) { config.ManagerURL = "http://manager.example.test" }},
		{name: "manager URL userinfo", mutate: func(config *Config) { config.ManagerURL = "https://user@manager.example.test" }},
		{name: "manager URL query", mutate: func(config *Config) { config.ManagerURL += "?key=value" }},
		{name: "manager URL fragment", mutate: func(config *Config) { config.ManagerURL += "#fragment" }},
		{name: "empty namespace", mutate: func(config *Config) { config.Namespace = "" }},
		{name: "empty sandbox ID", mutate: func(config *Config) { config.SandboxID = "" }},
		{name: "missing bearer provider", mutate: func(config *Config) { config.BearerTokenProvider = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := New(config); err == nil {
				t.Fatal("New() error = nil")
			}
		})
	}
}

func TestNewTransportRejectsNonOriginBinding(t *testing.T) {
	client, err := New(Config{
		ManagerURL:          "https://manager.example.test",
		Namespace:           "team-a",
		SandboxID:           "sandbox-id",
		BearerTokenProvider: func(context.Context) (string, error) { return "token", nil },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, origin := range []string{"gateway.example.test", "https://user@gateway.example.test", "https://gateway.example.test/path", "https://gateway.example.test?query=value"} {
		t.Run(origin, func(t *testing.T) {
			if _, err := client.NewTransport(origin, nil); err == nil {
				t.Fatal("NewTransport() error = nil")
			}
		})
	}
}
