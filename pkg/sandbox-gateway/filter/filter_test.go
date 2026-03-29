package filter

import (
	"testing"

	"github.com/openkruise/agents/pkg/proxy"
	"github.com/openkruise/agents/pkg/sandbox-gateway/registry"
)

func TestDecodeHeadersMissingSandboxID(t *testing.T) {
	// When sandbox-id header is missing, the filter should return Continue (pass-through).
	// We can't easily test the full Envoy filter interface without the Envoy runtime,
	// but we can test the registry logic that the filter depends on.
	r := registry.GetRegistry()
	defer r.Clear()
	r.Update("default--app1", proxy.Route{IP: "10.0.0.1", ResourceVersion: "1"})

	route, ok := r.Get("default--app1")
	if !ok || route.IP != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1, got %q", route.IP)
	}

	// Missing key returns not found
	_, ok = r.Get("default--nonexistent")
	if ok {
		t.Fatal("expected not found for missing sandbox")
	}
}

func TestExtractHostInfo(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		wantHostKey string
		wantPort    string
	}{
		{
			name:        "valid host format with port",
			headerValue: "8080-abc--def.example.com",
			wantHostKey: "abc--def",
			wantPort:    "8080",
		},
		{
			name:        "valid host format with different port",
			headerValue: "3000-myns--myservice.domain.com",
			wantHostKey: "myns--myservice",
			wantPort:    "3000",
		},
		{
			name:        "empty header value",
			headerValue: "",
			wantHostKey: "",
			wantPort:    "",
		},
		{
			name:        "invalid format - no dot",
			headerValue: "8080-abc--def",
			wantHostKey: "",
			wantPort:    "",
		},
		{
			name:        "invalid format - no port prefix",
			headerValue: "abc--def.example.com",
			wantHostKey: "",
			wantPort:    "",
		},
		{
			name:        "invalid format - no hyphen separator",
			headerValue: "8080abcdef.example.com",
			wantHostKey: "",
			wantPort:    "",
		},
		{
			name:        "valid format with multiple hyphens in name",
			headerValue: "443-ns--my-app-v2.domain.com",
			wantHostKey: "ns--my-app-v2",
			wantPort:    "443",
		},
	}

	cfg := &Config{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHostKey, gotPort := cfg.ExtractHostInfo(tt.headerValue)
			if gotHostKey != tt.wantHostKey {
				t.Errorf("ExtractHostInfo() gotHostKey = %q, want %q", gotHostKey, tt.wantHostKey)
			}
			if gotPort != tt.wantPort {
				t.Errorf("ExtractHostInfo() gotPort = %q, want %q", gotPort, tt.wantPort)
			}
		})
	}
}
