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

package claimidentity

import "testing"

func TestIsServiceAccountUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     bool
	}{
		{name: "canonical username", username: "system:serviceaccount:tenant-a:runtime", want: true},
		{name: "empty namespace", username: "system:serviceaccount::runtime", want: false},
		{name: "empty service account", username: "system:serviceaccount:tenant-a:", want: false},
		{name: "invalid namespace", username: "system:serviceaccount:Tenant:runtime", want: false},
		{name: "invalid service account", username: "system:serviceaccount:tenant-a:Runtime", want: false},
		{name: "extra segment", username: "system:serviceaccount:tenant-a:runtime:extra", want: false},
		{name: "ordinary user", username: "alice", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsServiceAccountUsername(tt.username); got != tt.want {
				t.Fatalf("IsServiceAccountUsername(%q) = %t, want %t", tt.username, got, tt.want)
			}
		})
	}
}
