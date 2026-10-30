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
	"fmt"
	"os"
	"strings"
)

// BearerTokenFile returns a provider that reads path for every refresh.
func BearerTokenFile(path string) BearerTokenProvider {
	return func(context.Context) (string, error) {
		contents, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read bearer token file %q: %w", path, err)
		}
		return strings.TrimSpace(string(contents)), nil
	}
}
