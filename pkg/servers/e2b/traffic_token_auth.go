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
	"context"
	"net/http"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/openkruise/agents/pkg/claimidentity"
	sandboxmanager "github.com/openkruise/agents/pkg/sandbox-manager"
	"github.com/openkruise/agents/pkg/servers/e2b/models"
	"github.com/openkruise/agents/pkg/servers/web"
)

type trafficTokenServiceAccount struct {
	namespace string
	identity  sandboxmanager.ServiceAccountIdentity
}

func (sc *Controller) CheckTrafficTokenCredentials(ctx context.Context, request *http.Request) (context.Context, *web.ApiError) {
	authorizationHeaders := request.Header.Values("Authorization")
	if len(authorizationHeaders) == 0 {
		return sc.CheckApiKey(ctx, request)
	}
	if len(request.Header.Values(models.HeaderApiKey)) != 0 || len(authorizationHeaders) != 1 {
		return ctx, invalidBearerTokenError()
	}

	scheme, token, found := strings.Cut(authorizationHeaders[0], " ")
	if !found || scheme != "Bearer" || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return ctx, invalidBearerTokenError()
	}
	namespaces := request.URL.Query()["namespace"]
	if len(namespaces) != 1 || len(validation.IsDNS1123Label(namespaces[0])) != 0 {
		return ctx, invalidBearerTokenError()
	}
	if sc.tokenReviewer == nil {
		return ctx, tokenReviewUnavailableError()
	}

	review, err := sc.tokenReviewer.Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: token},
	}, metav1.CreateOptions{})
	if err != nil || review == nil {
		return ctx, tokenReviewUnavailableError()
	}
	if review.Status.Error != "" || !review.Status.Authenticated || review.Status.User.UID == "" || !claimidentity.IsServiceAccountUsername(review.Status.User.Username) {
		return ctx, invalidBearerTokenError()
	}

	principal := trafficTokenServiceAccount{
		namespace: namespaces[0],
		identity: sandboxmanager.ServiceAccountIdentity{
			Username: review.Status.User.Username,
			UID:      review.Status.User.UID,
		},
	}
	return context.WithValue(ctx, trafficTokenServiceAccountContextKey, principal), nil
}

func invalidBearerTokenError() *web.ApiError {
	return &web.ApiError{Code: http.StatusUnauthorized, Message: "Invalid bearer token"}
}

func tokenReviewUnavailableError() *web.ApiError {
	return &web.ApiError{Code: http.StatusServiceUnavailable, Message: "Token review is unavailable"}
}
