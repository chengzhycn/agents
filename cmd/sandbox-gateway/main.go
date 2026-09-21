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

package main

import (
	"context"
	"os"

	envoyhttp "github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/sandbox-gateway/controller"
	"github.com/openkruise/agents/pkg/sandbox-gateway/filter"
	"github.com/openkruise/agents/pkg/sandbox-gateway/jwtauth"
	"github.com/openkruise/agents/pkg/sandbox-gateway/logging"
	"github.com/openkruise/agents/pkg/sandbox-gateway/registry"
	peerserver "github.com/openkruise/agents/pkg/sandbox-gateway/server"
	"github.com/openkruise/agents/pkg/sandboxroute/refresh"
)

func init() {
	if err := logging.Setup(); err != nil {
		logging.Logr().Error(err, "failed to configure sandbox gateway logging")
		os.Exit(1)
	}

	jwtAuthManager := jwtauth.NewManager()

	envoyhttp.RegisterHttpFilterFactoryAndConfigParser(
		"sandbox-gateway",
		filter.FilterFactory,
		filter.NewConfigParser(jwtAuthManager, logging.SetLevel),
	)
	routeRegistry := registry.GetRegistry()

	go func() {
		if err := controller.StartManager(context.Background(), controller.ManagerOptions{
			Registry:       routeRegistry,
			JWTAuthManager: jwtAuthManager,
		}); err != nil {
			logging.Logr().Error(err, "sandbox controller manager exited with error")
			os.Exit(1)
		}
	}()

	// Start the peer server for handling route synchronization from other peers
	go func() {
		ctx := context.Background()

		// Get Kubernetes config
		cfg, err := rest.InClusterConfig()
		if err != nil {
			logging.Logr().Error(err, "failed to get in-cluster config")
			os.Exit(1)
		}

		// Create controller-runtime client for peer discovery
		scheme := runtime.NewScheme()
		utilruntime.Must(clientgoscheme.AddToScheme(scheme))
		utilruntime.Must(agentsv1alpha1.AddToScheme(scheme))
		client, err := ctrlclient.New(cfg, ctrlclient.Options{Scheme: scheme})
		if err != nil {
			logging.Logr().Error(err, "failed to create controller-runtime client")
			os.Exit(1)
		}

		peerServer := peerserver.NewServer(
			client,
			routeRegistry,
			refresh.DefaultPort,
			jwtAuthManager.Ready,
		).WithMemberlistLogger(logging.MemberlistLogger())
		if err := peerServer.Start(ctx); err != nil {
			logging.Logr().Error(err, "failed to start peer server")
			os.Exit(1)
		}
	}()
}

func main() {}
