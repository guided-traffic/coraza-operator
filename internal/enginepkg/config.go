/*
Copyright 2026 Guided Traffic GmbH.

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

// Package enginepkg implements the Coraza-based reverse-proxy engine.
package enginepkg

import (
	"fmt"
	"os"
)

// Mode controls whether the WAF blocks or only detects violations.
type Mode string

const (
	// ModeDetection logs violations but does not block requests.
	ModeDetection Mode = "Detection"
	// ModeBlocking blocks requests that match rules.
	ModeBlocking Mode = "Blocking"
)

// Config holds all runtime configuration for the engine.
type Config struct {
	// ListenAddr is the TCP address the engine HTTP server listens on (e.g. ":8080").
	ListenAddr string
	// UpstreamURL is the backend URL requests are proxied to (e.g. "http://backend.svc:80").
	UpstreamURL string
	// Mode controls Detection vs Blocking behaviour.
	Mode Mode
	// RuleFilePath is the path to a file containing SecLang directives.
	RuleFilePath string
	// MetricsAddr is the TCP address of the Prometheus metrics server (e.g. ":9090").
	// An empty value disables the metrics server.
	MetricsAddr string

	// OperatorAddr is the operator's gRPC service address
	// (e.g. "coraza-operator-grpc.coraza-system.svc:9443").
	// Empty disables the gRPC subscriber.
	OperatorAddr string
	// EngineNamespace is the Kubernetes namespace of this engine pod.
	// Defaults to the POD_NAMESPACE env var if set.
	EngineNamespace string
	// EngineName is the Kubernetes name of this engine pod.
	// Defaults to the POD_NAME env var if set.
	EngineName string
	// CertDir is the directory for persisting the enrolled client cert, key,
	// and CA cert. Defaults to /var/lib/coraza/certs.
	CertDir string
	// SATokenPath is the path to the projected ServiceAccount token file used
	// for bootstrap enrollment. Defaults to /var/run/secrets/coraza/token.
	SATokenPath string
}

// FromEnv reads configuration from environment variables.
// Required: ENGINE_UPSTREAM_URL, ENGINE_RULE_FILE.
// Defaults: ENGINE_LISTEN_ADDR=":8080", ENGINE_MODE="Detection", ENGINE_METRICS_ADDR=":9090".
func FromEnv() (Config, error) {
	upstream := os.Getenv("ENGINE_UPSTREAM_URL")
	if upstream == "" {
		return Config{}, fmt.Errorf("ENGINE_UPSTREAM_URL is required but not set")
	}

	ruleFile := os.Getenv("ENGINE_RULE_FILE")
	if ruleFile == "" {
		return Config{}, fmt.Errorf("ENGINE_RULE_FILE is required but not set")
	}

	listenAddr := os.Getenv("ENGINE_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	mode := Mode(os.Getenv("ENGINE_MODE"))
	if mode == "" {
		mode = ModeDetection
	}
	if mode != ModeDetection && mode != ModeBlocking {
		return Config{}, fmt.Errorf("ENGINE_MODE must be %q or %q, got %q", ModeDetection, ModeBlocking, mode)
	}

	metricsAddr := os.Getenv("ENGINE_METRICS_ADDR")
	if metricsAddr == "" {
		metricsAddr = ":9090"
	}

	operatorAddr := os.Getenv("ENGINE_OPERATOR_ADDR")

	engineNS := os.Getenv("ENGINE_NAMESPACE")
	if engineNS == "" {
		engineNS = os.Getenv("POD_NAMESPACE")
	}

	engineName := os.Getenv("ENGINE_NAME")
	if engineName == "" {
		engineName = os.Getenv("POD_NAME")
	}

	certDir := os.Getenv("ENGINE_CERT_DIR")
	if certDir == "" {
		certDir = "/var/lib/coraza/certs"
	}

	saTokenPath := os.Getenv("ENGINE_SA_TOKEN")
	if saTokenPath == "" {
		saTokenPath = "/var/run/secrets/coraza/token"
	}

	return Config{
		ListenAddr:      listenAddr,
		UpstreamURL:     upstream,
		Mode:            mode,
		RuleFilePath:    ruleFile,
		MetricsAddr:     metricsAddr,
		OperatorAddr:    operatorAddr,
		EngineNamespace: engineNS,
		EngineName:      engineName,
		CertDir:         certDir,
		SATokenPath:     saTokenPath,
	}, nil
}
