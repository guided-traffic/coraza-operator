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

package enginepkg

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// atomicWriteFile writes data to path atomically: write to a temp file,
// fsync, then rename. This matches the i4 requirement of a safe file update.
func atomicWriteFile(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename temp to %s: %w", path, err)
	}
	return nil
}

// short returns the first 12 characters of a hex string for log readability.
func short(hex string) string {
	if len(hex) > 12 {
		return hex[:12]
	}
	return hex
}

// sha256Hex computes the hex-encoded SHA256 of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

const gracefulShutdownTimeout = 5 * time.Second

// statusJSON is the JSON structure returned by /status and /-/status.
type statusJSON struct {
	SHA256      string `json:"sha256"`
	RuleSetName string `json:"rulesetName"`
	RuleCount   int    `json:"ruleCount"`
	ReloadedAt  string `json:"reloadedAt"`
	LastError   string `json:"lastError,omitempty"`
	LastErrorAt string `json:"lastErrorAt,omitempty"`
}

// Run starts the engine: loads SecLang from cfg.RuleFilePath, builds WAF,
// starts the HTTP (and optional metrics) server, and blocks until ctx is
// cancelled or a fatal error occurs.
func Run(ctx context.Context, cfg Config, logger logr.Logger) error {
	// Load rule file.
	ruleBytes, err := os.ReadFile(cfg.RuleFilePath)
	if err != nil {
		return fmt.Errorf("read rule file %s: %w", cfg.RuleFilePath, err)
	}

	initialSHA := sha256Hex(ruleBytes)

	waf, ruleCount, err := BuildWAF(string(ruleBytes))
	if err != nil {
		return fmt.Errorf("build WAF: %w", err)
	}

	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return fmt.Errorf("parse upstream URL %q: %w", cfg.UpstreamURL, err)
	}

	reg := prometheus.NewRegistry()
	m := newEngineMetrics(reg)

	provider := NewAtomicProvider(waf, initialSHA)
	// Reflect the initial rule count in the gauge.
	m.wafCurrentRules.Set(float64(ruleCount))

	logger.Info("initial WAF loaded", "sha256", short(initialSHA), "rules", ruleCount)

	mux := http.NewServeMux()

	// /healthz (liveness): 200 if provider has a WAF, 503 otherwise.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if provider.Current() != nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.Error(w, "WAF not initialised", http.StatusServiceUnavailable)
	})

	// /readyz (readiness): 200 once a valid WAF has been loaded (SHA non-empty).
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if provider.State().SHA256 != "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready"))
			return
		}
		http.Error(w, "WAF not ready", http.StatusServiceUnavailable)
	})

	// statusHandler serialises ProviderState to JSON.
	statusHandler := func(w http.ResponseWriter, _ *http.Request) {
		// TODO(i7): gate behind cluster-internal auth or at least network policy.
		st := provider.State()
		resp := statusJSON{
			SHA256:      st.SHA256,
			RuleSetName: st.RuleSetName,
			RuleCount:   st.RuleCount,
			ReloadedAt:  st.ReloadedAt.UTC().Format(time.RFC3339),
			LastError:   st.LastError,
		}
		if !st.LastErrorAt.IsZero() {
			resp.LastErrorAt = st.LastErrorAt.UTC().Format(time.RFC3339)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
	mux.HandleFunc("/status", statusHandler)
	mux.HandleFunc("/-/status", statusHandler)

	// All other paths go through the WAF handler.
	mux.Handle("/", BuildHandler(provider, upstream, cfg.Mode, logger, m))

	mainSrv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: mux,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	errCh := make(chan error, 2)

	// Start SPOA listener if configured.
	if cfg.SPOAListenAddr != "" {
		spoaHandler := &SPOAHandler{
			Provider: provider,
			Mode:     cfg.Mode,
			Logger:   logger.WithName("spoa"),
			Metrics:  newSPOAMetrics(reg),
		}
		go func() {
			logger.Info("starting SPOA listener", "addr", cfg.SPOAListenAddr)
			if spoaErr := ServeSPOA(ctx, cfg.SPOAListenAddr, spoaHandler, logger); spoaErr != nil {
				errCh <- fmt.Errorf("spoa listener: %w", spoaErr)
			}
		}()
	}

	// Start gRPC config subscriber if configured.
	// On successful bundle receipt: parse into a fresh WAF, atomically swap, persist to disk.
	// On parse failure: keep current WAF, increment failure metric, log error.
	if cfg.OperatorAddr != "" {
		grpcCfg := GRPCClientConfig{
			OperatorAddr:    cfg.OperatorAddr,
			EngineNamespace: cfg.EngineNamespace,
			EngineName:      cfg.EngineName,
			CertDir:         cfg.CertDir,
			SATokenPath:     cfg.SATokenPath,
		}
		go func() {
			onBundle := func(b Bundle) {
				if err := provider.Swap(b.RuleSetName, b.SHA256, b.Compiled); err != nil {
					logger.Error(err, "WAF reload failed; keeping previous WAF",
						"sha256", short(b.SHA256))
					m.wafReloadTotal.WithLabelValues("failure").Inc()
					return
				}
				st := provider.State()
				logger.Info("WAF reloaded",
					"sha256", short(b.SHA256),
					"ruleset", b.RuleSetName,
					"rules", st.RuleCount)
				m.wafReloadTotal.WithLabelValues("success").Inc()
				m.wafCurrentRules.Set(float64(st.RuleCount))

				// Persist to writable cache path after a SUCCESSFUL swap so on container
				// restart the engine can rebuild from disk while waiting for the first
				// gRPC bundle. RuleFilePath is a ConfigMap mount (read-only) so we use
				// BundleCachePath which lives on the writable coraza-state emptyDir.
				if cfg.BundleCachePath != "" {
					if writeErr := atomicWriteFile(cfg.BundleCachePath, []byte(b.Compiled)); writeErr != nil {
						logger.Error(writeErr, "atomic write bundle to cache",
							"path", cfg.BundleCachePath)
					}
				}
			}

			if subscribeErr := SubscribeConfig(ctx, grpcCfg, onBundle, logger); subscribeErr != nil {
				logger.Error(subscribeErr, "gRPC subscriber exited")
			}
		}()
	}

	// Start main server.
	go func() {
		logger.Info("starting engine HTTP server", "addr", cfg.ListenAddr, "mode", cfg.Mode)
		if serveErr := mainSrv.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
			errCh <- fmt.Errorf("engine server: %w", serveErr)
			return
		}
		errCh <- nil
	}()

	// Optionally start metrics server.
	var metricsSrv *http.Server
	if cfg.MetricsAddr != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		metricsSrv = &http.Server{
			Addr:    cfg.MetricsAddr,
			Handler: metricsMux,
		}
		go func() {
			logger.Info("starting metrics server", "addr", cfg.MetricsAddr)
			if serveErr := metricsSrv.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
				errCh <- fmt.Errorf("metrics server: %w", serveErr)
				return
			}
			errCh <- nil
		}()
	}

	// Wait for ctx cancellation or a fatal server error.
	select {
	case <-ctx.Done():
		logger.Info("context cancelled, shutting down")
	case fatalErr := <-errCh:
		if fatalErr != nil {
			return fatalErr
		}
	}

	// Graceful shutdown with a fresh context (parent ctx is already done).
	shutdownCtx, cancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
	defer cancel()

	if shutdownErr := mainSrv.Shutdown(shutdownCtx); shutdownErr != nil {
		logger.Error(shutdownErr, "engine server shutdown error")
	}
	if metricsSrv != nil {
		if shutdownErr := metricsSrv.Shutdown(shutdownCtx); shutdownErr != nil {
			logger.Error(shutdownErr, "metrics server shutdown error")
		}
	}

	return nil
}
