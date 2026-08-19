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
	"errors"
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

// readHeaderTimeout bounds how long a client may take to send its request
// headers. Without it a Slowloris client pins a connection indefinitely, and the
// engine sits in the request path, so exhausted connections mean dropped traffic.
const readHeaderTimeout = 10 * time.Second

// atomicWriteFile writes data to path atomically: write to a temp file,
// fsync, then rename. This matches the i4 requirement of a safe file update.
func atomicWriteFile(path string, data []byte) error {
	tmp := path + ".tmp"
	// #nosec G304 -- path is the operator-supplied bundle cache path from Config, never request data.
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
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
func Run(ctx context.Context, cfg Config) error {
	logger := logr.FromContextOrDiscard(ctx)

	provider, ruleCount, err := loadInitialWAF(cfg.RuleFilePath)
	if err != nil {
		return err
	}

	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return fmt.Errorf("parse upstream URL %q: %w", cfg.UpstreamURL, err)
	}

	reg := prometheus.NewRegistry()
	m := newEngineMetrics(reg)
	m.wafCurrentRules.Set(float64(ruleCount))

	logger.Info("initial WAF loaded",
		"sha256", short(provider.State().SHA256), "rules", ruleCount)

	mainSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           buildEngineMux(provider, upstream, cfg, logger, m),
		ReadHeaderTimeout: readHeaderTimeout,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	errCh := make(chan error, 2)

	if cfg.SPOAListenAddr != "" {
		startSPOAListener(ctx, cfg, provider, reg, errCh)
	}

	if cfg.OperatorAddr != "" {
		startConfigSubscriber(ctx, cfg, provider, m)
	}

	go func() {
		logger.Info("starting engine HTTP server", "addr", cfg.ListenAddr, "mode", cfg.Mode)
		serveHTTP(mainSrv, "engine server", errCh)
	}()

	metricsSrv := startMetricsServer(cfg, reg, logger, errCh)

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

// loadInitialWAF reads the rule file from disk and builds the first WAF, so the
// engine can serve traffic before the operator has sent a bundle.
func loadInitialWAF(rulePath string) (*AtomicProvider, int, error) {
	// #nosec G304 -- rulePath is the operator-supplied rule mount from Config.
	ruleBytes, err := os.ReadFile(rulePath)
	if err != nil {
		return nil, 0, fmt.Errorf("read rule file %s: %w", rulePath, err)
	}

	waf, ruleCount, err := BuildWAF(string(ruleBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("build WAF: %w", err)
	}

	return NewAtomicProvider(waf, sha256Hex(ruleBytes)), ruleCount, nil
}

// buildEngineMux wires the probe, status and WAF routes of the engine server.
func buildEngineMux(
	provider *AtomicProvider,
	upstream *url.URL,
	cfg Config,
	logger logr.Logger,
	m *engineMetrics,
) *http.ServeMux {
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

	statusHandler := newStatusHandler(provider)
	mux.HandleFunc("/status", statusHandler)
	mux.HandleFunc("/-/status", statusHandler)

	// All other paths go through the WAF handler.
	mux.Handle("/", BuildHandler(provider, upstream, cfg.Mode, logger, m))

	return mux
}

// newStatusHandler serialises the current ProviderState to JSON.
func newStatusHandler(provider *AtomicProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
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
}

// startSPOAListener runs the SPOA agent in the background.
func startSPOAListener(
	ctx context.Context,
	cfg Config,
	provider *AtomicProvider,
	reg prometheus.Registerer,
	errCh chan<- error,
) {
	logger := logr.FromContextOrDiscard(ctx)

	handler := &SPOAHandler{
		Provider: provider,
		Mode:     cfg.Mode,
		Logger:   logger.WithName("spoa"),
		Metrics:  newSPOAMetrics(reg),
	}

	go func() {
		logger.Info("starting SPOA listener", "addr", cfg.SPOAListenAddr)
		if spoaErr := ServeSPOA(ctx, cfg.SPOAListenAddr, handler); spoaErr != nil {
			errCh <- fmt.Errorf("spoa listener: %w", spoaErr)
		}
	}()
}

// startConfigSubscriber runs the gRPC bundle subscriber in the background.
// A subscriber failure is logged but never fatal: the engine keeps serving with
// the rules it already has rather than dropping traffic.
func startConfigSubscriber(
	ctx context.Context,
	cfg Config,
	provider *AtomicProvider,
	m *engineMetrics,
) {
	logger := logr.FromContextOrDiscard(ctx)

	grpcCfg := GRPCClientConfig{
		OperatorAddr:    cfg.OperatorAddr,
		EngineNamespace: cfg.EngineNamespace,
		EngineName:      cfg.EngineName,
		CertDir:         cfg.CertDir,
		SATokenPath:     cfg.SATokenPath,
	}
	onBundle := newBundleHandler(provider, m, cfg.BundleCachePath, logger)

	go func() {
		if subscribeErr := SubscribeConfig(ctx, grpcCfg, onBundle); subscribeErr != nil {
			logger.Error(subscribeErr, "gRPC subscriber exited")
		}
	}()
}

// newBundleHandler returns the callback applied to every bundle received from
// the operator: parse into a fresh WAF, atomically swap, persist to disk. On a
// parse failure the current WAF stays active and only the failure metric moves.
func newBundleHandler(
	provider *AtomicProvider,
	m *engineMetrics,
	cachePath string,
	logger logr.Logger,
) func(Bundle) {
	return func(b Bundle) {
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

		// Persist to the writable cache path after a SUCCESSFUL swap so on container
		// restart the engine can rebuild from disk while waiting for the first
		// gRPC bundle. RuleFilePath is a ConfigMap mount (read-only), so the cache
		// lives on the writable coraza-state emptyDir instead.
		if cachePath == "" {
			return
		}
		if writeErr := atomicWriteFile(cachePath, []byte(b.Compiled)); writeErr != nil {
			logger.Error(writeErr, "atomic write bundle to cache", "path", cachePath)
		}
	}
}

// startMetricsServer starts the Prometheus endpoint when one is configured and
// returns the server so Run can shut it down. Returns nil when disabled.
func startMetricsServer(
	cfg Config,
	reg *prometheus.Registry,
	logger logr.Logger,
	errCh chan<- error,
) *http.Server {
	if cfg.MetricsAddr == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	srv := &http.Server{
		Addr:              cfg.MetricsAddr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	go func() {
		logger.Info("starting metrics server", "addr", cfg.MetricsAddr)
		serveHTTP(srv, "metrics server", errCh)
	}()

	return srv
}

// serveHTTP runs srv until it stops, reporting a fatal error on errCh and nil
// on a clean shutdown.
func serveHTTP(srv *http.Server, name string, errCh chan<- error) {
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errCh <- fmt.Errorf("%s: %w", name, err)
		return
	}
	errCh <- nil
}
