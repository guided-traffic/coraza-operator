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

// Package enginepkg_test — reload_test.go covers the focused provider+metrics
// integration path: AtomicProvider swap behaviour combined with Prometheus counter
// increments, mirroring what server.go does in production.
//
// A full end-to-end test (bufconn gRPC + engine HTTP listener) would require
// either a real on-disk cert infrastructure or a significant test-hook in
// GRPCClientConfig for the dial function. That is deferred to i7 when the
// Config.DialFunc hook will be added. The focused test below is non-negotiable
// per the i6 spec and provides comprehensive coverage of the atomic swap path.
package enginepkg_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/coraza-operator/internal/enginepkg"
)

// gatherCounter reads the current float64 value of a CounterVec label pair.
func gatherCounter(t *testing.T, reg *prometheus.Registry, name, labelKey, labelVal string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == labelKey && lp.GetValue() == labelVal {
					if c := m.GetCounter(); c != nil {
						return c.GetValue()
					}
				}
			}
		}
	}
	return 0
}

// gatherGauge reads the current float64 value of a gauge.
func gatherGauge(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		metrics := mf.GetMetric()
		if len(metrics) == 0 {
			return 0
		}
		if g := metrics[0].GetGauge(); g != nil {
			return g.GetValue()
		}
	}
	return 0
}

// simulateOnBundle mirrors the production onBundle closure in server.go so the
// test exercises the exact counter increment path without needing a live server.
func simulateOnBundle(
	provider *enginepkg.AtomicProvider,
	m *enginepkg.EngineMetrics,
	b enginepkg.Bundle,
	logger logr.Logger,
) {
	if err := provider.Swap(b.RuleSetName, b.SHA256, b.Compiled); err != nil {
		logger.Error(err, "WAF reload failed; keeping previous WAF")
		m.WAFReloadTotal().WithLabelValues("failure").Inc()
		return
	}
	st := provider.State()
	m.WAFReloadTotal().WithLabelValues("success").Inc()
	m.WAFCurrentRules().Set(float64(st.RuleCount))
}

// TestReload_SuccessfulSwap_IncrementsMetrics tests the full swap path:
// valid bundle → success counter incremented, gauge updated.
func TestReload_SuccessfulSwap_IncrementsMetrics(t *testing.T) {
	initial, _, err := enginepkg.BuildWAF(initialSeclang)
	require.NoError(t, err)

	provider := enginepkg.NewAtomicProvider(initial, "sha-start")
	reg := prometheus.NewRegistry()
	m := enginepkg.NewEngineMetricsExported(reg)

	simulateOnBundle(provider, m, enginepkg.Bundle{
		RuleSetName: "rs-v1",
		SHA256:      "sha-v1",
		Compiled:    validSeclang,
	}, logr.Discard())

	assert.Equal(t, float64(1), gatherCounter(t, reg, "coraza_engine_waf_reload_total", "result", "success"))
	assert.Equal(t, float64(0), gatherCounter(t, reg, "coraza_engine_waf_reload_total", "result", "failure"))
	assert.Equal(t, float64(1), gatherGauge(t, reg, "coraza_engine_waf_current_rules"))

	st := provider.State()
	assert.Equal(t, "sha-v1", st.SHA256)
	assert.Equal(t, "rs-v1", st.RuleSetName)
}

// TestReload_FailedSwap_IncrementsFailureCounter tests the parse-failure path:
// invalid bundle → failure counter incremented, WAF unchanged, SHA unchanged.
func TestReload_FailedSwap_IncrementsFailureCounter(t *testing.T) {
	initial, _, err := enginepkg.BuildWAF(initialSeclang)
	require.NoError(t, err)

	provider := enginepkg.NewAtomicProvider(initial, "sha-start")
	reg := prometheus.NewRegistry()
	m := enginepkg.NewEngineMetricsExported(reg)

	simulateOnBundle(provider, m, enginepkg.Bundle{
		RuleSetName: "rs-bad",
		SHA256:      "sha-bad",
		Compiled:    invalidSeclang,
	}, logr.Discard())

	assert.Equal(t, float64(0), gatherCounter(t, reg, "coraza_engine_waf_reload_total", "result", "success"))
	assert.Equal(t, float64(1), gatherCounter(t, reg, "coraza_engine_waf_reload_total", "result", "failure"))

	st := provider.State()
	assert.Equal(t, "sha-start", st.SHA256, "SHA must not change on parse failure")
	assert.NotEmpty(t, st.LastError)
}

// TestReload_SuccessThenFailure tests that after a successful swap,
// a subsequent parse failure leaves the new WAF in place.
func TestReload_SuccessThenFailure(t *testing.T) {
	initial, _, err := enginepkg.BuildWAF(initialSeclang)
	require.NoError(t, err)

	provider := enginepkg.NewAtomicProvider(initial, "sha-start")
	reg := prometheus.NewRegistry()
	m := enginepkg.NewEngineMetricsExported(reg)

	// Success.
	simulateOnBundle(provider, m, enginepkg.Bundle{
		RuleSetName: "rs-v1",
		SHA256:      "sha-v1",
		Compiled:    validSeclang,
	}, logr.Discard())

	// Failure.
	simulateOnBundle(provider, m, enginepkg.Bundle{
		RuleSetName: "rs-bad",
		SHA256:      "sha-bad",
		Compiled:    invalidSeclang,
	}, logr.Discard())

	assert.Equal(t, float64(1), gatherCounter(t, reg, "coraza_engine_waf_reload_total", "result", "success"))
	assert.Equal(t, float64(1), gatherCounter(t, reg, "coraza_engine_waf_reload_total", "result", "failure"))

	// WAF must still be the one from the successful swap.
	st := provider.State()
	assert.Equal(t, "sha-v1", st.SHA256)
	assert.NotEmpty(t, st.LastError, "LastError must be set from the failed attempt")
}

// TestReload_WAFBlocksAfterSwap verifies that after swapping in a blocking rule,
// the HTTP handler actually returns 403 for matching requests.
func TestReload_WAFBlocksAfterSwap(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	initial, _, err := enginepkg.BuildWAF(initialSeclang)
	require.NoError(t, err)

	provider := enginepkg.NewAtomicProvider(initial, "sha-start")
	reg := prometheus.NewRegistry()
	m := enginepkg.NewEngineMetricsExported(reg)
	handler := enginepkg.BuildHandler(provider, upstreamURL, enginepkg.ModeBlocking, logr.Discard(), m)

	// Before swap: /attack passes through.
	req1 := httptest.NewRequest(http.MethodGet, "/attack", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusOK, rr1.Code, "before swap, /attack should pass through")

	// Swap in the attack rule.
	simulateOnBundle(provider, m, enginepkg.Bundle{
		RuleSetName: "rs-blocking",
		SHA256:      "sha-blocking",
		Compiled:    validSeclang,
	}, logr.Discard())

	// After swap: /attack must be blocked.
	req2 := httptest.NewRequest(http.MethodGet, "/attack", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusForbidden, rr2.Code, "after swap, /attack must be blocked")
}

// TestReload_InvalidBundle_OldWAFStillBlocks verifies the CLAUDE.md requirement:
// after a failed bundle parse the old WAF remains active and keeps blocking.
func TestReload_InvalidBundle_OldWAFStillBlocks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	// Start with the blocking WAF.
	blocking, _, err := enginepkg.BuildWAF(validSeclang)
	require.NoError(t, err)

	provider := enginepkg.NewAtomicProvider(blocking, "sha-blocking")
	reg := prometheus.NewRegistry()
	m := enginepkg.NewEngineMetricsExported(reg)
	handler := enginepkg.BuildHandler(provider, upstreamURL, enginepkg.ModeBlocking, logr.Discard(), m)

	// Confirm blocking is active.
	req1 := httptest.NewRequest(http.MethodGet, "/attack", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	require.Equal(t, http.StatusForbidden, rr1.Code)

	// Publish an invalid bundle.
	simulateOnBundle(provider, m, enginepkg.Bundle{
		RuleSetName: "bad",
		SHA256:      "sha-bad",
		Compiled:    invalidSeclang,
	}, logr.Discard())

	// Old WAF must still block.
	req2 := httptest.NewRequest(http.MethodGet, "/attack", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusForbidden, rr2.Code, "old WAF must remain active after failed reload")

	// /status must report lastError.
	st := provider.State()
	assert.NotEmpty(t, st.LastError)
}

// TestReload_StatusEndpoint_PopulatesLastError builds a minimal mux with the
// /status handler (same logic as in server.go) and asserts the JSON output
// contains lastError after a failed reload.
func TestReload_StatusEndpoint_PopulatesLastError(t *testing.T) {
	initial, _, err := enginepkg.BuildWAF(initialSeclang)
	require.NoError(t, err)
	provider := enginepkg.NewAtomicProvider(initial, "sha-start")
	reg := prometheus.NewRegistry()
	m := enginepkg.NewEngineMetricsExported(reg)

	// Inject a bad bundle.
	simulateOnBundle(provider, m, enginepkg.Bundle{
		RuleSetName: "bad",
		SHA256:      "sha-bad",
		Compiled:    invalidSeclang,
	}, logr.Discard())

	// Build the /status handler inline — same logic as server.go.
	statusHandler := func(w http.ResponseWriter, _ *http.Request) {
		st := provider.State()
		type statusJSON struct {
			SHA256      string `json:"sha256"`
			RuleSetName string `json:"rulesetName"`
			RuleCount   int    `json:"ruleCount"`
			ReloadedAt  string `json:"reloadedAt"`
			LastError   string `json:"lastError,omitempty"`
			LastErrorAt string `json:"lastErrorAt,omitempty"`
		}
		resp := statusJSON{
			SHA256:      st.SHA256,
			RuleSetName: st.RuleSetName,
			RuleCount:   st.RuleCount,
			LastError:   st.LastError,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rr := httptest.NewRecorder()
	statusHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	lastErr, ok := body["lastError"].(string)
	require.True(t, ok, "lastError field must be present in JSON")
	assert.NotEmpty(t, lastErr)
	// SHA must still be the original.
	assert.Equal(t, "sha-start", body["sha256"])
}

