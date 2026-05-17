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

package enginepkg_test

import (
	"io"
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

// minimalSeclang is a SecLang config that enables the rule engine but has no block rules.
const minimalSeclang = `
SecRuleEngine On
`

// attackSeclang blocks requests whose URI contains /attack.
const attackSeclang = `
SecRuleEngine On
SecRule REQUEST_URI "@contains /attack" "id:1,phase:1,deny,status:403"
`

// counterValue reads the current float value of a CounterVec label combination.
func counterValue(t *testing.T, reg *prometheus.Registry, metricName, labelName, labelVal string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != metricName {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == labelName && lp.GetValue() == labelVal {
					if c := m.GetCounter(); c != nil {
						return c.GetValue()
					}
				}
			}
		}
	}
	return 0
}

func buildTestHandler(
	t *testing.T,
	seclang string,
	upstreamURL *url.URL,
	mode enginepkg.Mode,
	m *enginepkg.EngineMetrics,
) http.Handler {
	t.Helper()
	waf, _, err := enginepkg.BuildWAF(seclang)
	require.NoError(t, err)
	provider := enginepkg.StaticProvider{W: waf}
	return enginepkg.BuildHandler(provider, upstreamURL, mode, logr.Discard(), m)
}

// TestProxy_AllowedRequest verifies that a request not matching any rule is proxied
// through and the upstream response status is returned, with "allowed" metric incremented.
func TestProxy_AllowedRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "hello from upstream")
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	reg := prometheus.NewRegistry()
	m := enginepkg.NewEngineMetricsExported(reg)
	handler := buildTestHandler(t, minimalSeclang, upstreamURL, enginepkg.ModeBlocking, m)

	req := httptest.NewRequest(http.MethodGet, "/safe-path", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "hello from upstream")

	allowed := counterValue(t, reg, "coraza_engine_requests_total", "outcome", "allowed")
	assert.Equal(t, float64(1), allowed, "allowed counter must be 1")
}

// TestProxy_BlockedRequest verifies that a request matching the attack rule is blocked
// with 403 in Blocking mode and the upstream is NOT hit.
func TestProxy_BlockedRequest(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	reg := prometheus.NewRegistry()
	m := enginepkg.NewEngineMetricsExported(reg)
	handler := buildTestHandler(t, attackSeclang, upstreamURL, enginepkg.ModeBlocking, m)

	req := httptest.NewRequest(http.MethodGet, "/attack", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code, "should be 403 in Blocking mode")
	assert.False(t, upstreamHit, "upstream must NOT be hit when request is blocked")

	blocked := counterValue(t, reg, "coraza_engine_requests_total", "outcome", "blocked")
	assert.Equal(t, float64(1), blocked, "blocked counter must be 1")

	allowed := counterValue(t, reg, "coraza_engine_requests_total", "outcome", "allowed")
	assert.Equal(t, float64(0), allowed, "allowed counter must be 0")
}

// TestProxy_DetectionMode verifies that in Detection mode the upstream IS hit even
// when the rule matches, the response is 200, and the "blocked" counter stays at 0.
// Detection mode increments "allowed" because the request was passed through.
func TestProxy_DetectionMode(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream ok")
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	reg := prometheus.NewRegistry()
	m := enginepkg.NewEngineMetricsExported(reg)
	handler := buildTestHandler(t, attackSeclang, upstreamURL, enginepkg.ModeDetection, m)

	req := httptest.NewRequest(http.MethodGet, "/attack", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "Detection mode must pass through upstream response")
	assert.True(t, upstreamHit, "upstream MUST be hit in Detection mode")

	blocked := counterValue(t, reg, "coraza_engine_requests_total", "outcome", "blocked")
	assert.Equal(t, float64(0), blocked, "blocked counter must be 0 in detection mode")

	allowed := counterValue(t, reg, "coraza_engine_requests_total", "outcome", "allowed")
	assert.Equal(t, float64(1), allowed, "allowed counter must be 1 in detection mode")
}
