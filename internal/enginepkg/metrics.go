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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// EngineMetrics holds all Prometheus instruments for the engine.
type EngineMetrics struct {
	requestsTotal   *prometheus.CounterVec
	requestLatency  prometheus.Histogram
	wafReloadTotal  *prometheus.CounterVec
	wafCurrentRules prometheus.Gauge
}

// engineMetrics is an alias kept for internal use.
type engineMetrics = EngineMetrics

// NewEngineMetricsExported is the exported constructor used by tests.
// Production code uses newEngineMetrics.
func NewEngineMetricsExported(reg prometheus.Registerer) *EngineMetrics {
	return newEngineMetrics(reg)
}

// WAFReloadTotal exposes the wafReloadTotal counter for test-side simulation.
func (m *EngineMetrics) WAFReloadTotal() *prometheus.CounterVec {
	return m.wafReloadTotal
}

// WAFCurrentRules exposes the wafCurrentRules gauge for test-side simulation.
func (m *EngineMetrics) WAFCurrentRules() prometheus.Gauge {
	return m.wafCurrentRules
}

// newEngineMetrics registers and returns the engine Prometheus metrics.
// It uses a dedicated registry to avoid collisions in tests.
func newEngineMetrics(reg prometheus.Registerer) *EngineMetrics {
	factory := promauto.With(reg)

	requestsTotal := factory.NewCounterVec(prometheus.CounterOpts{
		Name: "coraza_engine_requests_total",
		Help: "Total number of requests processed by the WAF engine.",
	}, []string{"outcome"})

	requestLatency := factory.NewHistogram(prometheus.HistogramOpts{
		Name:    "coraza_engine_request_duration_seconds",
		Help:    "Duration of WAF engine request processing in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	wafReloadTotal := factory.NewCounterVec(prometheus.CounterOpts{
		Name: "coraza_engine_waf_reload_total",
		Help: "Total number of WAF reload attempts.",
	}, []string{"result"})

	wafCurrentRules := factory.NewGauge(prometheus.GaugeOpts{
		Name: "coraza_engine_waf_current_rules",
		Help: "Number of SecRule/SecAction directives in the currently-active WAF.",
	})

	// Pre-initialise label vectors so they appear in /metrics from the start.
	requestsTotal.WithLabelValues("allowed")
	requestsTotal.WithLabelValues("blocked")
	requestsTotal.WithLabelValues("error")
	wafReloadTotal.WithLabelValues("success")
	wafReloadTotal.WithLabelValues("failure")

	return &engineMetrics{
		requestsTotal:   requestsTotal,
		requestLatency:  requestLatency,
		wafReloadTotal:  wafReloadTotal,
		wafCurrentRules: wafCurrentRules,
	}
}
