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
	"bytes"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	coraza "github.com/corazawaf/coraza/v3"
	corazatypes "github.com/corazawaf/coraza/v3/types"
	"github.com/go-logr/logr"
)

const requestBodyLimit = 1 * 1024 * 1024 // 1 MiB

// WAFProvider abstracts access to the current WAF instance.
// The indirection allows i6 to hot-swap the WAF via atomic.Pointer.
type WAFProvider interface {
	Current() coraza.WAF
}

// StaticProvider holds a single immutable WAF instance.
type StaticProvider struct{ W coraza.WAF }

// Current returns the held WAF.
func (s StaticProvider) Current() coraza.WAF { return s.W }

// BuildHandler constructs an http.Handler that runs WAF inspection before
// proxying to upstream. m must not be nil.
func BuildHandler(p WAFProvider, upstream *url.URL, mode Mode, logger logr.Logger, m *engineMetrics) http.Handler {
	rp := httputil.NewSingleHostReverseProxy(upstream)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		waf := p.Current()
		tx := waf.NewTransaction()
		defer func() {
			tx.ProcessLogging()
			if err := tx.Close(); err != nil {
				logger.Error(err, "close coraza transaction")
			}
		}()

		if inspectRequest(w, r, tx, mode, logger, m, start) {
			return
		}

		// Phase 3: proxy to upstream, capture response for WAF processing.
		rec := newResponseRecorder(w)
		rp.ServeHTTP(rec, r)

		if inspectResponse(w, rec, tx, mode, logger, m, start) {
			return
		}

		flushRecorded(w, rec)

		m.requestsTotal.WithLabelValues("allowed").Inc()
		m.requestLatency.Observe(time.Since(start).Seconds())
	})
}

// inspectRequest runs the request-side WAF phases (connection, URI, headers,
// body). It reports whether a response has already been written and the handler
// must stop; in Detection mode an interruption is recorded but never stops the
// request.
func inspectRequest(
	w http.ResponseWriter,
	r *http.Request,
	tx corazatypes.Transaction,
	mode Mode,
	logger logr.Logger,
	m *engineMetrics,
	start time.Time,
) bool {
	// Phase 1: connection + URI.
	tx.ProcessConnection(r.RemoteAddr, 0, r.Host, 0)
	tx.ProcessURI(r.RequestURI, r.Method, r.Proto)

	addRequestHeaders(tx, r)

	if it := tx.ProcessRequestHeaders(); it != nil {
		blockOrDetect(w, mode, it, logger, m, start)
		if mode == ModeBlocking {
			return true
		}
	}

	// Phase 2: request body (buffered up to limit).
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, requestBodyLimit))
		if err != nil {
			return internalError(w, logger, m, err, "read request body")
		}
		_ = r.Body.Close()
		// Re-set body for the upstream proxy.
		r.Body = io.NopCloser(bytes.NewReader(body))

		writeIt, _, writeErr := tx.WriteRequestBody(body)
		if writeErr != nil {
			return internalError(w, logger, m, writeErr, "write request body to WAF")
		}
		if writeIt != nil {
			blockOrDetect(w, mode, writeIt, logger, m, start)
			if mode == ModeBlocking {
				return true
			}
		}
	}

	processIt, processErr := tx.ProcessRequestBody()
	if processErr != nil {
		return internalError(w, logger, m, processErr, "process request body")
	}
	if processIt != nil {
		blockOrDetect(w, mode, processIt, logger, m, start)
		if mode == ModeBlocking {
			return true
		}
	}

	return false
}

// inspectResponse runs the response-side WAF phases against the recorded
// upstream response. It reports whether the response was already written.
func inspectResponse(
	w http.ResponseWriter,
	rec *responseRecorder,
	tx corazatypes.Transaction,
	mode Mode,
	logger logr.Logger,
	m *engineMetrics,
	start time.Time,
) bool {
	// Phase 4: response headers.
	for key, vals := range rec.header {
		for _, v := range vals {
			tx.AddResponseHeader(key, v)
		}
	}

	if respIt := tx.ProcessResponseHeaders(rec.status, "HTTP/1.1"); respIt != nil {
		if mode == ModeBlocking {
			m.requestsTotal.WithLabelValues("blocked").Inc()
			m.requestLatency.Observe(time.Since(start).Seconds())
			http.Error(w, "response blocked by WAF", http.StatusForbidden)
			return true
		}
		logger.Info("WAF interrupted response (detection mode, passing through)", "status", respIt.Status)
	}

	// Phase 5: response body (best-effort; ignore interruption for now).
	if _, _, writeRespErr := tx.WriteResponseBody(rec.body.Bytes()); writeRespErr != nil {
		logger.Error(writeRespErr, "write response body to WAF")
	}
	if _, processRespErr := tx.ProcessResponseBody(); processRespErr != nil {
		logger.Error(processRespErr, "process response body")
	}

	return false
}

// addRequestHeaders feeds the request headers into the transaction. Go strips
// Host from r.Header, so it is added explicitly.
func addRequestHeaders(tx corazatypes.Transaction, r *http.Request) {
	for key, vals := range r.Header {
		for _, v := range vals {
			tx.AddRequestHeader(key, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
	}
}

// flushRecorded writes the buffered upstream response to the real writer.
func flushRecorded(w http.ResponseWriter, rec *responseRecorder) {
	for key, vals := range rec.header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(rec.status)
	_, _ = w.Write(rec.body.Bytes())
}

// internalError reports an engine-side failure to the client and records it.
// It always returns true so callers can stop the request in a single line.
func internalError(
	w http.ResponseWriter,
	logger logr.Logger,
	m *engineMetrics,
	err error,
	msg string,
) bool {
	logger.Error(err, msg)
	m.requestsTotal.WithLabelValues("error").Inc()
	http.Error(w, "internal server error", http.StatusInternalServerError)
	return true
}

// blockOrDetect responds with an error in Blocking mode; logs the interruption in Detection mode.
// Callers must check mode themselves to decide whether to return early.
func blockOrDetect(
	w http.ResponseWriter,
	mode Mode,
	it *corazatypes.Interruption,
	logger logr.Logger,
	m *engineMetrics,
	start time.Time,
) {
	status := it.Status
	if status == 0 {
		status = http.StatusForbidden
	}

	if mode == ModeBlocking {
		logger.Info("WAF blocked request", "ruleID", it.RuleID, "action", it.Action, "status", status)
		m.requestsTotal.WithLabelValues("blocked").Inc()
		m.requestLatency.Observe(time.Since(start).Seconds())
		http.Error(w, "request blocked by WAF", status)
		return
	}

	// Detection mode: log but allow.
	logger.Info("WAF would block (detection mode, allowing)", "ruleID", it.RuleID, "action", it.Action, "status", status)
}

// responseRecorder buffers an upstream response so the WAF can inspect it.
type responseRecorder struct {
	underlying http.ResponseWriter //nolint:unused
	header     http.Header
	status     int
	body       bytes.Buffer
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{
		underlying: w,
		header:     make(http.Header),
		status:     http.StatusOK,
	}
}

func (r *responseRecorder) Header() http.Header         { return r.header }
func (r *responseRecorder) WriteHeader(status int)      { r.status = status }
func (r *responseRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }
