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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	corazatypes "github.com/corazawaf/coraza/v3/types"
	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
	"github.com/dropmorepackets/haproxy-go/spop"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// spoaMetrics holds Prometheus instruments for the SPOA listener.
type spoaMetrics struct {
	messagesTotal   *prometheus.CounterVec
	messageDuration prometheus.Histogram
}

func newSPOAMetrics(reg prometheus.Registerer) *spoaMetrics {
	factory := promauto.With(reg)
	m := &spoaMetrics{
		messagesTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "coraza_engine_spoa_messages_total",
			Help: "Total number of SPOE messages processed by the WAF engine.",
		}, []string{"outcome"}),
		messageDuration: factory.NewHistogram(prometheus.HistogramOpts{
			Name:    "coraza_engine_spoa_message_duration_seconds",
			Help:    "Duration of SPOE message processing in seconds.",
			Buckets: prometheus.DefBuckets,
		}),
	}
	// Pre-initialise label vectors so they appear in /metrics immediately.
	m.messagesTotal.WithLabelValues("allowed")
	m.messagesTotal.WithLabelValues("denied")
	m.messagesTotal.WithLabelValues("error")
	return m
}

// SPOAHandler bridges HAProxy SPOE messages to Coraza WAF transactions.
// One handler instance is shared across all connections; goroutine-safe because
// WAFProvider uses atomic.Pointer internally.
type SPOAHandler struct {
	Provider WAFProvider
	Mode     Mode
	Logger   logr.Logger
	Metrics  *spoaMetrics
}

// HandleSPOE implements spop.Handler.
//
// HAProxy IC sends one SPOE message per request with fields arriving in the order
// configured by modsecurity-args (default):
//
//	unique-id     (string)
//	method        (string)
//	path          (string)
//	query         (string)
//	req.ver       (string, e.g. "1.1")
//	req.hdrs_bin  (binary; HTTP/1.1 header block terminated by CRLF CRLF)
//	req.body_size (int64)
//	req.body      (binary)
//
// Output variables written back to HAProxy using TXN scope.
// The SPOE config at the haproxy-ingress side prefixes variables with "coraza.",
// so we write bare names: action, id, status, rules_hit, rule_ids.
func (h *SPOAHandler) HandleSPOE(ctx context.Context, w *encoding.ActionWriter, m *encoding.Message) {
	start := time.Now()

	var (
		method    string
		path      string
		query     string
		reqVer    string
		hdrsBin   []byte
		bodyBytes []byte
	)

	kv := encoding.AcquireKVEntry()
	defer encoding.ReleaseKVEntry(kv)

	// HAProxy Ingress Controller sends args POSITIONALLY (no name= prefix in
	// spoe-message args directive), so wire-level KV names arrive empty.
	// We accept both: match by name when set, fall back to declaration order.
	// IC default order: unique-id, method, path, query, req.ver, req.hdrs_bin,
	// req.body_size, req.body.
	idx := 0
	for m.KV.Next(kv) {
		name := string(kv.NameBytes())
		switch {
		case name == "method" || (name == "" && idx == 1):
			method = string(kv.ValueBytes())
		case name == "path" || (name == "" && idx == 2):
			path = string(kv.ValueBytes())
		case name == "query" || (name == "" && idx == 3):
			query = string(kv.ValueBytes())
		case name == "req.ver" || (name == "" && idx == 4):
			reqVer = string(kv.ValueBytes())
		case name == "req.hdrs_bin" || (name == "" && idx == 5):
			b := kv.ValueBytes()
			cp := make([]byte, len(b))
			copy(cp, b)
			hdrsBin = cp
		case name == "req.body" || (name == "" && idx == 7):
			b := kv.ValueBytes()
			cp := make([]byte, len(b))
			copy(cp, b)
			bodyBytes = cp
			// unique-id (idx 0) and req.body_size (idx 6) accepted but unused.
		}
		idx++
	}

	if err := m.KV.Error(); err != nil {
		h.Logger.Error(err, "SPOE KV scan error")
		h.setErrorVars(w, err.Error())
		if h.Metrics != nil {
			h.Metrics.messagesTotal.WithLabelValues("error").Inc()
			h.Metrics.messageDuration.Observe(time.Since(start).Seconds())
		}
		return
	}

	if reqVer == "" {
		reqVer = "1.1"
	}

	waf := h.Provider.Current()
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		if cerr := tx.Close(); cerr != nil {
			h.Logger.Error(cerr, "close coraza SPOA transaction")
		}
	}()

	// Phase 1: connection (zeros for unknown IPs/ports).
	tx.ProcessConnection("", 0, "", 0)

	fullURI := path
	if query != "" {
		fullURI = path + "?" + query
	}
	tx.ProcessURI(fullURI, method, "HTTP/"+reqVer)

	// Parse binary header block (HTTP/1.1 wire format).
	if len(hdrsBin) > 0 {
		if err := feedHeaders(tx, hdrsBin); err != nil {
			h.Logger.Error(err, "parse SPOE header block (non-fatal, continuing)")
		}
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		outcome := h.applyInterruption(w, tx, it)
		if h.Metrics != nil {
			h.Metrics.messagesTotal.WithLabelValues(outcome).Inc()
			h.Metrics.messageDuration.Observe(time.Since(start).Seconds())
		}
		return
	}

	// Phase 2: request body.
	if len(bodyBytes) > 0 {
		writeIt, _, err := tx.WriteRequestBody(bodyBytes)
		if err != nil {
			h.Logger.Error(err, "write request body to WAF (SPOA)")
			h.setErrorVars(w, err.Error())
			if h.Metrics != nil {
				h.Metrics.messagesTotal.WithLabelValues("error").Inc()
				h.Metrics.messageDuration.Observe(time.Since(start).Seconds())
			}
			return
		}
		if writeIt != nil {
			outcome := h.applyInterruption(w, tx, writeIt)
			if h.Metrics != nil {
				h.Metrics.messagesTotal.WithLabelValues(outcome).Inc()
				h.Metrics.messageDuration.Observe(time.Since(start).Seconds())
			}
			return
		}
	}

	processIt, err := tx.ProcessRequestBody()
	if err != nil {
		h.Logger.Error(err, "process request body (SPOA)")
		h.setErrorVars(w, err.Error())
		if h.Metrics != nil {
			h.Metrics.messagesTotal.WithLabelValues("error").Inc()
			h.Metrics.messageDuration.Observe(time.Since(start).Seconds())
		}
		return
	}
	if processIt != nil {
		outcome := h.applyInterruption(w, tx, processIt)
		if h.Metrics != nil {
			h.Metrics.messagesTotal.WithLabelValues(outcome).Inc()
			h.Metrics.messageDuration.Observe(time.Since(start).Seconds())
		}
		return
	}

	// No interruption — always allow.
	matched := tx.MatchedRules()
	rulesHit := int32(len(matched))
	ruleIDs := buildRuleIDs(matched)

	scope := encoding.VarScopeTransaction
	_ = w.SetString(scope, "action", "allow")
	_ = w.SetString(scope, "id", tx.ID())
	_ = w.SetInt32(scope, "status", 200)
	_ = w.SetInt32(scope, "rules_hit", rulesHit)
	_ = w.SetString(scope, "rule_ids", ruleIDs)

	if h.Metrics != nil {
		h.Metrics.messagesTotal.WithLabelValues("allowed").Inc()
		h.Metrics.messageDuration.Observe(time.Since(start).Seconds())
	}
}

// applyInterruption writes the deny/allow response variables for an interruption.
// In Detection mode it always sets action=allow but still populates rules_hit/rule_ids.
// Returns the metrics outcome label ("denied" or "allowed").
func (h *SPOAHandler) applyInterruption(
	w *encoding.ActionWriter,
	tx corazatypes.Transaction,
	it *corazatypes.Interruption,
) string {
	matched := tx.MatchedRules()
	rulesHit := int32(len(matched))
	ruleIDs := buildRuleIDs(matched)

	status := int32(it.Status)
	if status == 0 {
		status = 403
	}

	scope := encoding.VarScopeTransaction
	_ = w.SetString(scope, "id", tx.ID())
	_ = w.SetInt32(scope, "rules_hit", rulesHit)
	_ = w.SetString(scope, "rule_ids", ruleIDs)

	if h.Mode == ModeBlocking {
		h.Logger.Info("SPOA WAF blocked request",
			"ruleID", it.RuleID, "action", it.Action, "status", status)
		_ = w.SetString(scope, "action", "deny")
		_ = w.SetInt32(scope, "status", status)
		return "denied"
	}

	// Detection mode: log but allow.
	h.Logger.Info("SPOA WAF would block (detection mode, allowing)",
		"ruleID", it.RuleID, "action", it.Action, "status", status)
	_ = w.SetString(scope, "action", "allow")
	_ = w.SetInt32(scope, "status", status)
	return "allowed"
}

// setErrorVars sets coraza.action=allow and coraza.error=msg.
// Fail-open: on processing errors we allow traffic through.
// TODO: make fail-open/fail-closed configurable.
func (h *SPOAHandler) setErrorVars(w *encoding.ActionWriter, msg string) {
	scope := encoding.VarScopeTransaction
	_ = w.SetString(scope, "action", "allow")
	_ = w.SetString(scope, "error", msg)
}

// feedHeaders parses a binary HTTP/1.1 header block and adds each header to tx.
// HAProxy sends headers as "Name: Value\r\n...\r\n" with a trailing blank line.
func feedHeaders(tx interface{ AddRequestHeader(key, value string) }, hdrsBin []byte) error {
	// Normalise: ensure the block ends with the blank line textproto needs.
	block := hdrsBin
	if !bytes.HasSuffix(block, []byte("\r\n\r\n")) {
		if bytes.HasSuffix(block, []byte("\r\n")) {
			block = append(block, "\r\n"...)
		} else {
			block = append(block, "\r\n\r\n"...)
		}
	}

	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(block)))
	mh, err := tp.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		// textproto returns io.EOF at the blank line; any other error is a parse failure.
		return fmt.Errorf("parse MIME headers: %w", err)
	}
	for k, vals := range mh {
		for _, v := range vals {
			tx.AddRequestHeader(k, v)
		}
	}
	return nil
}

// ServeSPOA starts the SPOA TCP listener on addr and serves until ctx is cancelled.
// It returns nil when the context is cancelled (graceful shutdown), or a non-nil
// error on unexpected listener failure.
func ServeSPOA(ctx context.Context, addr string, handler *SPOAHandler, logger logr.Logger) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("spoa listen %s: %w", addr, err)
	}

	logger.Info("SPOA listener started", "addr", ln.Addr().String())

	agent := &spop.Agent{
		Handler:     handler,
		BaseContext: ctx,
		Addr:        ln.Addr().String(),
	}

	if err := agent.Serve(ln); err != nil {
		if ctx.Err() != nil {
			logger.Info("SPOA listener stopped (context cancelled)")
			return nil
		}
		return fmt.Errorf("spoa serve: %w", err)
	}
	return nil
}

// buildRuleIDs returns a comma-separated, deduplicated list of rule IDs.
func buildRuleIDs(rules []corazatypes.MatchedRule) string {
	if len(rules) == 0 {
		return ""
	}
	ids := make([]string, 0, len(rules))
	seen := make(map[int]struct{}, len(rules))
	for _, r := range rules {
		id := r.Rule().ID()
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, strconv.Itoa(id))
	}
	return strings.Join(ids, ",")
}
