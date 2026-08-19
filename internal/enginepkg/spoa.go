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
	"math"
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
func (h *SPOAHandler) HandleSPOE(_ context.Context, w *encoding.ActionWriter, m *encoding.Message) {
	start := time.Now()

	req, err := parseSPOERequest(m)
	if err != nil {
		h.fail(w, err, "SPOE KV scan error", start)
		return
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
	tx.ProcessURI(req.fullURI(), req.method, "HTTP/"+req.reqVer)

	// Parse binary header block (HTTP/1.1 wire format).
	if len(req.hdrsBin) > 0 {
		if hdrErr := feedHeaders(tx, req.hdrsBin); hdrErr != nil {
			h.Logger.Error(hdrErr, "parse SPOE header block (non-fatal, continuing)")
		}
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		h.observe(h.applyInterruption(w, tx, it), start)
		return
	}

	// Phase 2: request body.
	if len(req.bodyBytes) > 0 {
		writeIt, _, writeErr := tx.WriteRequestBody(req.bodyBytes)
		if writeErr != nil {
			h.fail(w, writeErr, "write request body to WAF (SPOA)", start)
			return
		}
		if writeIt != nil {
			h.observe(h.applyInterruption(w, tx, writeIt), start)
			return
		}
	}

	processIt, processErr := tx.ProcessRequestBody()
	if processErr != nil {
		h.fail(w, processErr, "process request body (SPOA)", start)
		return
	}
	if processIt != nil {
		h.observe(h.applyInterruption(w, tx, processIt), start)
		return
	}

	h.applyAllow(w, tx)
	h.observe("allowed", start)
}

// spoeRequest holds the request fields HandleSPOE reads off the SPOE wire.
type spoeRequest struct {
	method    string
	path      string
	query     string
	reqVer    string
	hdrsBin   []byte
	bodyBytes []byte
}

// fullURI joins path and query back into the URI Coraza evaluates.
func (r spoeRequest) fullURI() string {
	if r.query == "" {
		return r.path
	}
	return r.path + "?" + r.query
}

// spoeFields maps each request field to its wire name and its position in the
// positional form. unique-id (position 0) and req.body_size (position 6) are
// accepted by the scanner but carry nothing the WAF needs.
var spoeFields = []struct {
	name     string
	position int
	assign   func(*spoeRequest, []byte)
}{
	{"method", 1, func(r *spoeRequest, v []byte) { r.method = string(v) }},
	{"path", 2, func(r *spoeRequest, v []byte) { r.path = string(v) }},
	{"query", 3, func(r *spoeRequest, v []byte) { r.query = string(v) }},
	{"req.ver", 4, func(r *spoeRequest, v []byte) { r.reqVer = string(v) }},
	{"req.hdrs_bin", 5, func(r *spoeRequest, v []byte) { r.hdrsBin = bytes.Clone(v) }},
	{"req.body", 7, func(r *spoeRequest, v []byte) { r.bodyBytes = bytes.Clone(v) }},
}

// parseSPOERequest reads the SPOE KV pairs of one message into a spoeRequest.
//
// HAProxy Ingress Controller sends args POSITIONALLY (no name= prefix in the
// spoe-message args directive), so wire-level KV names arrive empty. Both forms
// are accepted: match by name when set, fall back to declaration order.
// IC default order: unique-id, method, path, query, req.ver, req.hdrs_bin,
// req.body_size, req.body.
func parseSPOERequest(m *encoding.Message) (spoeRequest, error) {
	var req spoeRequest

	kv := encoding.AcquireKVEntry()
	defer encoding.ReleaseKVEntry(kv)

	idx := 0
	for m.KV.Next(kv) {
		name := string(kv.NameBytes())
		for _, f := range spoeFields {
			if name == f.name || (name == "" && idx == f.position) {
				f.assign(&req, kv.ValueBytes())
				break
			}
		}
		idx++
	}

	if err := m.KV.Error(); err != nil {
		return spoeRequest{}, err
	}

	if req.reqVer == "" {
		req.reqVer = "1.1"
	}

	return req, nil
}

// observe records the outcome and duration of one handled SPOE message.
func (h *SPOAHandler) observe(outcome string, start time.Time) {
	if h.Metrics == nil {
		return
	}
	h.Metrics.messagesTotal.WithLabelValues(outcome).Inc()
	h.Metrics.messageDuration.Observe(time.Since(start).Seconds())
}

// fail logs err, writes the error response variables and records the outcome.
// The request is not blocked: an engine-side failure must not take traffic down.
func (h *SPOAHandler) fail(w *encoding.ActionWriter, err error, msg string, start time.Time) {
	h.Logger.Error(err, msg)
	h.setErrorVars(w, err.Error())
	h.observe("error", start)
}

// applyAllow writes the response variables for a request no rule interrupted.
func (h *SPOAHandler) applyAllow(w *encoding.ActionWriter, tx corazatypes.Transaction) {
	matched := tx.MatchedRules()

	scope := encoding.VarScopeTransaction
	_ = w.SetString(scope, "action", "allow")
	_ = w.SetString(scope, "id", tx.ID())
	_ = w.SetInt32(scope, "status", 200)
	_ = w.SetInt32(scope, "rules_hit", clampInt32(len(matched)))
	_ = w.SetString(scope, "rule_ids", buildRuleIDs(matched))
}

// clampInt32 narrows an int to the int32 the SPOE wire format carries. The
// counts involved (matched rules, HTTP status) can never realistically reach
// 2^31, but the conversion must saturate rather than wrap silently if they did.
func clampInt32(n int) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < math.MinInt32 {
		return math.MinInt32
	}
	return int32(n)
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
	rulesHit := clampInt32(len(matched))
	ruleIDs := buildRuleIDs(matched)

	status := clampInt32(it.Status)
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
func ServeSPOA(ctx context.Context, addr string, handler *SPOAHandler) error {
	logger := logr.FromContextOrDiscard(ctx)

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
