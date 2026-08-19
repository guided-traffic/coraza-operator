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
	"net"
	"testing"
	"time"

	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildSPOAHandler creates a SPOAHandler with a WAF built from the given SecLang rules.
// mode controls Detection vs Blocking.
func buildSPOAHandler(t *testing.T, rules string, mode Mode) *SPOAHandler {
	t.Helper()
	waf, _, err := BuildWAF(rules)
	require.NoError(t, err)
	return &SPOAHandler{
		Provider: StaticProvider{W: waf},
		Mode:     mode,
		Logger:   logr.Discard(),
		Metrics:  nil, // nil is safe — all Metrics calls are guarded
	}
}

// spoaTestMessage builds a synthetic SPOE Message carrying the given request fields.
// The returned Message's KV scanner points into a buffer owned by this helper,
// which stays alive as long as the Message does.
func spoaTestMessage(t *testing.T, method, path, query string) *encoding.Message {
	t.Helper()

	// We need to serialise KV pairs in the SPOE wire format, then wrap them
	// into a Message manually via the package's internal pool types.
	// The public API gives us a KVWriter for this.
	kvBuf := make([]byte, 4096)
	kvw := encoding.AcquireKVWriter(kvBuf, 0)
	defer encoding.ReleaseKVWriter(kvw)

	require.NoError(t, kvw.SetString("method", method))
	require.NoError(t, kvw.SetString("path", path))
	require.NoError(t, kvw.SetString("query", query))
	require.NoError(t, kvw.SetString("req.ver", "1.1"))
	// req.hdrs_bin — minimal header block
	hdrs := []byte("Accept: */*\r\n\r\n")
	require.NoError(t, kvw.SetBinary("req.hdrs_bin", hdrs))

	serialised := make([]byte, kvw.Off())
	copy(serialised, kvBuf[:kvw.Off()])

	// Count the number of KV entries we wrote (5 fields above).
	const kvCount = 5

	m := encoding.AcquireMessage()
	m.KV = encoding.AcquireKVScanner(serialised, kvCount)

	return m
}

// spoaActionWriter returns an ActionWriter backed by a fresh buffer.
func spoaActionWriter() *encoding.ActionWriter {
	buf := make([]byte, 16384)
	return encoding.NewActionWriter(buf, 0)
}

// readActionsMap parses the action bytes written by a HandleSPOE call back into
// a map of variable name → string value (string vars only).
func readActionsMap(t *testing.T, w *encoding.ActionWriter) map[string]string {
	t.Helper()
	out := make(map[string]string)
	data := w.Bytes()
	if len(data) == 0 {
		return out
	}

	// Parse action list: each entry starts with action-type (1 byte),
	// nb-args (1 byte), scope (1 byte), then name (varint-length-prefixed bytes),
	// then data-type + value.
	i := 0
	for i < len(data) {
		if data[i] != byte(encoding.ActionTypeSetVar) {
			break
		}
		i++ // action type
		i++ // nb-args
		i++ // scope

		// name: varint length + bytes
		nameLen, n, err := encoding.Varint(data[i:])
		require.NoError(t, err)
		i += n
		name := string(data[i : i+int(nameLen)])
		i += int(nameLen)

		// data type
		dt := encoding.DataType(data[i] & 0x0F)
		i++

		switch dt {
		case encoding.DataTypeString:
			valLen, n, err := encoding.Varint(data[i:])
			require.NoError(t, err)
			i += n
			out[name] = string(data[i : i+int(valLen)])
			i += int(valLen)
		case encoding.DataTypeInt64:
			_, n, err := encoding.Varint(data[i:])
			require.NoError(t, err)
			i += n
			// For int fields we just record the name as present.
			out[name] = "<int>"
		default:
			// An unknown data type means the remaining bytes cannot be skipped
			// correctly, so the rest of the buffer would be misparsed.
			t.Fatalf("unexpected SPOE data type %v for %q", dt, name)
		}
	}
	return out
}

// readActionsInt parses the action bytes and returns int64 values by name.
func readActionsInt(t *testing.T, w *encoding.ActionWriter) map[string]int64 {
	t.Helper()
	out := make(map[string]int64)
	data := w.Bytes()
	if len(data) == 0 {
		return out
	}

	i := 0
	for i < len(data) {
		if data[i] != byte(encoding.ActionTypeSetVar) {
			break
		}
		i++ // action type
		i++ // nb-args
		i++ // scope

		nameLen, n, err := encoding.Varint(data[i:])
		require.NoError(t, err)
		i += n
		name := string(data[i : i+int(nameLen)])
		i += int(nameLen)

		dt := encoding.DataType(data[i] & 0x0F)
		i++

		switch dt {
		case encoding.DataTypeString:
			valLen, n, err := encoding.Varint(data[i:])
			require.NoError(t, err)
			i += n
			i += int(valLen)
		case encoding.DataTypeInt64:
			v, n, err := encoding.Varint(data[i:])
			require.NoError(t, err)
			i += n
			out[name] = int64(v)
		default:
			t.Fatalf("unexpected SPOE data type %v for %q", dt, name)
		}
	}
	return out
}

func TestSPOAHandler_AllowsBenignRequest(t *testing.T) {
	h := buildSPOAHandler(t, "SecRuleEngine On\n", ModeBlocking)
	m := spoaTestMessage(t, "GET", "/", "")
	defer encoding.ReleaseMessage(m)

	w := spoaActionWriter()
	h.HandleSPOE(context.Background(), w, m)

	strVars := readActionsMap(t, w)
	assert.Equal(t, "allow", strVars["action"], "benign GET / must be allowed")

	intVars := readActionsInt(t, w)
	assert.Equal(t, int64(0), intVars["rules_hit"], "no rules should match a benign GET /")
}

func TestSPOAHandler_DeniesAttackInBlockingMode(t *testing.T) {
	rules := `SecRuleEngine On
SecRule REQUEST_URI "@contains /attack" "id:1,phase:1,deny,status:403"`
	h := buildSPOAHandler(t, rules, ModeBlocking)
	m := spoaTestMessage(t, "GET", "/attack", "")
	defer encoding.ReleaseMessage(m)

	w := spoaActionWriter()
	h.HandleSPOE(context.Background(), w, m)

	strVars := readActionsMap(t, w)
	assert.Equal(t, "deny", strVars["action"], "path /attack must be denied in Blocking mode")
	assert.Equal(t, "1", strVars["rule_ids"], "rule id 1 must be reported")

	intVars := readActionsInt(t, w)
	assert.Equal(t, int64(1), intVars["rules_hit"], "exactly one rule should match")
	assert.Equal(t, int64(403), intVars["status"], "HTTP status must be 403")
}

func TestSPOAHandler_DetectionMode(t *testing.T) {
	rules := `SecRuleEngine On
SecRule REQUEST_URI "@contains /attack" "id:1,phase:1,deny,status:403"`
	h := buildSPOAHandler(t, rules, ModeDetection)
	m := spoaTestMessage(t, "GET", "/attack", "")
	defer encoding.ReleaseMessage(m)

	w := spoaActionWriter()
	h.HandleSPOE(context.Background(), w, m)

	strVars := readActionsMap(t, w)
	assert.Equal(t, "allow", strVars["action"], "Detection mode must not block — action must be allow")
	assert.Equal(t, "1", strVars["rule_ids"], "rule id 1 must still be reported in detection mode")

	intVars := readActionsInt(t, w)
	assert.Equal(t, int64(1), intVars["rules_hit"], "rule_hits must reflect matched rules even in detection mode")
}

func TestServeSPOA_GracefulShutdown(t *testing.T) {
	rules := "SecRuleEngine On\n"
	waf, _, err := BuildWAF(rules)
	require.NoError(t, err)
	h := &SPOAHandler{
		Provider: StaticProvider{W: waf},
		Mode:     ModeDetection,
		Logger:   logr.Discard(),
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Bind to an OS-assigned port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	_ = ln.Close() // Free the port — ServeSPOA will re-bind.

	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeSPOA(ctx, addr, h)
	}()

	// Give the goroutine time to bind.
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case err := <-errCh:
		assert.NoError(t, err, "ServeSPOA should return nil on context cancellation")
	case <-time.After(2 * time.Second):
		t.Fatal("ServeSPOA did not shut down within 2 seconds")
	}
}
