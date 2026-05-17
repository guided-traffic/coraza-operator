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
	"fmt"
	"sync/atomic"
	"time"

	coraza "github.com/corazawaf/coraza/v3"
)

// ProviderState is an immutable snapshot of metadata published alongside each WAF.
// It is replaced atomically on every successful or failed Swap call.
type ProviderState struct {
	// SHA256 is the hex-encoded sha256 of the compiled SecLang bundle.
	SHA256 string
	// RuleSetName is the name of the RuleSet that produced this bundle.
	RuleSetName string
	// RuleCount is the number of SecRule/SecAction directives in the active bundle.
	RuleCount int
	// ReloadedAt is the time of the last successful swap.
	ReloadedAt time.Time
	// LastError is the parse error from the most recent failed Swap; empty on success.
	LastError string
	// LastErrorAt is the time of the most recent failed Swap; zero on no failure.
	LastErrorAt time.Time
}

// AtomicProvider holds the current WAF behind atomic.Pointer values so reads
// in the HTTP request hot path are lock-free. Both the WAF pointer and the
// state pointer are updated atomically on each successful Swap.
type AtomicProvider struct {
	waf   atomic.Pointer[coraza.WAF]
	state atomic.Pointer[ProviderState]
}

// NewAtomicProvider initialises an AtomicProvider with the provided WAF and
// initial SHA. sha256 may be empty when starting from a blank rule file.
func NewAtomicProvider(initial coraza.WAF, sha string) *AtomicProvider {
	p := &AtomicProvider{}
	p.waf.Store(&initial)
	s := &ProviderState{
		SHA256:     sha,
		ReloadedAt: time.Now(),
	}
	p.state.Store(s)
	return p
}

// Current implements WAFProvider. It is safe for concurrent calls and never
// returns nil once the provider has been initialised with NewAtomicProvider.
func (p *AtomicProvider) Current() coraza.WAF {
	return *p.waf.Load()
}

// State returns the current immutable metadata snapshot. Safe for concurrent use.
func (p *AtomicProvider) State() ProviderState {
	return *p.state.Load()
}

// Swap parses seclang into a fresh coraza.WAF. On success it atomically
// replaces both the WAF pointer and the state pointer (WAF first, then state
// — a concurrent State() reader may briefly see the old state with the new WAF,
// never the reverse). Returns the parse error without changing the active WAF
// on failure; updates LastError/LastErrorAt in that case.
func (p *AtomicProvider) Swap(rulesetName, sha, seclang string) error {
	waf, ruleCount, err := BuildWAF(seclang)
	if err != nil {
		// Parse failed — keep current WAF, update state to record the error.
		prev := p.state.Load()
		updated := &ProviderState{
			SHA256:      prev.SHA256,
			RuleSetName: prev.RuleSetName,
			RuleCount:   prev.RuleCount,
			ReloadedAt:  prev.ReloadedAt,
			LastError:   fmt.Sprintf("parse failed: %v", err),
			LastErrorAt: time.Now(),
		}
		p.state.Store(updated)
		return fmt.Errorf("swap WAF: %w", err)
	}

	// Parse succeeded — store WAF first, then state.
	p.waf.Store(&waf)
	p.state.Store(&ProviderState{
		SHA256:      sha,
		RuleSetName: rulesetName,
		RuleCount:   ruleCount,
		ReloadedAt:  time.Now(),
	})
	return nil
}
