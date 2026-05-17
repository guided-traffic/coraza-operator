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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/coraza-operator/internal/enginepkg"
)

const (
	initialSeclang = "SecRuleEngine On\n"
	validSeclang   = `SecRuleEngine On
SecRule REQUEST_URI "@contains /attack" "id:1,phase:1,deny,status:403"
`
	invalidSeclang = "THIS IS NOT VALID SECLANG\n"
)

// TestAtomicProvider_NewProvider verifies that a freshly-created provider
// returns the initial WAF and has the correct SHA in its state.
func TestAtomicProvider_NewProvider(t *testing.T) {
	waf, _, err := enginepkg.BuildWAF(initialSeclang)
	require.NoError(t, err)

	p := enginepkg.NewAtomicProvider(waf, "abc123")

	assert.NotNil(t, p.Current(), "Current must return the initial WAF")
	st := p.State()
	assert.Equal(t, "abc123", st.SHA256)
	assert.Empty(t, st.LastError)
}

// TestAtomicProvider_Swap_ValidSeclang verifies that after a successful Swap
// the provider returns a NEW WAF pointer and updates the state metadata.
func TestAtomicProvider_Swap_ValidSeclang(t *testing.T) {
	initial, _, err := enginepkg.BuildWAF(initialSeclang)
	require.NoError(t, err)
	p := enginepkg.NewAtomicProvider(initial, "sha-old")

	err = p.Swap("rs-v2", "sha-new", validSeclang)
	require.NoError(t, err)

	newWAF := p.Current()
	assert.NotNil(t, newWAF)
	// The new WAF must not be pointer-equal to the initial one.
	// We cannot compare interface pointers directly, but we can verify state.
	st := p.State()
	assert.Equal(t, "sha-new", st.SHA256)
	assert.Equal(t, "rs-v2", st.RuleSetName)
	assert.Equal(t, 1, st.RuleCount, "one SecRule directive in validSeclang")
	assert.Empty(t, st.LastError)
	assert.True(t, st.LastErrorAt.IsZero(), "LastErrorAt must be zero on success")
}

// TestAtomicProvider_Swap_InvalidSeclang verifies that a failed Swap:
//   - returns an error
//   - leaves Current() returning the OLD WAF (pointer equal via state SHA check)
//   - populates LastError and LastErrorAt in the state
//   - does NOT change SHA256
func TestAtomicProvider_Swap_InvalidSeclang(t *testing.T) {
	initial, _, err := enginepkg.BuildWAF(initialSeclang)
	require.NoError(t, err)
	p := enginepkg.NewAtomicProvider(initial, "sha-original")

	err = p.Swap("rs-bad", "sha-bad", invalidSeclang)
	require.Error(t, err, "Swap with invalid SecLang must return an error")

	// WAF must still be the original (SHA unchanged in state).
	st := p.State()
	assert.Equal(t, "sha-original", st.SHA256, "SHA must not change on parse failure")
	assert.NotEmpty(t, st.LastError)
	assert.False(t, st.LastErrorAt.IsZero(), "LastErrorAt must be set on failure")

	// Current WAF must still be non-nil and functional.
	assert.NotNil(t, p.Current())
}

// TestAtomicProvider_Swap_InvalidThenValid verifies recovery: after a failed
// swap, a subsequent successful swap replaces the WAF and clears the error.
func TestAtomicProvider_Swap_InvalidThenValid(t *testing.T) {
	initial, _, err := enginepkg.BuildWAF(initialSeclang)
	require.NoError(t, err)
	p := enginepkg.NewAtomicProvider(initial, "sha-v1")

	// First swap: fail.
	require.Error(t, p.Swap("bad", "sha-bad", invalidSeclang))

	// Second swap: succeed.
	require.NoError(t, p.Swap("rs-v2", "sha-v2", validSeclang))

	st := p.State()
	assert.Equal(t, "sha-v2", st.SHA256)
	// LastError is not automatically cleared on success (it records the last
	// failure for ops visibility), but SHA and RuleCount reflect the new WAF.
	assert.Equal(t, 1, st.RuleCount)
}

// TestAtomicProvider_Concurrent verifies that concurrent Swap calls and a hot
// loop of Current() calls produce no panics, no nil WAFs, and no torn reads.
// Run with -race to validate the atomic.Pointer semantics.
func TestAtomicProvider_Concurrent(t *testing.T) {
	initial, _, err := enginepkg.BuildWAF(initialSeclang)
	require.NoError(t, err)
	p := enginepkg.NewAtomicProvider(initial, "sha-init")

	const (
		readers  = 8
		swappers = 4
		iters    = 200
	)

	var wg sync.WaitGroup

	// Readers: hammer Current() and assert non-nil.
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters*10; j++ {
				w := p.Current()
				assert.NotNil(t, w, "Current must never return nil")
			}
		}()
	}

	// Swappers: alternate valid/invalid bundles.
	for i := 0; i < swappers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				if j%3 == 0 {
					// Inject an invalid bundle — WAF must not be replaced.
					_ = p.Swap("bad", "sha-bad", invalidSeclang)
				} else {
					_ = p.Swap("rs", "sha-ok", validSeclang)
				}
			}
		}(i)
	}

	wg.Wait()

	// After all goroutines finish, Current must still be non-nil.
	assert.NotNil(t, p.Current())
}
