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

package compiler_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/coraza-operator/internal/compiler"
)

func TestCompile_EmptyList(t *testing.T) {
	bundle, err := compiler.Compile(nil)
	require.NoError(t, err)
	assert.Equal(t, "", bundle.Compiled)
	assert.Equal(t, int32(0), bundle.RuleCount)
	// Hash must be deterministic and non-empty.
	assert.NotEmpty(t, bundle.SHA256)
}

func TestCompile_EmptyList_DeterministicHash(t *testing.T) {
	b1, err := compiler.Compile(nil)
	require.NoError(t, err)
	b2, err := compiler.Compile(nil)
	require.NoError(t, err)
	assert.Equal(t, b1.SHA256, b2.SHA256)
}

func TestCompile_SingleSource_TwoRules(t *testing.T) {
	src := compiler.Source{
		Kind: "SecRules",
		Name: "my-rules",
		Body: `SecRule ARGS "@contains sql" "id:1001,phase:2,deny"
SecRule REQUEST_HEADERS:User-Agent "@contains bot" "id:1002,phase:1,log"
`,
	}
	bundle, err := compiler.Compile([]compiler.Source{src})
	require.NoError(t, err)
	assert.Equal(t, int32(2), bundle.RuleCount)
	assert.Contains(t, bundle.Compiled, "# --- begin SecRules/my-rules ---")
	assert.Contains(t, bundle.Compiled, "# --- end SecRules/my-rules ---")
	assert.Contains(t, bundle.Compiled, "SecRule ARGS")
	assert.NotEmpty(t, bundle.SHA256)
}

func TestCompile_TwoSources_NoConflict_OrderPreserved(t *testing.T) {
	src1 := compiler.Source{
		Kind: "SecRules",
		Name: "alpha",
		Body: `SecRule ARGS "@contains xss" "id:2001,phase:2,deny"
`,
	}
	src2 := compiler.Source{
		Kind: "ClusterSecRules",
		Name: "beta",
		Body: `SecRule REQUEST_URI "@beginsWith /admin" "id:3001,phase:1,deny"
`,
	}
	bundle, err := compiler.Compile([]compiler.Source{src1, src2})
	require.NoError(t, err)
	assert.Equal(t, int32(2), bundle.RuleCount)

	// Both banners must be present and alpha must come before beta.
	alphaIdx := strings.Index(bundle.Compiled, "# --- begin SecRules/alpha ---")
	betaIdx := strings.Index(bundle.Compiled, "# --- begin ClusterSecRules/beta ---")
	assert.True(t, alphaIdx >= 0, "alpha banner not found")
	assert.True(t, betaIdx >= 0, "beta banner not found")
	assert.Less(t, alphaIdx, betaIdx, "alpha must appear before beta")
}

func TestCompile_TwoSources_ConflictingRuleID(t *testing.T) {
	src1 := compiler.Source{
		Kind: "SecRules",
		Name: "first",
		Body: `SecRule ARGS "@contains sql" "id:9999,phase:2,deny"
`,
	}
	src2 := compiler.Source{
		Kind: "ClusterSecRules",
		Name: "second",
		Body: `SecRule ARGS "@contains xss" "id:9999,phase:2,deny"
`,
	}
	_, err := compiler.Compile([]compiler.Source{src1, src2})
	require.Error(t, err)

	var conflictErr *compiler.ConflictError
	require.True(t, errors.As(err, &conflictErr), "expected *ConflictError, got %T: %v", err, err)
	assert.Equal(t, "9999", conflictErr.RuleID)
	assert.Equal(t, "SecRules/first", conflictErr.First)
	assert.Equal(t, "ClusterSecRules/second", conflictErr.Second)
	// Error message must name both sources and the ID.
	assert.Contains(t, err.Error(), "9999")
	assert.Contains(t, err.Error(), "SecRules/first")
	assert.Contains(t, err.Error(), "ClusterSecRules/second")
}

func TestCompile_WhitespaceAndCommentsDoNotCountAsRules(t *testing.T) {
	src := compiler.Source{
		Kind: "SecRules",
		Name: "comments",
		Body: `
# This is a comment

# SecRule in a comment does not count
SecAction "id:5001,phase:1,nolog,pass"
`,
	}
	bundle, err := compiler.Compile([]compiler.Source{src})
	require.NoError(t, err)
	// Only the SecAction line counts.
	assert.Equal(t, int32(1), bundle.RuleCount)
}

func TestCompile_HashIsStableAcrossRuns(t *testing.T) {
	sources := []compiler.Source{
		{Kind: "SecRules", Name: "stable", Body: `SecRule ARGS "@contains test" "id:7777,phase:2,deny"` + "\n"},
	}
	b1, err := compiler.Compile(sources)
	require.NoError(t, err)
	b2, err := compiler.Compile(sources)
	require.NoError(t, err)
	assert.Equal(t, b1.SHA256, b2.SHA256)
	assert.Equal(t, b1.Compiled, b2.Compiled)
}
