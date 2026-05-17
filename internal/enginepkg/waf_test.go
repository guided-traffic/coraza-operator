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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/coraza-operator/internal/enginepkg"
)

func TestBuildWAF_ValidMinimal(t *testing.T) {
	waf, count, err := enginepkg.BuildWAF("SecRuleEngine On\n")
	require.NoError(t, err)
	assert.NotNil(t, waf)
	assert.Equal(t, 0, count, "no SecRule/SecAction directives in minimal config")
}

func TestBuildWAF_WithRule(t *testing.T) {
	seclang := `SecRuleEngine On
SecRule REQUEST_URI "@contains /attack" "id:1,phase:1,deny,status:403"
`
	waf, count, err := enginepkg.BuildWAF(seclang)
	require.NoError(t, err)
	assert.NotNil(t, waf)
	assert.Equal(t, 1, count)
}

func TestBuildWAF_InvalidSecLang(t *testing.T) {
	_, _, err := enginepkg.BuildWAF("THIS IS NOT VALID SECLANG\n")
	require.Error(t, err, "invalid SecLang must return an error")
	assert.NotEmpty(t, err.Error(), "error message must be non-empty")
}
