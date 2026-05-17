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

	coraza "github.com/corazawaf/coraza/v3"

	"github.com/guided-traffic/coraza-operator/internal/compiler"
)

// BuildWAF parses the given SecLang directives and returns a configured coraza.WAF
// plus the number of SecRule/SecAction directives found in the text.
// Errors include line-level context when available (Coraza embeds that in the error message).
func BuildWAF(seclang string) (coraza.WAF, int, error) {
	cfg := coraza.NewWAFConfig().
		WithRequestBodyAccess().
		WithRequestBodyLimit(1 * 1024 * 1024). // 1 MiB
		WithRequestBodyInMemoryLimit(1 * 1024 * 1024).
		WithResponseBodyAccess().
		WithResponseBodyLimit(1 * 1024 * 1024).
		WithDirectives(seclang)

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, 0, fmt.Errorf("build WAF from SecLang: %w", err)
	}
	return waf, compiler.CountRules(seclang), nil
}
