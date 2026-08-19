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

// Package compiler provides pure functions for concatenating and validating
// SecLang rule sources into a single compiled bundle.
package compiler

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
)

// ruleDirectiveRe matches lines that start a SecRule or SecAction directive
// (optionally preceded by whitespace).
var ruleDirectiveRe = regexp.MustCompile(`(?i)^\s*(SecRule|SecAction)\b`)

// ruleIDRe extracts the numeric id action from a SecRule/SecAction line.
var ruleIDRe = regexp.MustCompile(`\bid:(\d+)`)

// Source is a single input to the compiler.
type Source struct {
	// Kind identifies the resource kind, e.g. "SecRules" or "ClusterSecRules".
	Kind string
	// Name is the resource name, used in diagnostics and banner comments.
	Name string
	// Body is the raw SecLang text.
	Body string
}

// Bundle is the output of a successful compilation.
type Bundle struct {
	// Compiled is the concatenated rule text with banner comments per source.
	Compiled string
	// SHA256 is the hex-encoded sha256 digest of Compiled.
	SHA256 string
	// RuleCount is the number of SecRule/SecAction directives found.
	RuleCount int32
}

// ConflictError is returned when two sources declare the same rule ID.
type ConflictError struct {
	RuleID string
	First  string // "<Kind>/<Name>"
	Second string // "<Kind>/<Name>"
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("rule ID %s is declared in both %s and %s", e.RuleID, e.First, e.Second)
}

// Compile concatenates sources in order, preceding each with banner comments.
// It detects duplicate rule IDs across sources and returns *ConflictError on
// the first duplicate found. RuleCount counts SecRule and SecAction directives.
func Compile(sources []Source) (*Bundle, error) {
	if len(sources) == 0 {
		hash := sha256hex("")
		return &Bundle{Compiled: "", SHA256: hash, RuleCount: 0}, nil
	}

	var sb strings.Builder
	// ruleOwner maps rule ID string -> "Kind/Name" of the first source that declared it.
	ruleOwner := make(map[string]string)
	var ruleCount int32

	for _, src := range sources {
		label := src.Kind + "/" + src.Name
		fmt.Fprintf(&sb, "# --- begin %s ---\n", label)
		sb.WriteString(src.Body)
		// Ensure the body ends with a newline before the end banner.
		if len(src.Body) > 0 && src.Body[len(src.Body)-1] != '\n' {
			sb.WriteByte('\n')
		}
		fmt.Fprintf(&sb, "# --- end %s ---\n", label)

		// Scan for directives in the body.
		for line := range strings.SplitSeq(src.Body, "\n") {
			if !ruleDirectiveRe.MatchString(line) {
				continue
			}
			ruleCount++
			// Extract id: if present and check for conflicts.
			if m := ruleIDRe.FindStringSubmatch(line); m != nil {
				id := m[1]
				if owner, seen := ruleOwner[id]; seen {
					return nil, &ConflictError{RuleID: id, First: owner, Second: label}
				}
				ruleOwner[id] = label
			}
		}
	}

	compiled := sb.String()
	return &Bundle{
		Compiled:  compiled,
		SHA256:    sha256hex(compiled),
		RuleCount: ruleCount,
	}, nil
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)
}

// CountRules returns the number of SecRule/SecAction directives in seclang text.
// It is the same logic used internally by Compile; exported for callers that
// build SecLang outside the compiler pipeline (e.g. WAF swap on bundle receipt).
func CountRules(seclang string) int {
	var n int
	for line := range strings.SplitSeq(seclang, "\n") {
		if ruleDirectiveRe.MatchString(line) {
			n++
		}
	}
	return n
}
