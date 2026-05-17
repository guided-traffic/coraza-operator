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

package v1

// Condition type constants used across all coraza-operator CRDs.
const (
	// ConditionReady indicates the resource is fully reconciled and operational.
	ConditionReady = "Ready"
	// ConditionProgressing indicates the resource is being created or updated.
	ConditionProgressing = "Progressing"
	// ConditionDegraded indicates the resource has encountered an error and is not fully functional.
	ConditionDegraded = "Degraded"
)

// Reason constants used in condition Reason fields.
const (
	// ReasonReconciling is used when a reconcile loop is actively in progress.
	ReasonReconciling = "Reconciling"
	// ReasonReconciled is used when reconciliation completed successfully.
	ReasonReconciled = "Reconciled"
	// ReasonInvalidSpec is used when the resource spec fails validation.
	ReasonInvalidSpec = "InvalidSpec"
	// ReasonDependencyMissing is used when a referenced resource (e.g. RuleSet, SecRules) cannot be found.
	ReasonDependencyMissing = "DependencyMissing"
	// ReasonRuleConflict is used when duplicate SecRule IDs are detected across sources.
	ReasonRuleConflict = "RuleConflict"
	// ReasonCompiled is used when a RuleSet has been successfully compiled.
	ReasonCompiled = "Compiled"
)
