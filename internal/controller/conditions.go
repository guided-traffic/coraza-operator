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

package controller

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wafv1 "github.com/guided-traffic/coraza-operator/api/v1"
)

// setConditionDegraded sets the Degraded condition to True.
func setConditionDegraded(conditions *[]metav1.Condition, generation int64, reason, message string) {
	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:               wafv1.ConditionDegraded,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
	})
}

// clearCondition removes a condition by type if present.
func clearCondition(conditions *[]metav1.Condition, condType string) {
	meta.RemoveStatusCondition(conditions, condType)
}
