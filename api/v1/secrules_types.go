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

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SecRulesSpec defines the desired state of SecRules.
type SecRulesSpec struct {
	// rules contains raw SecLang text to be applied by the WAF engine.
	// +kubebuilder:validation:Required
	Rules string `json:"rules"`

	// description is an optional human-readable description of these rules.
	// +optional
	Description string `json:"description,omitempty"`
}

// SecRulesStatus defines the observed state of SecRules.
type SecRulesStatus struct {
	// conditions represent the current state of the SecRules resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// observedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// parsedRuleCount is the number of rules successfully parsed from spec.rules.
	// Populated after the controller processes the resource.
	// +optional
	ParsedRuleCount int32 `json:"parsedRuleCount,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=sr
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"

// SecRules is the Schema for the secrules API.
type SecRules struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SecRules
	// +required
	Spec SecRulesSpec `json:"spec"`

	// status defines the observed state of SecRules
	// +optional
	Status SecRulesStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SecRulesList contains a list of SecRules.
type SecRulesList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecRules `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecRules{}, &SecRulesList{})
}
