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

// SourceRefKind enumerates the allowed kinds for a SourceRef.
// +kubebuilder:validation:Enum=SecRules;ClusterSecRules
type SourceRefKind string

const (
	// SourceRefKindSecRules references a namespace-scoped SecRules object.
	SourceRefKindSecRules SourceRefKind = "SecRules"
	// SourceRefKindClusterSecRules references a cluster-scoped ClusterSecRules object.
	SourceRefKindClusterSecRules SourceRefKind = "ClusterSecRules"
)

// SourceRef is a reference to either a SecRules or ClusterSecRules resource.
type SourceRef struct {
	// kind is the resource kind being referenced.
	// +kubebuilder:default=SecRules
	// +kubebuilder:validation:Enum=SecRules;ClusterSecRules
	// +optional
	Kind SourceRefKind `json:"kind,omitempty"`

	// name is the name of the referenced resource.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// RuleSetSpec defines the desired state of RuleSet.
type RuleSetSpec struct {
	// sources is an ordered list of SecRules/ClusterSecRules references whose
	// rules are merged (in declared order) into a single compiled bundle.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Sources []SourceRef `json:"sources"`
}

// RuleSetStatus defines the observed state of RuleSet.
type RuleSetStatus struct {
	// conditions represent the current state of the RuleSet resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// observedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// compiledHash is the sha256 hash of the compiled rule bundle.
	// +optional
	CompiledHash string `json:"compiledHash,omitempty"`

	// ruleCount is the total number of rules in the compiled bundle.
	// +optional
	RuleCount int32 `json:"ruleCount,omitempty"`

	// lastCompiledAt is the timestamp of the most recent successful compilation.
	// +optional
	LastCompiledAt *metav1.Time `json:"lastCompiledAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=rs
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Hash",type="string",JSONPath=".status.compiledHash",priority=0
// +kubebuilder:printcolumn:name="Rules",type="integer",JSONPath=".status.ruleCount"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"

// RuleSet is the Schema for the rulesets API.
type RuleSet struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of RuleSet
	// +required
	Spec RuleSetSpec `json:"spec"`

	// status defines the observed state of RuleSet
	// +optional
	Status RuleSetStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// RuleSetList contains a list of RuleSet.
type RuleSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []RuleSet `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RuleSet{}, &RuleSetList{})
}
