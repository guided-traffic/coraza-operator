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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EngineType identifies the WAF engine implementation.
// +kubebuilder:validation:Enum=coraza-http
type EngineType string

const (
	// EngineTypeCorazaHTTP is the Coraza HTTP reverse-proxy engine.
	EngineTypeCorazaHTTP EngineType = "coraza-http"
)

// EngineMode controls whether the WAF blocks or only detects violations.
// +kubebuilder:validation:Enum=Detection;Blocking
type EngineMode string

const (
	// EngineModeDetection logs violations but does not block requests.
	EngineModeDetection EngineMode = "Detection"
	// EngineModeBlocking blocks requests that match rules.
	EngineModeBlocking EngineMode = "Blocking"
)

// ListenerConfig defines how the engine exposes its HTTP listener.
type ListenerConfig struct {
	// port is the TCP port the engine listens on.
	// +kubebuilder:default=8080
	// +optional
	Port int32 `json:"port,omitempty"`

	// proxyProtocol enables PROXY protocol support on the listener.
	// +kubebuilder:default=false
	// +optional
	ProxyProtocol bool `json:"proxyProtocol,omitempty"`
}

// UpstreamConfig defines the backend target the engine proxies to.
type UpstreamConfig struct {
	// url is the upstream backend URL, e.g. "http://backend.svc:80".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	URL string `json:"url"`
}

// EngineSpec defines the desired state of Engine.
type EngineSpec struct {
	// type identifies the WAF engine implementation.
	// +kubebuilder:default=coraza-http
	// +kubebuilder:validation:Enum=coraza-http
	// +optional
	Type EngineType `json:"type,omitempty"`

	// ruleSetRef references the RuleSet in the same namespace that this engine uses.
	// +kubebuilder:validation:Required
	RuleSetRef corev1.LocalObjectReference `json:"ruleSetRef"`

	// replicas is the desired number of engine pod replicas.
	// +kubebuilder:default=1
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// image overrides the default engine container image.
	// If not set, the operator uses its built-in default image.
	// +optional
	Image *string `json:"image,omitempty"`

	// listener configures the HTTP listener exposed by the engine.
	// +optional
	Listener ListenerConfig `json:"listener,omitempty"`

	// upstream configures the backend target the engine proxies requests to.
	// +kubebuilder:validation:Required
	Upstream UpstreamConfig `json:"upstream"`

	// mode controls whether the WAF operates in Detection or Blocking mode.
	// +kubebuilder:default=Detection
	// +kubebuilder:validation:Enum=Detection;Blocking
	// +optional
	Mode EngineMode `json:"mode,omitempty"`

	// resources defines CPU and memory constraints for the engine container.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`
}

// EngineStatus defines the observed state of Engine.
type EngineStatus struct {
	// conditions represent the current state of the Engine resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// observedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// readyReplicas is the number of engine pods that are ready.
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// appliedRuleSetHash is the compiledHash of the RuleSet currently active in the engine.
	// +optional
	AppliedRuleSetHash string `json:"appliedRuleSetHash,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=eng
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="RuleSet",type="string",JSONPath=".spec.ruleSetRef.name"
// +kubebuilder:printcolumn:name="Mode",type="string",JSONPath=".spec.mode"
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Hash",type="string",JSONPath=".status.appliedRuleSetHash",priority=1

// Engine is the Schema for the engines API.
type Engine struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of Engine
	// +required
	Spec EngineSpec `json:"spec"`

	// status defines the observed state of Engine
	// +optional
	Status EngineStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// EngineList contains a list of Engine.
type EngineList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Engine `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Engine{}, &EngineList{})
}
