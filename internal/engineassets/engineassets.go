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

// Package engineassets provides pure builder functions that construct the
// desired Deployment, Service, and ConfigMap objects from an Engine spec.
// No side effects, no client calls.
package engineassets

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	wafv1 "github.com/guided-traffic/coraza-operator/api/v1"
)

// saTokenExpiry is captured here so it can be referenced in a pointer below.
var saTokenExpiry = saTokenExpiration

// DefaultEngineImage is used when Engine.Spec.Image is nil.
const DefaultEngineImage = "docker.io/guidedtraffic/coraza-engine:dev"

// RulesConfigMapMountPath is the directory inside the engine container where
// the rules ConfigMap is mounted.
const RulesConfigMapMountPath = "/etc/coraza"

// RulesConfigMapKey is the key inside the ConfigMap that holds the compiled SecLang bundle.
const RulesConfigMapKey = "rules.conf"

// RulesFilePath is the full path to the rules file inside the container.
const RulesFilePath = RulesConfigMapMountPath + "/" + RulesConfigMapKey

const (
	annotationRulesetHash = "waf.gtrfc.com/ruleset-hash"
	labelAppName          = "app.kubernetes.io/name"
	labelAppInstance      = "app.kubernetes.io/instance"
	labelEngine           = "waf.gtrfc.com/engine"

	defaultListenerPort int32 = 8080
	containerName             = "coraza-engine"
	rulesVolumeName           = "coraza-rules"

	// SATokenVolumeName is the projected ServiceAccount token volume name.
	SATokenVolumeName = "coraza-sa-token"
	// SATokenMountPath is where the projected SA token is mounted.
	SATokenMountPath = "/var/run/secrets/coraza"
	// SATokenFile is the full path to the projected SA token file.
	SATokenFile = SATokenMountPath + "/token"
	// SATokenAudience is the audience used for the projected SA token.
	SATokenAudience = "coraza-operator"
	// saTokenExpiration is the SA token expiration in seconds.
	saTokenExpiration int64 = 3600

	// CertStateVolumeName is the emptyDir volume for cert cache state.
	CertStateVolumeName = "coraza-state"
	// CertStateMountPath is where the cert state volume is mounted.
	CertStateMountPath = "/var/lib/coraza"
)

// ServiceAccountName returns the ServiceAccount name for an engine.
func ServiceAccountName(engine *wafv1.Engine) string { return engine.Name + "-engine" }

// Labels returns the canonical label set for resources owned by engine.
func Labels(engine *wafv1.Engine) map[string]string {
	return map[string]string{
		labelAppName:     "coraza-engine",
		labelAppInstance: engine.Name,
		labelEngine:      engine.Name,
	}
}

// DeploymentName returns the deterministic Deployment name for an engine.
func DeploymentName(engine *wafv1.Engine) string { return engine.Name }

// ServiceName returns the Service name (engine.Name + "-svc").
func ServiceName(engine *wafv1.Engine) string { return engine.Name + "-svc" }

// RulesConfigMapName returns the name of the ConfigMap holding the compiled rule bundle.
func RulesConfigMapName(engine *wafv1.Engine) string { return engine.Name + "-rules" }

// BuildServiceAccount builds the desired ServiceAccount for the engine's pods.
// The SA is named "<engine.Name>-engine" and is owned by the Engine.
func BuildServiceAccount(engine *wafv1.Engine) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceAccountName(engine),
			Namespace: engine.Namespace,
			Labels:    Labels(engine),
		},
	}
}

// BuildRulesConfigMap builds the desired ConfigMap holding the compiled SecLang bundle.
// bundle is the raw compiled text (e.g. compiler.Bundle.Compiled).
func BuildRulesConfigMap(engine *wafv1.Engine, bundle string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      RulesConfigMapName(engine),
			Namespace: engine.Namespace,
			Labels:    Labels(engine),
		},
		Data: map[string]string{
			RulesConfigMapKey: bundle,
		},
	}
}

// BuildDeployment builds the desired Deployment for the given Engine.
// appliedRuleSetHash, if non-empty, is set as pod-template annotation to trigger rollouts.
// operatorGRPCAddr is the operator's gRPC service address (e.g. "coraza-operator-grpc.coraza-system.svc:9443").
// If empty, the gRPC env vars are omitted.
// defaultImage overrides DefaultEngineImage when engine.Spec.Image is nil and defaultImage is non-empty.
func BuildDeployment(engine *wafv1.Engine, appliedRuleSetHash, operatorGRPCAddr, defaultImage string) *appsv1.Deployment {
	labels := Labels(engine)

	replicas := int32(1)
	if engine.Spec.Replicas != nil {
		replicas = *engine.Spec.Replicas
	}

	image := DefaultEngineImage
	if defaultImage != "" {
		image = defaultImage
	}
	if engine.Spec.Image != nil && *engine.Spec.Image != "" {
		image = *engine.Spec.Image
	}

	port := defaultListenerPort
	if engine.Spec.Listener.Port != 0 {
		port = engine.Spec.Listener.Port
	}

	podAnnotations := map[string]string{}
	if appliedRuleSetHash != "" {
		podAnnotations[annotationRulesetHash] = appliedRuleSetHash
	}

	envVars := []corev1.EnvVar{
		{Name: "WAF_MODE", Value: string(engine.Spec.Mode)},
		{Name: "WAF_UPSTREAM_URL", Value: engine.Spec.Upstream.URL},
		// Engine binary env vars.
		{Name: "ENGINE_UPSTREAM_URL", Value: engine.Spec.Upstream.URL},
		{Name: "ENGINE_MODE", Value: string(engine.Spec.Mode)},
		{Name: "ENGINE_RULE_FILE", Value: RulesFilePath},
	}
	if appliedRuleSetHash != "" {
		envVars = append(envVars, corev1.EnvVar{Name: "RULESET_HASH", Value: appliedRuleSetHash})
	}
	if operatorGRPCAddr != "" {
		envVars = append(envVars,
			corev1.EnvVar{Name: "ENGINE_OPERATOR_ADDR", Value: operatorGRPCAddr},
			corev1.EnvVar{
				Name: "ENGINE_NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
				},
			},
			corev1.EnvVar{
				Name: "ENGINE_NAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
				},
			},
		)
	}

	maxSurge := intstr.FromInt32(1)
	maxUnavailable := intstr.FromInt32(0)

	// livenessProbe: 200 if the WAF object is non-nil (process is healthy).
	livenessProbe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/healthz",
				Port: intstr.FromInt32(port),
			},
		},
	}

	// readinessProbe: 200 once a valid WAF has been loaded (SHA non-empty).
	// This prevents traffic from reaching the engine before the initial rule file
	// (or the first gRPC bundle) has been successfully parsed.
	readinessProbe := &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/readyz",
				Port: intstr.FromInt32(port),
			},
		},
	}

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeploymentName(engine),
			Namespace: engine.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxSurge:       &maxSurge,
					MaxUnavailable: &maxUnavailable,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      labels,
					Annotations: podAnnotations,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: ServiceAccountName(engine),
					Volumes: []corev1.Volume{
						{
							Name: rulesVolumeName,
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: RulesConfigMapName(engine),
									},
								},
							},
						},
						{
							// coraza-state: emptyDir for persisting the enrolled client cert
							// and CA cert between container restarts.
							Name: CertStateVolumeName,
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
						{
							// coraza-sa-token: projected SA token for bootstrap enrollment.
							Name: SATokenVolumeName,
							VolumeSource: corev1.VolumeSource{
								Projected: &corev1.ProjectedVolumeSource{
									Sources: []corev1.VolumeProjection{
										{
											ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
												Path:              "token",
												Audience:          SATokenAudience,
												ExpirationSeconds: &saTokenExpiry,
											},
										},
									},
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  containerName,
							Image: image,
							Ports: []corev1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: port,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							Env:       envVars,
							Resources: engine.Spec.Resources,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      rulesVolumeName,
									MountPath: RulesConfigMapMountPath,
									ReadOnly:  true,
								},
								{
									Name:      CertStateVolumeName,
									MountPath: CertStateMountPath,
								},
								{
									Name:      SATokenVolumeName,
									MountPath: SATokenMountPath,
									ReadOnly:  true,
								},
							},
							ReadinessProbe: readinessProbe,
							LivenessProbe:  livenessProbe,
						},
					},
				},
			},
		},
	}

	return dep
}

// BuildService builds the desired ClusterIP Service exposing the listener port.
func BuildService(engine *wafv1.Engine) *corev1.Service {
	labels := Labels(engine)

	port := defaultListenerPort
	if engine.Spec.Listener.Port != 0 {
		port = engine.Spec.Listener.Port
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceName(engine),
			Namespace: engine.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: labels,
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       port,
					TargetPort: intstr.FromInt32(port),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}
