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

package engineassets_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	wafv1 "github.com/guided-traffic/coraza-operator/api/v1"
	"github.com/guided-traffic/coraza-operator/internal/engineassets"
)

func baseEngine() *wafv1.Engine {
	return &wafv1.Engine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-engine",
			Namespace: "default",
		},
		Spec: wafv1.EngineSpec{
			RuleSetRef: corev1.LocalObjectReference{Name: "my-ruleset"},
			Upstream:   wafv1.UpstreamConfig{URL: "http://backend.svc:80"},
			Mode:       wafv1.EngineModeDetection,
		},
	}
}

func TestLabels_Stable(t *testing.T) {
	engine := baseEngine()
	a := engineassets.Labels(engine)
	b := engineassets.Labels(engine)
	assert.Equal(t, a, b, "Labels must be deterministic")
	assert.Equal(t, "coraza-engine", a["app.kubernetes.io/name"])
	assert.Equal(t, "my-engine", a["app.kubernetes.io/instance"])
	assert.Equal(t, "my-engine", a["waf.gtrfc.com/engine"])
}

func TestDeploymentName(t *testing.T) {
	engine := baseEngine()
	assert.Equal(t, "my-engine", engineassets.DeploymentName(engine))
}

func TestServiceName(t *testing.T) {
	engine := baseEngine()
	assert.Equal(t, "my-engine-svc", engineassets.ServiceName(engine))
}

func TestBuildDeployment_Metadata(t *testing.T) {
	engine := baseEngine()
	dep := engineassets.BuildDeployment(engine, "", "", "")
	assert.Equal(t, "my-engine", dep.Name)
	assert.Equal(t, "default", dep.Namespace)
	assert.Equal(t, engineassets.Labels(engine), dep.Labels)
	assert.Equal(t, engineassets.Labels(engine), dep.Spec.Selector.MatchLabels)
	assert.Equal(t, engineassets.Labels(engine), dep.Spec.Template.Labels)
}

func TestBuildDeployment_DefaultReplicas(t *testing.T) {
	engine := baseEngine()
	dep := engineassets.BuildDeployment(engine, "", "", "")
	require.NotNil(t, dep.Spec.Replicas)
	assert.Equal(t, int32(1), *dep.Spec.Replicas)
}

func TestBuildDeployment_CustomReplicas(t *testing.T) {
	engine := baseEngine()
	n := int32(3)
	engine.Spec.Replicas = &n
	dep := engineassets.BuildDeployment(engine, "", "", "")
	require.NotNil(t, dep.Spec.Replicas)
	assert.Equal(t, int32(3), *dep.Spec.Replicas)
}

func TestBuildDeployment_DefaultImage(t *testing.T) {
	engine := baseEngine()
	dep := engineassets.BuildDeployment(engine, "", "", "")
	require.Len(t, dep.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, engineassets.DefaultEngineImage, dep.Spec.Template.Spec.Containers[0].Image)
}

func TestBuildDeployment_CustomImage(t *testing.T) {
	engine := baseEngine()
	img := "my-registry/coraza-engine:v2"
	engine.Spec.Image = &img
	dep := engineassets.BuildDeployment(engine, "", "", "")
	require.Len(t, dep.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, img, dep.Spec.Template.Spec.Containers[0].Image)
}

func TestBuildDeployment_DefaultImageOverride(t *testing.T) {
	engine := baseEngine()
	// No Spec.Image set — defaultImage parameter should take effect.
	override := "harbor.example.com/myorg/coraza-engine:staging"
	dep := engineassets.BuildDeployment(engine, "", "", override)
	require.Len(t, dep.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, override, dep.Spec.Template.Spec.Containers[0].Image)
}

func TestBuildDeployment_SpecImageWinsOverDefaultOverride(t *testing.T) {
	engine := baseEngine()
	specImg := "my-registry/coraza-engine:v2"
	engine.Spec.Image = &specImg
	override := "harbor.example.com/myorg/coraza-engine:staging"
	dep := engineassets.BuildDeployment(engine, "", "", override)
	require.Len(t, dep.Spec.Template.Spec.Containers, 1)
	// engine.Spec.Image wins over defaultImage.
	assert.Equal(t, specImg, dep.Spec.Template.Spec.Containers[0].Image)
}

func TestBuildDeployment_ContainerName(t *testing.T) {
	engine := baseEngine()
	dep := engineassets.BuildDeployment(engine, "", "", "")
	require.Len(t, dep.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, "coraza-engine", dep.Spec.Template.Spec.Containers[0].Name)
}

func TestBuildDeployment_ImagePullPolicy(t *testing.T) {
	engine := baseEngine()
	dep := engineassets.BuildDeployment(engine, "", "", "")
	require.Len(t, dep.Spec.Template.Spec.Containers, 1)
	assert.Equal(t, corev1.PullAlways, dep.Spec.Template.Spec.Containers[0].ImagePullPolicy)
}

func TestBuildDeployment_DefaultListenerPort(t *testing.T) {
	engine := baseEngine()
	// Listener.Port == 0 — should default to 8080
	dep := engineassets.BuildDeployment(engine, "", "", "")
	c := dep.Spec.Template.Spec.Containers[0]
	require.Len(t, c.Ports, 1)
	assert.Equal(t, int32(8080), c.Ports[0].ContainerPort)
}

func TestBuildDeployment_CustomListenerPort(t *testing.T) {
	engine := baseEngine()
	engine.Spec.Listener.Port = 9090
	dep := engineassets.BuildDeployment(engine, "", "", "")
	c := dep.Spec.Template.Spec.Containers[0]
	require.Len(t, c.Ports, 1)
	assert.Equal(t, int32(9090), c.Ports[0].ContainerPort)
}

func TestBuildDeployment_EnvVars(t *testing.T) {
	engine := baseEngine()
	dep := engineassets.BuildDeployment(engine, "", "", "")
	envMap := envByName(dep.Spec.Template.Spec.Containers[0].Env)
	assert.Equal(t, "Detection", envMap["WAF_MODE"])
	assert.Equal(t, "http://backend.svc:80", envMap["WAF_UPSTREAM_URL"])
	_, hasHash := envMap["RULESET_HASH"]
	assert.False(t, hasHash, "RULESET_HASH env var must be absent when hash is empty")
}

func TestBuildDeployment_EnvVarsWithHash(t *testing.T) {
	engine := baseEngine()
	dep := engineassets.BuildDeployment(engine, "abc123", "", "")
	envMap := envByName(dep.Spec.Template.Spec.Containers[0].Env)
	assert.Equal(t, "abc123", envMap["RULESET_HASH"])
}

func TestBuildDeployment_RulesetHashAnnotation_Empty(t *testing.T) {
	engine := baseEngine()
	dep := engineassets.BuildDeployment(engine, "", "", "")
	_, ok := dep.Spec.Template.Annotations["waf.gtrfc.com/ruleset-hash"]
	assert.False(t, ok, "annotation must not be set when hash is empty")
}

func TestBuildDeployment_RulesetHashAnnotation_Set(t *testing.T) {
	engine := baseEngine()
	dep := engineassets.BuildDeployment(engine, "deadbeef", "", "")
	assert.Equal(t, "deadbeef", dep.Spec.Template.Annotations["waf.gtrfc.com/ruleset-hash"])
}

func TestBuildDeployment_Probes(t *testing.T) {
	engine := baseEngine()
	engine.Spec.Listener.Port = 9090
	dep := engineassets.BuildDeployment(engine, "", "", "")
	c := dep.Spec.Template.Spec.Containers[0]

	// Readiness probe must use /readyz — only passes once a valid WAF is loaded.
	require.NotNil(t, c.ReadinessProbe)
	require.NotNil(t, c.ReadinessProbe.HTTPGet)
	assert.Equal(t, "/readyz", c.ReadinessProbe.HTTPGet.Path)
	assert.Equal(t, int32(9090), c.ReadinessProbe.HTTPGet.Port.IntVal)

	// Liveness probe must use /healthz — passes as long as the WAF object is non-nil.
	require.NotNil(t, c.LivenessProbe)
	require.NotNil(t, c.LivenessProbe.HTTPGet)
	assert.Equal(t, "/healthz", c.LivenessProbe.HTTPGet.Path)
	assert.Equal(t, int32(9090), c.LivenessProbe.HTTPGet.Port.IntVal)
}

func TestBuildDeployment_RollingUpdateStrategy(t *testing.T) {
	engine := baseEngine()
	dep := engineassets.BuildDeployment(engine, "", "", "")
	assert.Equal(t, "RollingUpdate", string(dep.Spec.Strategy.Type))
	require.NotNil(t, dep.Spec.Strategy.RollingUpdate)
	assert.Equal(t, int32(1), dep.Spec.Strategy.RollingUpdate.MaxSurge.IntVal)
	assert.Equal(t, int32(0), dep.Spec.Strategy.RollingUpdate.MaxUnavailable.IntVal)
}

func TestBuildService_Metadata(t *testing.T) {
	engine := baseEngine()
	svc := engineassets.BuildService(engine)
	assert.Equal(t, "my-engine-svc", svc.Name)
	assert.Equal(t, "default", svc.Namespace)
	assert.Equal(t, engineassets.Labels(engine), svc.Labels)
}

func TestBuildService_ClusterIP(t *testing.T) {
	engine := baseEngine()
	svc := engineassets.BuildService(engine)
	assert.Equal(t, corev1.ServiceTypeClusterIP, svc.Spec.Type)
}

func TestBuildService_Port(t *testing.T) {
	engine := baseEngine()
	engine.Spec.Listener.Port = 9090
	svc := engineassets.BuildService(engine)
	require.Len(t, svc.Spec.Ports, 1)
	assert.Equal(t, "http", svc.Spec.Ports[0].Name)
	assert.Equal(t, int32(9090), svc.Spec.Ports[0].Port)
	assert.Equal(t, int32(9090), svc.Spec.Ports[0].TargetPort.IntVal)
}

func TestBuildService_DefaultPort(t *testing.T) {
	engine := baseEngine()
	svc := engineassets.BuildService(engine)
	require.Len(t, svc.Spec.Ports, 1)
	assert.Equal(t, int32(8080), svc.Spec.Ports[0].Port)
}

func TestBuildService_Selector(t *testing.T) {
	engine := baseEngine()
	svc := engineassets.BuildService(engine)
	assert.Equal(t, engineassets.Labels(engine), svc.Spec.Selector)
}

func TestBuildDeployment_GRPCEnvVars_Empty(t *testing.T) {
	engine := baseEngine()
	dep := engineassets.BuildDeployment(engine, "", "", "")
	envMap := envByName(dep.Spec.Template.Spec.Containers[0].Env)
	_, hasAddr := envMap["ENGINE_OPERATOR_ADDR"]
	assert.False(t, hasAddr, "ENGINE_OPERATOR_ADDR must be absent when operatorGRPCAddr is empty")
}

func TestBuildDeployment_GRPCEnvVars_Set(t *testing.T) {
	engine := baseEngine()
	dep := engineassets.BuildDeployment(engine, "", "coraza-operator-grpc.system.svc:9443", "")
	c := dep.Spec.Template.Spec.Containers[0]

	// Find ENGINE_OPERATOR_ADDR.
	var found []corev1.EnvVar
	for _, e := range c.Env {
		if e.Name == "ENGINE_OPERATOR_ADDR" || e.Name == "ENGINE_NAMESPACE" || e.Name == "ENGINE_NAME" {
			found = append(found, e)
		}
	}
	require.Len(t, found, 3, "expected ENGINE_OPERATOR_ADDR, ENGINE_NAMESPACE, ENGINE_NAME")

	for _, e := range found {
		switch e.Name {
		case "ENGINE_OPERATOR_ADDR":
			assert.Equal(t, "coraza-operator-grpc.system.svc:9443", e.Value)
		case "ENGINE_NAMESPACE":
			require.NotNil(t, e.ValueFrom)
			require.NotNil(t, e.ValueFrom.FieldRef)
			assert.Equal(t, "metadata.namespace", e.ValueFrom.FieldRef.FieldPath)
		case "ENGINE_NAME":
			assert.Nil(t, e.ValueFrom, "ENGINE_NAME must be a literal value, not a fieldRef")
			assert.Equal(t, "my-engine", e.Value)
		}
	}
}

func TestBuildDeployment_SPOAPort_Unset(t *testing.T) {
	engine := baseEngine()
	// SPOAPort defaults to 0 — no second port, no ENGINE_SPOA_ADDR env var.
	dep := engineassets.BuildDeployment(engine, "", "", "")
	c := dep.Spec.Template.Spec.Containers[0]

	require.Len(t, c.Ports, 1, "only http port expected when SPOAPort is 0")
	assert.Equal(t, "http", c.Ports[0].Name)

	envMap := envByName(c.Env)
	_, has := envMap["ENGINE_SPOA_ADDR"]
	assert.False(t, has, "ENGINE_SPOA_ADDR must not be set when SPOAPort is 0")
}

func TestBuildDeployment_SPOAPort_Set(t *testing.T) {
	engine := baseEngine()
	engine.Spec.Listener.SPOAPort = 9000
	dep := engineassets.BuildDeployment(engine, "", "", "")
	c := dep.Spec.Template.Spec.Containers[0]

	require.Len(t, c.Ports, 2, "http + spoa ports expected when SPOAPort is non-zero")
	assert.Equal(t, "http", c.Ports[0].Name)
	assert.Equal(t, "spoa", c.Ports[1].Name)
	assert.Equal(t, int32(9000), c.Ports[1].ContainerPort)

	envMap := envByName(c.Env)
	assert.Equal(t, ":9000", envMap["ENGINE_SPOA_ADDR"])
}

func TestBuildService_SPOAPort_Unset(t *testing.T) {
	engine := baseEngine()
	svc := engineassets.BuildService(engine)
	require.Len(t, svc.Spec.Ports, 1, "only http port expected when SPOAPort is 0")
	assert.Equal(t, "http", svc.Spec.Ports[0].Name)
}

func TestBuildService_SPOAPort_Set(t *testing.T) {
	engine := baseEngine()
	engine.Spec.Listener.SPOAPort = 9000
	svc := engineassets.BuildService(engine)
	require.Len(t, svc.Spec.Ports, 2, "http + spoa ports expected when SPOAPort is non-zero")
	assert.Equal(t, "http", svc.Spec.Ports[0].Name)
	assert.Equal(t, "spoa", svc.Spec.Ports[1].Name)
	assert.Equal(t, int32(9000), svc.Spec.Ports[1].Port)
	assert.Equal(t, "spoa", svc.Spec.Ports[1].TargetPort.String())
}

// envByName converts an env slice to a name→value map for easy assertion.
// Only captures envvars with a plain Value (not ValueFrom).
func envByName(env []corev1.EnvVar) map[string]string {
	m := make(map[string]string, len(env))
	for _, e := range env {
		m[e.Name] = e.Value
	}
	return m
}
