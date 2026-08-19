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
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wafv1 "github.com/guided-traffic/coraza-operator/api/v1"
	"github.com/guided-traffic/coraza-operator/internal/compiler"
	"github.com/guided-traffic/coraza-operator/internal/engineassets"
	"github.com/guided-traffic/coraza-operator/internal/rulestore"
)

// EngineReconciler reconciles an Engine object.
type EngineReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	Store            *rulestore.Store // may be nil in tests that don't exercise store
	OperatorGRPCAddr string           // e.g. "coraza-operator-grpc.coraza-system.svc:9443"
	DefaultEngineImage string         // overrides engineassets.DefaultEngineImage when non-empty
}

// +kubebuilder:rbac:groups=waf.gtrfc.com,resources=engines,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=waf.gtrfc.com,resources=engines/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=waf.gtrfc.com,resources=rulesets,verbs=get;list;watch
// +kubebuilder:rbac:groups=waf.gtrfc.com,resources=secrules,verbs=get;list;watch
// +kubebuilder:rbac:groups=waf.gtrfc.com,resources=clustersecrules,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create

// Reconcile implements the reconciliation loop for Engine.
func (r *EngineReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var engine wafv1.Engine
	if err := r.Get(ctx, req.NamespacedName, &engine); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get Engine %s: %w", req.NamespacedName, err)
	}

	statusPatch := engine.DeepCopy()

	// Step 1: resolve the referenced RuleSet.
	var ruleset wafv1.RuleSet
	rsKey := types.NamespacedName{Namespace: engine.Namespace, Name: engine.Spec.RuleSetRef.Name}
	if err := r.Get(ctx, rsKey, &ruleset); err != nil {
		if apierrors.IsNotFound(err) {
			msg := fmt.Sprintf("RuleSet %s/%s not found", engine.Namespace, engine.Spec.RuleSetRef.Name)
			log.Info(msg)
			setConditionDegraded(&statusPatch.Status.Conditions, engine.Generation, wafv1.ReasonDependencyMissing, msg)
			clearCondition(&statusPatch.Status.Conditions, wafv1.ConditionReady)
			clearCondition(&statusPatch.Status.Conditions, wafv1.ConditionProgressing)
			return r.patchEngineStatusIfChanged(ctx, log, &engine, statusPatch)
		}
		return ctrl.Result{}, fmt.Errorf("get RuleSet %s: %w", rsKey, err)
	}

	// Step 2: wait for RuleSet to be compiled.
	if ruleset.Status.CompiledHash == "" {
		log.Info("RuleSet not yet compiled, requeueing", "ruleset", rsKey)
		meta.SetStatusCondition(&statusPatch.Status.Conditions, metav1.Condition{
			Type:               wafv1.ConditionProgressing,
			Status:             metav1.ConditionTrue,
			Reason:             "WaitingForRuleSetCompilation",
			Message:            fmt.Sprintf("waiting for RuleSet %s to be compiled", engine.Spec.RuleSetRef.Name),
			ObservedGeneration: engine.Generation,
		})
		clearCondition(&statusPatch.Status.Conditions, wafv1.ConditionReady)
		if _, err := r.patchEngineStatusIfChanged(ctx, log, &engine, statusPatch); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Step 3: compile the full SecLang bundle for the ConfigMap.
	bundle, err := compileRuleSet(ctx, r.Client, engine.Namespace, &ruleset)
	if err != nil {
		msg := fmt.Sprintf("compile RuleSet %s: %v", rsKey, err)
		log.Error(err, "failed to compile RuleSet for engine")
		setConditionDegraded(&statusPatch.Status.Conditions, engine.Generation, wafv1.ReasonDependencyMissing, msg)
		clearCondition(&statusPatch.Status.Conditions, wafv1.ConditionReady)
		clearCondition(&statusPatch.Status.Conditions, wafv1.ConditionProgressing)
		if _, patchErr := r.patchEngineStatusIfChanged(ctx, log, &engine, statusPatch); patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	appliedHash := bundle.SHA256

	// Step 4: build desired objects.
	desiredCM := engineassets.BuildRulesConfigMap(&engine, bundle.Compiled)
	desiredDep := engineassets.BuildDeployment(&engine, appliedHash, r.OperatorGRPCAddr, r.DefaultEngineImage)
	desiredSvc := engineassets.BuildService(&engine)
	desiredSA := engineassets.BuildServiceAccount(&engine)

	// Step 5: set owner references so GC cleans up on Engine deletion.
	if err := controllerutil.SetControllerReference(&engine, desiredCM, r.Scheme); err != nil {
		return ctrl.Result{}, fmt.Errorf("set owner reference on ConfigMap: %w", err)
	}
	if err := controllerutil.SetControllerReference(&engine, desiredDep, r.Scheme); err != nil {
		return ctrl.Result{}, fmt.Errorf("set owner reference on Deployment: %w", err)
	}
	if err := controllerutil.SetControllerReference(&engine, desiredSvc, r.Scheme); err != nil {
		return ctrl.Result{}, fmt.Errorf("set owner reference on Service: %w", err)
	}
	if err := controllerutil.SetControllerReference(&engine, desiredSA, r.Scheme); err != nil {
		return ctrl.Result{}, fmt.Errorf("set owner reference on ServiceAccount: %w", err)
	}

	// Step 5a: CreateOrPatch ServiceAccount.
	var existingSA corev1.ServiceAccount
	existingSA.Name = desiredSA.Name
	existingSA.Namespace = desiredSA.Namespace
	saResult, err := controllerutil.CreateOrPatch(ctx, r.Client, &existingSA, func() error {
		return mutateSA(desiredSA, &existingSA)
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("reconcile ServiceAccount %s/%s: %w", desiredSA.Namespace, desiredSA.Name, err)
	}
	if saResult != controllerutil.OperationResultNone {
		log.Info("ServiceAccount reconciled", "result", saResult, "name", existingSA.Name)
	}

	// Step 6a: CreateOrPatch ConfigMap.
	var existingCM corev1.ConfigMap
	existingCM.Name = desiredCM.Name
	existingCM.Namespace = desiredCM.Namespace
	cmResult, err := controllerutil.CreateOrPatch(ctx, r.Client, &existingCM, func() error {
		return mutateConfigMap(desiredCM, &existingCM)
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("reconcile ConfigMap %s/%s: %w", desiredCM.Namespace, desiredCM.Name, err)
	}
	if cmResult != controllerutil.OperationResultNone {
		log.Info("ConfigMap reconciled", "result", cmResult, "name", existingCM.Name)
	}

	// Step 6b: CreateOrPatch Deployment.
	var existingDep appsv1.Deployment
	existingDep.Name = desiredDep.Name
	existingDep.Namespace = desiredDep.Namespace
	depResult, err := controllerutil.CreateOrPatch(ctx, r.Client, &existingDep, func() error {
		return mutateDeployment(desiredDep, &existingDep)
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("reconcile Deployment %s/%s: %w", desiredDep.Namespace, desiredDep.Name, err)
	}
	if depResult != controllerutil.OperationResultNone {
		log.Info("Deployment reconciled", "result", depResult, "name", existingDep.Name)
	}

	// Step 6c: CreateOrPatch Service.
	var existingSvc corev1.Service
	existingSvc.Name = desiredSvc.Name
	existingSvc.Namespace = desiredSvc.Namespace
	svcResult, err := controllerutil.CreateOrPatch(ctx, r.Client, &existingSvc, func() error {
		return mutateService(desiredSvc, &existingSvc)
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("reconcile Service %s/%s: %w", desiredSvc.Namespace, desiredSvc.Name, err)
	}
	if svcResult != controllerutil.OperationResultNone {
		log.Info("Service reconciled", "result", svcResult, "name", existingSvc.Name)
	}

	// Step 7: read back Deployment status.
	var currentDep appsv1.Deployment
	if err := r.Get(ctx, types.NamespacedName{Namespace: engine.Namespace, Name: engineassets.DeploymentName(&engine)}, &currentDep); err != nil {
		return ctrl.Result{}, fmt.Errorf("get Deployment %s after apply: %w", engineassets.DeploymentName(&engine), err)
	}

	readyReplicas := currentDep.Status.ReadyReplicas
	desiredReplicas := int32(1)
	if engine.Spec.Replicas != nil {
		desiredReplicas = *engine.Spec.Replicas
	}

	// Step 8: set status fields.
	statusPatch.Status.ObservedGeneration = engine.Generation
	statusPatch.Status.AppliedRuleSetHash = appliedHash
	statusPatch.Status.ReadyReplicas = readyReplicas

	if readyReplicas == desiredReplicas {
		meta.SetStatusCondition(&statusPatch.Status.Conditions, metav1.Condition{
			Type:               wafv1.ConditionReady,
			Status:             metav1.ConditionTrue,
			Reason:             wafv1.ReasonReconciled,
			Message:            "engine deployment is ready",
			ObservedGeneration: engine.Generation,
		})
		meta.SetStatusCondition(&statusPatch.Status.Conditions, metav1.Condition{
			Type:               wafv1.ConditionProgressing,
			Status:             metav1.ConditionFalse,
			Reason:             wafv1.ReasonReconciled,
			ObservedGeneration: engine.Generation,
		})
		meta.SetStatusCondition(&statusPatch.Status.Conditions, metav1.Condition{
			Type:               wafv1.ConditionDegraded,
			Status:             metav1.ConditionFalse,
			Reason:             wafv1.ReasonReconciled,
			ObservedGeneration: engine.Generation,
		})
		result, patchErr := r.patchEngineStatusIfChanged(ctx, log, &engine, statusPatch)
		if patchErr != nil {
			return ctrl.Result{}, patchErr
		}
		r.publishBundle(engine.Namespace, engine.Name, ruleset.Name, bundle)
		return result, nil
	}

	// Rollout in progress.
	meta.SetStatusCondition(&statusPatch.Status.Conditions, metav1.Condition{
		Type:               wafv1.ConditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             "DeploymentRollingOut",
		Message:            fmt.Sprintf("%d/%d replicas ready", readyReplicas, desiredReplicas),
		ObservedGeneration: engine.Generation,
	})
	meta.SetStatusCondition(&statusPatch.Status.Conditions, metav1.Condition{
		Type:               wafv1.ConditionProgressing,
		Status:             metav1.ConditionTrue,
		Reason:             "DeploymentRollingOut",
		Message:            fmt.Sprintf("%d/%d replicas ready", readyReplicas, desiredReplicas),
		ObservedGeneration: engine.Generation,
	})
	meta.SetStatusCondition(&statusPatch.Status.Conditions, metav1.Condition{
		Type:               wafv1.ConditionDegraded,
		Status:             metav1.ConditionFalse,
		Reason:             "DeploymentRollingOut",
		ObservedGeneration: engine.Generation,
	})

	if _, err := r.patchEngineStatusIfChanged(ctx, log, &engine, statusPatch); err != nil {
		return ctrl.Result{}, err
	}
	r.publishBundle(engine.Namespace, engine.Name, ruleset.Name, bundle)
	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

// publishBundle publishes the compiled bundle to the rulestore if a Store is wired.
// It is a no-op when Store is nil (e.g. in envtest controller tests).
func (r *EngineReconciler) publishBundle(engineNS, engineName, ruleSetName string, b *compiler.Bundle) {
	if r.Store == nil {
		return
	}
	r.Store.PublishIfChanged(engineNS, engineName, rulestore.Bundle{
		RuleSetName: ruleSetName,
		SHA256:      b.SHA256,
		Compiled:    b.Compiled,
		GeneratedAt: time.Now(),
	})
}

// compileRuleSet re-compiles the SecLang bundle from the sources referenced by rs.
// This is intentionally re-computed on each reconcile to keep the ConfigMap in sync;
// the SHA256 in RuleSet.Status gates rollouts.
func compileRuleSet(ctx context.Context, c client.Client, ns string, rs *wafv1.RuleSet) (*compiler.Bundle, error) {
	sources := make([]compiler.Source, 0, len(rs.Spec.Sources))

	for _, ref := range rs.Spec.Sources {
		switch ref.Kind {
		case wafv1.SourceRefKindSecRules, "":
			var sr wafv1.SecRules
			key := types.NamespacedName{Namespace: ns, Name: ref.Name}
			if err := c.Get(ctx, key, &sr); err != nil {
				if apierrors.IsNotFound(err) {
					return nil, fmt.Errorf("SecRules %s/%s not found", ns, ref.Name)
				}
				return nil, fmt.Errorf("get SecRules %s/%s: %w", ns, ref.Name, err)
			}
			sources = append(sources, compiler.Source{Kind: "SecRules", Name: ref.Name, Body: sr.Spec.Rules})

		case wafv1.SourceRefKindClusterSecRules:
			var csr wafv1.ClusterSecRules
			key := types.NamespacedName{Name: ref.Name}
			if err := c.Get(ctx, key, &csr); err != nil {
				if apierrors.IsNotFound(err) {
					return nil, fmt.Errorf("ClusterSecRules %s not found", ref.Name)
				}
				return nil, fmt.Errorf("get ClusterSecRules %s: %w", ref.Name, err)
			}
			sources = append(sources, compiler.Source{Kind: "ClusterSecRules", Name: ref.Name, Body: csr.Spec.Rules})

		default:
			return nil, fmt.Errorf("unknown source kind %q in spec.sources", ref.Kind)
		}
	}

	bundle, err := compiler.Compile(sources)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	return bundle, nil
}

// mutateSA copies managed fields from desired onto existing ServiceAccount.
func mutateSA(desired, existing *corev1.ServiceAccount) error {
	existing.Labels = desired.Labels
	existing.Annotations = desired.Annotations
	existing.OwnerReferences = desired.OwnerReferences
	return nil
}

// mutateConfigMap copies managed fields from desired onto existing.
func mutateConfigMap(desired, existing *corev1.ConfigMap) error {
	existing.Labels = desired.Labels
	existing.Annotations = desired.Annotations
	existing.OwnerReferences = desired.OwnerReferences
	existing.Data = desired.Data
	return nil
}

// mutateDeployment copies managed fields from desired onto existing.
// Selector is immutable after creation; returns an error if it changed.
func mutateDeployment(desired, existing *appsv1.Deployment) error {
	// On create the existing object has empty labels/annotations — copy them.
	existing.Labels = desired.Labels
	existing.Annotations = desired.Annotations

	// Copy owner references from desired (set by SetControllerReference).
	existing.OwnerReferences = desired.OwnerReferences

	// Selector is immutable: set only on create (when ResourceVersion is empty).
	if existing.ResourceVersion == "" {
		existing.Spec.Selector = desired.Spec.Selector
	}

	existing.Spec.Replicas = desired.Spec.Replicas
	existing.Spec.Template = desired.Spec.Template
	existing.Spec.Strategy = desired.Spec.Strategy
	return nil
}

// mutateService copies managed fields from desired onto existing.
// ClusterIP is preserved (it's assigned by the API server and immutable).
func mutateService(desired, existing *corev1.Service) error {
	existing.Labels = desired.Labels
	existing.Annotations = desired.Annotations
	existing.OwnerReferences = desired.OwnerReferences

	existing.Spec.Ports = desired.Spec.Ports
	existing.Spec.Selector = desired.Spec.Selector
	existing.Spec.Type = desired.Spec.Type
	return nil
}

// patchEngineStatusIfChanged updates Engine status only when it has changed.
func (r *EngineReconciler) patchEngineStatusIfChanged(
	ctx context.Context,
	log interface{ Info(string, ...any) },
	original *wafv1.Engine,
	updated *wafv1.Engine,
) (ctrl.Result, error) {
	if equality.Semantic.DeepEqual(original.Status, updated.Status) {
		return ctrl.Result{}, nil
	}
	if err := r.Status().Update(ctx, updated); err != nil {
		return ctrl.Result{}, fmt.Errorf("update Engine status %s/%s: %w", updated.Namespace, updated.Name, err)
	}
	log.Info("status updated", "namespace", updated.Namespace, "name", updated.Name)
	return ctrl.Result{}, nil
}

// enqueueEnginesForRuleSet maps a RuleSet event to all Engines in the same
// namespace that reference it by name.
//
// TODO: switch to a field indexer for O(1) lookups instead of list+filter;
// acceptable for prototype but will not scale to large numbers of Engines.
func (r *EngineReconciler) enqueueEnginesForRuleSet(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)

	var engineList wafv1.EngineList
	if err := r.List(ctx, &engineList, client.InNamespace(obj.GetNamespace())); err != nil {
		log.Error(err, "list Engines for RuleSet watch", "namespace", obj.GetNamespace())
		return nil
	}

	var requests []reconcile.Request
	for _, eng := range engineList.Items {
		if eng.Spec.RuleSetRef.Name == obj.GetName() {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: eng.Namespace,
					Name:      eng.Name,
				},
			})
		}
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *EngineReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wafv1.Engine{}, builder.WithPredicates(
			predicate.Or(
				predicate.GenerationChangedPredicate{},
				predicate.AnnotationChangedPredicate{},
			),
		)).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.ServiceAccount{}).
		Watches(
			&wafv1.RuleSet{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueEnginesForRuleSet),
		).
		Named("engine").
		Complete(r)
}
