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
	"errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wafv1 "github.com/guided-traffic/coraza-operator/api/v1"
	"github.com/guided-traffic/coraza-operator/internal/compiler"
	"github.com/guided-traffic/coraza-operator/internal/rulestore"
)

// RuleSetReconciler reconciles a RuleSet object.
type RuleSetReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Store  *rulestore.Store // may be nil; no-op when unset
}

// +kubebuilder:rbac:groups=waf.gtrfc.com,resources=rulesets,verbs=get;list;watch
// +kubebuilder:rbac:groups=waf.gtrfc.com,resources=rulesets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=waf.gtrfc.com,resources=secrules,verbs=get;list;watch
// +kubebuilder:rbac:groups=waf.gtrfc.com,resources=clustersecrules,verbs=get;list;watch

// Reconcile implements the reconciliation loop for RuleSet.
func (r *RuleSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var rs wafv1.RuleSet
	if err := r.Get(ctx, req.NamespacedName, &rs); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get RuleSet %s: %w", req.NamespacedName, err)
	}

	statusPatch := rs.DeepCopy()

	// Gather sources in declared order.
	sources, missing, err := r.collectSources(ctx, &rs)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("collect sources for RuleSet %s: %w", req.NamespacedName, err)
	}
	if missing != "" {
		setConditionDegraded(&statusPatch.Status.Conditions, rs.Generation, wafv1.ReasonDependencyMissing, missing)
		clearCondition(&statusPatch.Status.Conditions, wafv1.ConditionReady)
		clearCondition(&statusPatch.Status.Conditions, wafv1.ConditionProgressing)
		return r.patchStatusIfChanged(ctx, log, &rs, statusPatch)
	}

	bundle, err := compiler.Compile(sources)
	if err != nil {
		var conflictErr *compiler.ConflictError
		if errors.As(err, &conflictErr) {
			setConditionDegraded(&statusPatch.Status.Conditions, rs.Generation, wafv1.ReasonRuleConflict, err.Error())
			clearCondition(&statusPatch.Status.Conditions, wafv1.ConditionReady)
			clearCondition(&statusPatch.Status.Conditions, wafv1.ConditionProgressing)
			return r.patchStatusIfChanged(ctx, log, &rs, statusPatch)
		}
		return ctrl.Result{}, fmt.Errorf("compile RuleSet %s: %w", req.NamespacedName, err)
	}

	now := metav1.Now()
	meta.SetStatusCondition(&statusPatch.Status.Conditions, metav1.Condition{
		Type:               wafv1.ConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             wafv1.ReasonCompiled,
		Message:            fmt.Sprintf("compiled %d rules", bundle.RuleCount),
		ObservedGeneration: rs.Generation,
	})
	meta.SetStatusCondition(&statusPatch.Status.Conditions, metav1.Condition{
		Type:               wafv1.ConditionProgressing,
		Status:             metav1.ConditionFalse,
		Reason:             wafv1.ReasonCompiled,
		ObservedGeneration: rs.Generation,
	})
	meta.SetStatusCondition(&statusPatch.Status.Conditions, metav1.Condition{
		Type:               wafv1.ConditionDegraded,
		Status:             metav1.ConditionFalse,
		Reason:             wafv1.ReasonCompiled,
		ObservedGeneration: rs.Generation,
	})
	statusPatch.Status.CompiledHash = bundle.SHA256
	statusPatch.Status.RuleCount = bundle.RuleCount
	statusPatch.Status.LastCompiledAt = &now
	statusPatch.Status.ObservedGeneration = rs.Generation

	result, err := r.patchStatusIfChanged(ctx, log, &rs, statusPatch)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Publish the bundle to all engines referencing this RuleSet, after the
	// API server has accepted the status update.
	r.publishToEngines(ctx, log, &rs, bundle)

	return result, nil
}

// publishToEngines looks up all Engine objects in the same namespace whose
// spec.ruleSetRef.name matches rs.Name and publishes the compiled bundle to
// the in-memory store so gRPC subscribers receive it immediately.
// It is a no-op when Store is nil.
func (r *RuleSetReconciler) publishToEngines(
	ctx context.Context,
	log interface {
		Info(string, ...any)
		Error(error, string, ...any)
	},
	rs *wafv1.RuleSet,
	b *compiler.Bundle,
) {
	if r.Store == nil {
		return
	}

	var engineList wafv1.EngineList
	if err := r.List(ctx, &engineList, client.InNamespace(rs.Namespace)); err != nil {
		log.Error(err, "list Engines for bundle publish", "ruleset", rs.Name)
		return
	}

	for _, eng := range engineList.Items {
		if eng.Spec.RuleSetRef.Name != rs.Name {
			continue
		}
		r.Store.Publish(eng.Namespace, eng.Name, rulestore.Bundle{
			RuleSetName: rs.Name,
			SHA256:      b.SHA256,
			Compiled:    b.Compiled,
			GeneratedAt: time.Now(),
		})
		log.Info("published bundle to engine", "engine", eng.Name, "sha256", b.SHA256)
	}
}

// collectSources fetches the body of each source in spec order.
// Returns (sources, missingMessage, error).
// missingMessage is non-empty when a referenced resource was not found.
// error is non-nil only on unexpected API errors.
func (r *RuleSetReconciler) collectSources(ctx context.Context, rs *wafv1.RuleSet) ([]compiler.Source, string, error) {
	sources := make([]compiler.Source, 0, len(rs.Spec.Sources))

	for _, ref := range rs.Spec.Sources {
		switch ref.Kind {
		case wafv1.SourceRefKindSecRules, "":
			var sr wafv1.SecRules
			key := types.NamespacedName{Namespace: rs.Namespace, Name: ref.Name}
			if err := r.Get(ctx, key, &sr); err != nil {
				if apierrors.IsNotFound(err) {
					return nil, fmt.Sprintf("SecRules %s/%s not found", rs.Namespace, ref.Name), nil
				}
				return nil, "", fmt.Errorf("get SecRules %s/%s: %w", rs.Namespace, ref.Name, err)
			}
			sources = append(sources, compiler.Source{
				Kind: "SecRules",
				Name: ref.Name,
				Body: sr.Spec.Rules,
			})

		case wafv1.SourceRefKindClusterSecRules:
			var csr wafv1.ClusterSecRules
			key := types.NamespacedName{Name: ref.Name}
			if err := r.Get(ctx, key, &csr); err != nil {
				if apierrors.IsNotFound(err) {
					return nil, fmt.Sprintf("ClusterSecRules %s not found", ref.Name), nil
				}
				return nil, "", fmt.Errorf("get ClusterSecRules %s: %w", ref.Name, err)
			}
			sources = append(sources, compiler.Source{
				Kind: "ClusterSecRules",
				Name: ref.Name,
				Body: csr.Spec.Rules,
			})

		default:
			return nil, fmt.Sprintf("unknown source kind %q in spec.sources", ref.Kind), nil
		}
	}

	return sources, "", nil
}

func (r *RuleSetReconciler) patchStatusIfChanged(
	ctx context.Context,
	log interface{ Info(string, ...any) },
	original *wafv1.RuleSet,
	updated *wafv1.RuleSet,
) (ctrl.Result, error) {
	if equality.Semantic.DeepEqual(original.Status, updated.Status) {
		return ctrl.Result{}, nil
	}
	if err := r.Status().Update(ctx, updated); err != nil {
		return ctrl.Result{}, fmt.Errorf("update RuleSet status %s/%s: %w", updated.Namespace, updated.Name, err)
	}
	log.Info("status updated", "namespace", updated.Namespace, "name", updated.Name)
	return ctrl.Result{}, nil
}

// enqueueRuleSetsForSecRules maps a SecRules event to all RuleSets in the same
// namespace that reference it by name.
//
// TODO: switch to a field indexer for O(1) lookups instead of list+filter;
// acceptable for prototype but will not scale to large numbers of RuleSets.
func (r *RuleSetReconciler) enqueueRuleSetsForSecRules(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)

	var rsList wafv1.RuleSetList
	if err := r.List(ctx, &rsList, client.InNamespace(obj.GetNamespace())); err != nil {
		log.Error(err, "list RuleSets for SecRules watch", "namespace", obj.GetNamespace())
		return nil
	}

	var requests []reconcile.Request
	for _, rs := range rsList.Items {
		for _, src := range rs.Spec.Sources {
			if (src.Kind == wafv1.SourceRefKindSecRules || src.Kind == "") && src.Name == obj.GetName() {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Namespace: rs.Namespace,
						Name:      rs.Name,
					},
				})
				break
			}
		}
	}
	return requests
}

// enqueueRuleSetsForClusterSecRules maps a ClusterSecRules event to all RuleSets
// cluster-wide that reference it by name.
//
// TODO: switch to a field indexer for O(1) lookups instead of list+filter;
// acceptable for prototype but will not scale to large numbers of RuleSets.
func (r *RuleSetReconciler) enqueueRuleSetsForClusterSecRules(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)

	var rsList wafv1.RuleSetList
	if err := r.List(ctx, &rsList); err != nil {
		log.Error(err, "list RuleSets for ClusterSecRules watch")
		return nil
	}

	var requests []reconcile.Request
	for _, rs := range rsList.Items {
		for _, src := range rs.Spec.Sources {
			if src.Kind == wafv1.SourceRefKindClusterSecRules && src.Name == obj.GetName() {
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Namespace: rs.Namespace,
						Name:      rs.Name,
					},
				})
				break
			}
		}
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *RuleSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Predicate for watching SecRules/ClusterSecRules: re-enqueue on generation
	// or annotation changes (annotations may carry hash hints in future iterations).
	sourcePredicate := predicate.Or(
		predicate.GenerationChangedPredicate{},
		predicate.AnnotationChangedPredicate{},
	)

	return ctrl.NewControllerManagedBy(mgr).
		For(&wafv1.RuleSet{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Watches(
			&wafv1.SecRules{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueRuleSetsForSecRules),
			builder.WithPredicates(sourcePredicate),
		).
		Watches(
			&wafv1.ClusterSecRules{},
			handler.EnqueueRequestsFromMapFunc(r.enqueueRuleSetsForClusterSecRules),
			builder.WithPredicates(sourcePredicate),
		).
		Named("ruleset").
		Complete(r)
}
