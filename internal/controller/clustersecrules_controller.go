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

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	wafv1 "github.com/guided-traffic/coraza-operator/api/v1"
	"github.com/guided-traffic/coraza-operator/internal/compiler"
)

// ClusterSecRulesReconciler reconciles a ClusterSecRules object.
type ClusterSecRulesReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=waf.gtrfc.com,resources=clustersecrules,verbs=get;list;watch
// +kubebuilder:rbac:groups=waf.gtrfc.com,resources=clustersecrules/status,verbs=get;update;patch

// Reconcile implements the reconciliation loop for ClusterSecRules.
func (r *ClusterSecRulesReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var csr wafv1.ClusterSecRules
	if err := r.Get(ctx, req.NamespacedName, &csr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get ClusterSecRules %s: %w", req.Name, err)
	}

	statusPatch := csr.DeepCopy()

	if csr.Spec.Rules == "" {
		setConditionDegraded(&statusPatch.Status.Conditions, csr.Generation, wafv1.ReasonInvalidSpec, "spec.rules must not be empty")
		clearCondition(&statusPatch.Status.Conditions, wafv1.ConditionReady)
		clearCondition(&statusPatch.Status.Conditions, wafv1.ConditionProgressing)
		return r.patchStatusIfChanged(ctx, log, &csr, statusPatch)
	}

	bundle, err := compiler.Compile([]compiler.Source{
		{Kind: "ClusterSecRules", Name: req.Name, Body: csr.Spec.Rules},
	})
	if err != nil {
		setConditionDegraded(&statusPatch.Status.Conditions, csr.Generation, wafv1.ReasonInvalidSpec, err.Error())
		clearCondition(&statusPatch.Status.Conditions, wafv1.ConditionReady)
		clearCondition(&statusPatch.Status.Conditions, wafv1.ConditionProgressing)
		return r.patchStatusIfChanged(ctx, log, &csr, statusPatch)
	}

	meta.SetStatusCondition(&statusPatch.Status.Conditions, metav1.Condition{
		Type:               wafv1.ConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             wafv1.ReasonReconciled,
		Message:            "rules compiled successfully",
		ObservedGeneration: csr.Generation,
	})
	meta.SetStatusCondition(&statusPatch.Status.Conditions, metav1.Condition{
		Type:               wafv1.ConditionProgressing,
		Status:             metav1.ConditionFalse,
		Reason:             wafv1.ReasonReconciled,
		ObservedGeneration: csr.Generation,
	})
	meta.SetStatusCondition(&statusPatch.Status.Conditions, metav1.Condition{
		Type:               wafv1.ConditionDegraded,
		Status:             metav1.ConditionFalse,
		Reason:             wafv1.ReasonReconciled,
		ObservedGeneration: csr.Generation,
	})
	statusPatch.Status.ParsedRuleCount = bundle.RuleCount
	statusPatch.Status.ObservedGeneration = csr.Generation

	return r.patchStatusIfChanged(ctx, log, &csr, statusPatch)
}

func (r *ClusterSecRulesReconciler) patchStatusIfChanged(
	ctx context.Context,
	log interface{ Info(string, ...any) },
	original *wafv1.ClusterSecRules,
	updated *wafv1.ClusterSecRules,
) (ctrl.Result, error) {
	if equality.Semantic.DeepEqual(original.Status, updated.Status) {
		return ctrl.Result{}, nil
	}
	if err := r.Status().Update(ctx, updated); err != nil {
		return ctrl.Result{}, fmt.Errorf("update ClusterSecRules status %s: %w", updated.Name, err)
	}
	log.Info("status updated", "name", updated.Name)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterSecRulesReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wafv1.ClusterSecRules{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Named("clustersecrules").
		Complete(r)
}
