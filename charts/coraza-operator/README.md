## coraza-operator Helm chart

Installs the coraza-operator and all four CRDs (SecRules, ClusterSecRules, RuleSet, Engine) into the target namespace. Set `installCRDs: false` if CRDs are managed externally. The `engineImage` values are injected as `DEFAULT_ENGINE_IMAGE` into the operator Deployment and used by the EngineReconciler as the pull image for engine pods; individual Engine resources can override with `spec.image`.

```sh
helm upgrade --install coraza-operator charts/coraza-operator -n coraza-system --create-namespace
```
