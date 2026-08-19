# HAProxy IC HelmRelease Patch (for review)

**Target file:** `/Users/hfi/repos/k8s-flux-base/components/ingress-controller/haproxy-external/external-reverse-proxy/helmrelease.yml`

**Goal:** aktiviert ModSecurity-Endpunkt mit Coraza-Variante, zeigt auf unsere SPOA-Engine im Namespace `coraza-demo`.

**Was passiert nach commit:**
- Flux reconciled HelmRelease (Intervall 1m laut Spec)
- HAProxy-IC schreibt SPOE-Config neu, restartet/reloaded
- Ingresses mit Annotation `haproxy-ingress.github.io/waf: modsecurity` aktivieren Inspektion

**Was NICHT geändert wird:**
- Keine zusätzlichen Container (kein modsecurity-spoa Sidecar — unsere Engine läuft separat)
- Keine Volume-Mounts hinzu (`coraza-config` Volume bleibt unverändert, derzeit ungenutzt)
- Keine Args/Format-Anpassung (Default-`modsecurity-args` der IC reicht)

## Diff

```diff
--- a/components/ingress-controller/haproxy-external/external-reverse-proxy/helmrelease.yml
+++ b/components/ingress-controller/haproxy-external/external-reverse-proxy/helmrelease.yml
@@ -58,9 +58,9 @@ spec:
           http-request capture req.hdr(Cookie) len 1000
           http-request set-var(txn.scheme) str(https) if { ssl_fc }
           http-request set-var(txn.scheme) str(http) if !{ ssl_fc }
-        # modsecurity-endpoints: "127.0.0.1:12345"
-        # modsecurity-use-coraza: "true"
-        # modsecurity-args: "app=hdr(host) id=unique-id src-ip=src src-port=src_port dst-ip=dst dst-port=dst_port method=method path=path query=query version=req.ver headers=req.hdrs body=req.body"
+        modsecurity-endpoints: "demo-engine-svc.coraza-demo.svc:9000"
+        modsecurity-use-coraza: "true"
+        # modsecurity-args belassen wir auf IC-Default; Coraza-SPOA-Engine arbeitet damit
         external-has-lua: "true"
```

## Nach commit + Flux reconcile

Verifikation aus k8s-flux-base-Sicht:
```
flux reconcile helmrelease haproxy-ingress-external -n external-ingress
kubectl -n external-ingress rollout status ds/external-haproxy-ingress-controller
kubectl -n external-ingress get cm external-haproxy-ingress-controller -o jsonpath='{.data.modsecurity-endpoints}'
```

Erwartet: `demo-engine-svc.coraza-demo.svc:9000`

Smoke-Test danach (mache ich):
```
curl http://coraza.stage.wds18.de/         # erwartet 200 (upstream "ok")
curl http://coraza.stage.wds18.de/attack    # erwartet 403 (SecRule id:1001 trifft)
```

## Rollback

Patch revert + `flux reconcile`. Ingresses ohne `waf`-Annotation sind unbeeinflusst (war auch vorher schon aus).
