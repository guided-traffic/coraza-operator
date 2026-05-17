# Coraza WAF Operator – Planungsdokument

Dieses Dokument sammelt offene Fragen vor Implementierungsstart. Jede Frage hat ein
Antwortfeld. Bitte direkt darunter beantworten. Mehrfachauswahl und Freitext erlaubt.

---

## 0. Projekt-Metadaten

### 0.1 Wie soll das fertige Projekt heißen (Repo, Modulpfad, Image-Name)?
Antwort: coraza-operator ist der Produktname. Der Repo ist unter: https://github.com/guided-traffic/coraza-operator erreichbar. Releast werden die Images unter docker.io/guidedtraffic/coraza-operator veröffentlicht.

### 0.2 Welche Lizenz?
Antwort: Apache 2.0

### 0.3 Wer ist Zielnutzer (interne Plattform-Teams, Open-Source-Community, beides)?
Antwort: Zielnutzer ist der Betrieb durch das Plattform-Team eines Unternehmens welches auf die Provisionierung der Kubernetes-Umgebung übernimmt. Ziel ist die zentrale Bereitstellung durch dieses Team, die ausgestaltung der Regelns soll aber in den Händen der jeweiligen Applikationen liegen.

### 0.4 Welche Mindest-Kubernetes-Version wird unterstützt?
Antwort: 1.33.x

### 0.5 Soll der Operator nur auf einer Distribution (z. B. Vanilla, OpenShift, EKS, GKE) laufen oder distributionsneutral sein?
Antwort: Es soll so konzipiert sein, dass es auf einem Standard-Kubernetes-Cluster läuft. Wir versuchen den Operator agnositisch aufzubauen. So dass dieser in vielen Kubernetes Umgebungen lauffähig ist. Die Engine selbst wird dann aber auf ein bestimmtes Tool zugeschnitte.

---

## 1. Scope & Architektur-Grundsätze

### 1.1 MVP-Umfang: Welche Funktionen müssen Version 0.1.0 unbedingt enthalten?
Antwort: SecRules, ClusterSecRules, RuleSet, ClusterRuleSet, Engine + Frontend.
Der HA-Proxy selbst wird in diesem Chart nicht gemanaged, ein dediziertes HA-Proxy Setup mit SPOE-Integration muss vom Applikation Team betrieben werden und ist nicht Teil dieses Tools.

### 1.2 Soll der Operator namespace-scoped, cluster-scoped, oder konfigurierbar sein?
Antwort: Der Operatior aggiert cluster-weit

### 1.3 Sollen CRDs cluster-scoped oder namespace-scoped sein? Pro CRD entscheiden:
- SecRules: namespaced
- ClusterSecRules: cluster
- RuleSet: namespaced
- Engine: namespaced

### 1.4 Erlaubt das Modell Cross-Namespace-Referenzen (z. B. RuleSet in NS A referenziert SecRules in NS B)?
Antwort: Nein. Aber RuleSet können ClusterSecRules integrieren.

### 1.5 Wie viele Engines pro Cluster realistisch (10, 100, 1000+)? Beeinflusst Reconcile-Design.
Antwort: Es können 10+ Engines pro Cluster betrieben werden.

### 1.6 Sollen mehrere Engine-Typen architektonisch von Anfang an vorgesehen werden (Plug-in-Interface), auch wenn nur Coraza implementiert wird?
Antwort: Es soll von Anfang an ein Plugin-Interface vorgesehen werden, damit später weitere Engines (z. B. ModSecurity v3, lua-resty-waf) ergänzt werden können. Wir beginnen zunächst mit Coraza welches nach dem Start das aktuelle Ruleset vom Operator abholt.

---

## 2. Technologie-Stack

### 2.1 Programmiersprache des Operators?
Antwort: Go (kubebuilder/operator-sdk)

### 2.2 Framework?
Optionen: kubebuilder | operator-sdk | controller-runtime direkt | andere

Antwort: Offen, bitte schlage mir ein Framework vor und begründe kurz, warum du es für dieses Projekt für geeignet hältst.

### 2.3 Code-Generator / Schema-Validierung: OpenAPI v3, CEL-Validation-Rules, Webhook-Validierung?
Antwort: OpenAPI v3

### 2.4 Build- & Release-Tooling (Make, Mage, Earthly, Bazel)?
Antwort: Make

### 2.5 Container-Registry für Operator- und Engine-Images?
Antwort: docker.io

### 2.6 Frontend-Stack (React + Vite, SvelteKit, Vue, HTMX, ...)?
Antwort: Angular

### 2.7 Stats-Backend: Prometheus + Grafana embedded, eigener Time-Series-Store, beides?
Antwort: eigene TimescaleDB, muss vom Plattform-Team seperat bereitgestellt werden.

---

## 3. CRD: SecRules

### 3.1 Beispiel zeigt `spec.rules` als großen String. Soll zusätzlich erlaubt sein:
- (a) Referenz auf ConfigMap (`spec.configMapRef`)
- (b) Referenz auf Secret (für lizenzierte Regeln)
- (c) URL-Quelle (z. B. OWASP CRS-Tarball mit Checksum)
- (d) Git-Quelle direkt
- (e) Nur Inline-String

Antwort:

### 3.2 Validierung: Soll der Operator die SecLang-Syntax beim Apply validieren (Admission-Webhook mit Coraza-Parser)?
Antwort: Ja, das soll unbedingt passieren. Bitte achte darauf geeignete Fehlermeldungen zurückzugeben, damit der Nutzer genau weiß, was in welcher Zeile falsch ist.

### 3.3 Wie wird mit ungültigen Regeln umgegangen?
Optionen:
- (a) Admission ablehnen
- (b) Akzeptieren, Status auf Invalid, keine Engine-Reload
- (c) Akzeptieren, Engine läuft mit letzter gültiger Version weiter

Antwort: b

### 3.4 Sollen Regeln Variablen/Templating unterstützen (z. B. `{{ .Env.CLUSTER_NAME }}`)?
Antwort: Ja, klingt gut.

### 3.5 Größenlimit pro SecRules-Objekt (etcd-Limit ~1 MiB)? Bei Überschreitung Chunking via ConfigMap?
Antwort: SecRules

### 3.6 Sollen Labels/Selectors auf SecRules unterstützt werden, damit RuleSet via Selector statt Namensliste matchen kann?
Antwort: Ja, das wäre eine gute Ergänzung. So könnten RuleSets flexibel Regeln gruppieren, ohne dass die RuleSet-Definition ständig angepasst werden muss.

---

## 4. CRD: RuleSet

### 4.1 Beispiel zeigt `spec.sources` als Liste benannter Referenzen. Reihenfolge wichtig — explizit garantieren?
Antwort: Ja die Reihenfolge ist wichtig. Bitte garantieren.

### 4.2 Soll RuleSet zusätzliche Konfiguration enthalten (Default-Action, AuditLog-Format, BodyLimits)?
Antwort: Erstmal nicht.

### 4.3 Konfliktauflösung bei doppelten SecRule-IDs zwischen Sources?
Optionen:
- (a) Letzte gewinnt
- (b) Apply-Fehler
- (c) Operator vergibt Suffix

Antwort: Apply-Fehler

### 4.4 Soll RuleSet ein zusammengeführtes "compiled" Artefakt im Status veröffentlichen (Hash, Größe, Regelanzahl)?
Antwort: Hash reicht erstmal aus.

### 4.5 Soll RuleSet-Änderung automatisch alle abhängigen Engines neu konfigurieren, oder Opt-in pro Engine?
Antwort: Ja, änderungen müssen zu einem reconcile aller abhängigen Engines führen.

### 4.6 Unterstützung für Include-Direktiven aus SecLang (verweisen auf andere Objekte)?
Antwort:

---

## 5. CRD: Engine

### 5.1 Welche Felder soll `spec` enthalten? Vorschlag — bitte ergänzen/streichen:
- `ruleSetRef` (Pflicht)
- `type` (Default `coraza-http`)
- `replicas` (oder `autoscaling`)
- `resources` (CPU/RAM)
- `listener` (Port, TLS-Config, ProxyProtocol)
- `upstream` (Backend-Target oder via HAProxy/SPOE)
- `mode` (Detection | Blocking)
- `tls` (Cert-Quelle: cert-manager Issuer, Secret, autosigned)
- `observability` (Metrics-Port, AuditLog-Sink)
- `affinity`, `tolerations`, `nodeSelector`
- `podDisruptionBudget`
- `serviceType` (ClusterIP | LoadBalancer | NodePort)

Antwort:

### 5.2 Sollen Engines hinter einem Operator-managed Service erreichbar sein, oder erstellt Engine selbst Service/Ingress?
Antwort:

### 5.3 Engine-Container: eigenes Image bauen oder offizielles Coraza-Proxy-Image verwenden? Wenn eigenes, welche Basis (distroless, alpine, scratch)?
Antwort:

### 5.4 Hot-Reload-Verhalten: Wie reagiert die Engine auf RuleSet-Änderung?
Optionen:
- (a) In-Process-Reload via SIGHUP / Admin-Endpoint
- (b) Rolling-Restart des Deployments
- (c) Blue/Green-Deployment

Antwort:

### 5.5 Was passiert bei Engine-Konfig-Fehler nach Reload?
Optionen:
- (a) Rollback auf vorherige Version automatisch
- (b) Engine bleibt mit alter Konfig, Status reportet Fehler
- (c) Engine geht in CrashLoop

Antwort:

### 5.6 Soll Engine eine Health-/Readiness-Probe-Strategie vorgeben oder konfigurierbar machen?
Antwort:

### 5.7 Audit-Logs: Wohin (stdout/JSON, syslog, Loki, Kafka, S3)? Schema?
Antwort:

### 5.8 Maximale Body-Größen, Timeouts, Connection-Limits — Defaults vs. konfigurierbar?
Antwort:

---

## 6. Konfig-Distribution (Operator → Engine)

### 6.1 Beispieltext nennt "TLS-verschlüsselter API-Endpunkt". Welcher Mechanismus?
Optionen:
- (a) Operator stellt gRPC/HTTPS-Server bereit, Engine pollt/streamt
- (b) Operator schreibt ConfigMap/Secret, Engine mountet
- (c) Operator schreibt CR-Status, Engine watcht via Kube-API
- (d) Sidecar im Engine-Pod, der konfiguriert

Antwort:

### 6.2 Authentifizierung Engine ↔ Operator?
Optionen: mTLS mit ServiceAccount-CA | Bearer-Token (SA-Projected) | SPIFFE/SPIRE

Antwort:

### 6.3 Push (Operator informiert) oder Pull (Engine fragt)?
Antwort:

### 6.4 Wie wird Konsistenz garantiert bei N Replicas einer Engine? Atomarer Switch oder eventually consistent?
Antwort:

### 6.5 Bootstrap-Problem: Wie kommt die Engine beim ersten Start an Konfig, bevor sie Ready ist?
Antwort:

### 6.6 Verschlüsselung sensibler Regelteile at-rest (etcd) — KMS-Encryption verlassen oder eigenes Sealing?
Antwort:

---

## 7. HAProxy-Integration

### 7.1 Welche Integrationsform mit HAProxy?
Optionen:
- (a) Coraza als Reverse-Proxy vor HAProxy
- (b) HAProxy → SPOE → Coraza-SPOA
- (c) HAProxy → HTTP-Hook → Coraza
- (d) Side-by-side, keine direkte Kopplung

Antwort:

### 7.2 Wird HAProxy vom selben Operator verwaltet oder existierend vorausgesetzt?
Antwort:

### 7.3 Soll der Operator HAProxy-Konfigurations-Snippets (Backend-Definition, SPOE-Config) generieren?
Antwort:

### 7.4 Gibt es ein bevorzugtes HAProxy-Deployment (HAProxy-Ingress, HAProxy-Kubernetes-Ingress, eigenes)?
Antwort:

---

## 8. Frontend / Stats-UI

### 8.1 Funktionsumfang MVP-Frontend?
Optionen (Mehrfach):
- (a) Liste aller Engines + Status
- (b) Live-Request-Rate, Block-Rate
- (c) Top-Angreifer-IPs
- (d) Top-Regel-Treffer
- (e) Audit-Log-Browser mit Filter
- (f) Heatmap geographisch
- (g) Konfig-Editor (CRDs anzeigen/editieren)
- (h) Regel-Test-Playground

Antwort:

### 8.2 Authentifizierung des Frontends?
Optionen: OIDC | kube-rbac-proxy | Basic-Auth | nur Cluster-intern (kein eigener Auth)

Antwort:

### 8.3 Wird Frontend pro Engine, pro RuleSet, oder global deployed?
Antwort:

### 8.4 Datenquelle für Live-Stats?
Optionen:
- (a) Prometheus-Query gegen Engine-Metrics
- (b) WebSocket/SSE direkt von Engine
- (c) Aggregator-Service im Operator
- (d) Mischform

Antwort:

### 8.5 Aufbewahrungsdauer für Stats (1h, 24h, 30d)? Wo gespeichert?
Antwort:

### 8.6 Multi-Tenancy-Anforderungen im Frontend (User sieht nur eigene Namespaces)?
Antwort:

### 8.7 Soll Frontend embedded im Operator-Pod laufen oder separates Deployment?
Antwort:

---

## 9. Observability

### 9.1 Welche Operator-Metriken sind Pflicht (reconcile_total, reconcile_errors, engine_state, ruleset_hash)?
Antwort:

### 9.2 Welche Engine-Metriken sind Pflicht (requests_total, blocked_total, latency_buckets, rule_hits)?
Antwort:

### 9.3 OpenTelemetry-Tracing-Unterstützung Pflicht oder optional?
Antwort:

### 9.4 Strukturierte Logs (JSON) per Default?
Antwort:

### 9.5 Prometheus-ServiceMonitor und PodMonitor automatisch erzeugen?
Antwort:

### 9.6 Sollen Default-Grafana-Dashboards mitgeliefert werden?
Antwort:

---

## 10. Security & Compliance

### 10.1 RBAC-Minimalprinzip: Welche Permissions soll der Operator-ServiceAccount maximal haben dürfen?
Antwort:

### 10.2 Pod-Security-Standards (restricted) für Engine- und Operator-Pods einhalten?
Antwort:

### 10.3 NetworkPolicies automatisch erzeugen (Operator ↔ Engine, Engine ↔ Upstream)?
Antwort:

### 10.4 cert-manager als harte Abhängigkeit, weiche Empfehlung oder optional?
Antwort:

### 10.5 Image-Signierung (cosign) und SBOM (syft) im Release-Prozess?
Antwort:

### 10.6 Vulnerability-Scanning (Trivy) im CI verpflichtend?
Antwort:

### 10.7 FIPS-Mode-Anforderungen für TLS-Bibliotheken?
Antwort:

### 10.8 DSGVO/Audit-Aspekte: IP-Pseudonymisierung in Audit-Logs?
Antwort:

---

## 11. Lifecycle & API-Evolution

### 11.1 Sollen Conversion-Webhooks von Anfang an vorgesehen werden (v1 → v1beta1 etc.)?
Antwort:

### 11.2 Status-Subresource mit Conditions (Ready, Progressing, Degraded) standardisiert?
Antwort:

### 11.3 Finalizers nutzen — wofür konkret (TLS-Cert-Cleanup, externe State-Cleanup)?
Antwort:

### 11.4 Wie lange Deprecation-Frist pro API-Version garantieren?
Antwort:

### 11.5 Migrationspfad bei breaking CRD-Änderungen?
Antwort:

---

## 12. GitOps & Flux-Integration

### 12.1 Soll es ein offizielles HelmRelease- und/oder Kustomization-Beispiel-Repo geben?
Antwort:

### 12.2 Helm-Chart vs. plain Kustomize vs. OLM-Bundle vs. alle drei?
Antwort:

### 12.3 Werden Beispiel-Flux-Manifeste mitgeliefert?
Antwort:

### 12.4 Soll der Operator selbst CRs anlegen, die per Flux nachträglich überschrieben werden könnten? Reconcile-Strategie bei `kubectl apply` aus Git vs. Operator-Updates?
Antwort:

### 12.5 Multi-Cluster: ein Operator pro Cluster, oder Hub/Spoke?
Antwort:

---

## 13. Tests & Qualitätssicherung

### 13.1 Test-Pyramide: Unit (envtest), Integration (kind), E2E (chainsaw/kuttl) — welche verpflichtend?
Antwort:

### 13.2 Coverage-Mindestschwelle?
Antwort:

### 13.3 Performance-Tests gegen Engine (k6, vegeta) im CI?
Antwort:

### 13.4 Chaos-Tests (Pod-Kills, Netzwerk-Partition)?
Antwort:

### 13.5 Konformitäts-Tests gegen OWASP CRS Testsuite?
Antwort:

---

## 14. Release, Versionierung, Distribution

### 14.1 SemVer strikt? Pre-1.0-Phase wie lange?
Antwort:

### 14.2 Release-Kadenz (zeitbasiert monatlich, feature-basiert)?
Antwort:

### 14.3 Wie wird die Kompatibilität Operator-Version ↔ Engine-Image-Version garantiert (Pinning, Matrix)?
Antwort:

### 14.4 Support-Policy für ältere Versionen (n-1, n-2)?
Antwort:

### 14.5 Channel-Konzept (stable / fast / edge)?
Antwort:

---

## 15. Performance & Skalierung

### 15.1 Reconcile-Throughput-Ziel pro Operator-Pod?
Antwort:

### 15.2 Operator-HA (Leader-Election, Replicas)?
Antwort:

### 15.3 Engine-Autoscaling: HPA auf CPU, KEDA auf Custom Metrics, beides?
Antwort:

### 15.4 Cold-Start-Latenz der Engine akzeptabel bis wie viele Sekunden?
Antwort:

### 15.5 Speicherprofil pro Engine (typisch / max)?
Antwort:

---

## 16. Failure-Modi & Disaster Recovery

### 16.1 Was passiert bei Operator-Ausfall — bleiben Engines weiter funktionsfähig?
Antwort:

### 16.2 Was passiert bei etcd-Restore mit alten CR-Versionen?
Antwort:

### 16.3 Backup-Strategie für CR-Inhalte (Velero, eigene Lösung)?
Antwort:

### 16.4 Verhalten bei verlorenem Kontakt Engine → Operator (Stale-Konfig akzeptabel?)?
Antwort:

---

## 17. Dokumentation & Developer Experience

### 17.1 Doku-Toolchain (mkdocs-material, Docusaurus, plain Markdown)?
Antwort:

### 17.2 API-Referenz auto-generiert (gen-crd-api-reference-docs)?
Antwort:

### 17.3 Quickstart-Tutorial-Format (CLI-Walkthrough, Video, Web-Playground)?
Antwort:

### 17.4 Beispiel-Workloads im Repo (juice-shop o. ä. für Demos)?
Antwort:

### 17.5 Contributor-Guide, DCO/CLA?
Antwort:

---

## 18. Roadmap-Punkte für später (Bestätigung, dass nicht in MVP)

- [ ] Weitere Engine-Typen (ModSecurity v3, lua-resty-waf)
- [ ] Geo-IP-Anreicherung
- [ ] Machine-Learning-basierte Anomalie-Erkennung
- [ ] Multi-Cluster-Federation
- [ ] Policy-as-Code-Integration (OPA/Kyverno)
- [ ] WASM-Filter-Support (Envoy)
- [ ] Marketplace für RuleSets

Was davon ist trotzdem MVP? Was fehlt?
Antwort:

---

## 19. Offene Punkte / Sonstiges

Freitextfeld für alles, was hier noch nicht erfasst ist:
Antwort:
