# Coraza WAF Operator – Planungsdokument

Dieses Dokument sammelt offene Fragen vor Implementierungsstart. Jede Frage hat ein
Antwortfeld. Bitte direkt darunter beantworten. Mehrfachauswahl und Freitext erlaubt.

> **Stand 2026-08-19:** Die verbindlichen Betriebsziele und alle Architektur-Entscheidungen
> stehen in [OPERATIONAL_TARGET.md](OPERATIONAL_TARGET.md) (Targets `T1`–`T10`,
> Invarianten `I1`–`I6`). Bei Widerspruch gewinnt OPERATIONAL_TARGET.md.
> Antworten unten sind entsprechend nachgetragen und mit ihrer Quelle markiert:
> *Entschieden* (Design-Entscheidung), *Verifiziert im Repo* (Code existiert),
> *Verifiziert upstream* (haproxy-ingress-Doku/-Template geprüft).

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

Nachtrag 2026-08-19 (T9): Engine bleibt namespaced und wird **in den Namespace der
HAProxy-Instanz** deployt, die sie bedient. Bindung über `spec.ingressClassName`,
nie über eine Team-Referenz. Zwei Engines mit derselben `ingressClassName` lehnt
der Webhook ab.

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

Antwort: kubebuilder (go.kubebuilder.io/v4). Verifiziert im Repo: [PROJECT](PROJECT)
ist mit kubebuilder v4.14 gescaffoldet, `api/`, `config/`, `internal/controller/`
folgen dem Layout. Entscheidung ist damit durch Implementierung gefallen.

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

Nachtrag 2026-08-19 (Entschieden, T6/T7): **0.1.0 ist Prometheus-only.** Die
TimescaleDB-Event-Pipeline ist auf später verschoben. Konsequenz: Dashboards und
Alarme dürfen nur Fragen stellen, die Prometheus-Aggregate beantworten können;
Einzelereignis-Sichten (Top-Angreifer-IPs, Audit-Browser, Forensik) sind bis dahin
außer Scope und werden im Chart nicht versprochen.

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
Antwort: Nein (Entschieden 2026-08-19, T4). `Include` steht auf der verbotenen
Direktivenliste für Team-Regeln (Dateisystemzugriff aus dem Pod). Komposition
passiert ausschließlich über `RuleSet.spec.sources`; Admin-Regeln werden
Engine-seitig injiziert (`admin-pre → team → admin-post`).

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

Antwort (Entschieden 2026-08-19, T1/T8/T9 — siehe YAML-Skizze in OPERATIONAL_TARGET.md §T9):
- **Neu:** `ingressClassName` (Pflicht — die Bindung an die HAProxy-Instanz),
  `workload` (kind: Deployment|DaemonSet, replicas, affinity, tolerations,
  nodeSelector, topologySpread, priorityClassName, PDB — T8; `replicas` bei
  DaemonSet abgelehnt).
- **Bleibt:** `type` (Plugin-Interface, 1.6), `mode`, `resources`, SPOA-Port,
  `ruleSetRef` → wird zu `baselineRuleSetRef` (Admin-Basis, z. B. CRS).
- **Entfällt:** `upstream` und `listener` (Reverse-Proxy-Modus gestrichen — SPOA
  ist der einzige Datenpfad), `serviceType` (immer ClusterIP: SPOE ist
  cluster-intern, ein LoadBalancer davor wäre ein Exposure-Fehler).
- `tls` beschränkt sich auf Engine↔Operator-mTLS (bereits implementiert, §6.2);
  Client-TLS liegt bei HAProxy (D1) und hat hier kein Feld.

### 5.2 Sollen Engines hinter einem Operator-managed Service erreichbar sein, oder erstellt Engine selbst Service/Ingress?
Antwort (Entschieden, T9): Operator erzeugt pro Engine einen ClusterIP-Service mit
OwnerReference. Dessen Adresse ist genau das, was das Plattform-Team in
`modsecurity-endpoints` (Global-Key, pro Controller-Instanz) einträgt. Die Engine
erstellt nie einen Ingress — sie steht hinter HAProxy, nicht davor.

### 5.3 Engine-Container: eigenes Image bauen oder offizielles Coraza-Proxy-Image verwenden? Wenn eigenes, welche Basis (distroless, alpine, scratch)?
Antwort: Eigenes Image — verifiziert im Repo: [Dockerfile.engine](Dockerfile.engine),
Engine-Code in [internal/enginepkg](internal/enginepkg) (Coraza als Library, SPOA
via spop). Basis-Image-Wahl noch offen.

### 5.4 Hot-Reload-Verhalten: Wie reagiert die Engine auf RuleSet-Änderung?
Optionen:
- (a) In-Process-Reload via SIGHUP / Admin-Endpoint
- (b) Rolling-Restart des Deployments
- (c) Blue/Green-Deployment

Antwort: (a), aber ohne Signal: die Engine hält einen gRPC-`Subscribe`-Stream zum
Operator und tauscht bei jedem neuen Bundle die WAF-Instanz atomar in-process
(verifiziert im Repo: [internal/enginepkg](internal/enginepkg), Reload-Tests).
Kein Rolling-Restart — Invariante I4: atomar und connection-preserving, laufende
SPOE-Verbindungen dürfen nicht abreißen.

### 5.5 Was passiert bei Engine-Konfig-Fehler nach Reload?
Optionen:
- (a) Rollback auf vorherige Version automatisch
- (b) Engine bleibt mit alter Konfig, Status reportet Fehler
- (c) Engine geht in CrashLoop

Antwort: (b) — folgt aus 3.3(b) und I4: ungültige Regeln erreichen die Engine gar
nicht erst (Status `Invalid`, kein Reload); schlägt der Swap trotzdem fehl, bleibt
die letzte gültige WAF-Instanz aktiv und der Fehler landet in den
Engine-Conditions.

### 5.6 Soll Engine eine Health-/Readiness-Probe-Strategie vorgeben oder konfigurierbar machen?
Antwort:

### 5.7 Audit-Logs: Wohin (stdout/JSON, syslog, Loki, Kafka, S3)? Schema?
Antwort:

### 5.8 Maximale Body-Größen, Timeouts, Connection-Limits — Defaults vs. konfigurierbar?
Antwort (teilweise, verifiziert upstream): Die harten Grenzen setzt HAProxy, nicht
wir — `req.body` kommt puffergebunden über SPOE, und das Latenzbudget ist
`modsecurity-timeout-processing` (Global, Default `1s`; dazu `-hello` 100ms,
`-idle` 30s). Für ClamAV (T10) braucht das CR explizit `maxScanSize` +
`onOversize: allow|deny`. Fail-open/fail-closed wird pro Engine konfigurierbar,
Default fail-closed im Blocking-Mode (I6) — aktuell hardcoded fail-open in
[internal/enginepkg/spoa.go](internal/enginepkg/spoa.go), muss vor T10 gefixt werden.

---

## 6. Konfig-Distribution (Operator → Engine)

### 6.1 Beispieltext nennt "TLS-verschlüsselter API-Endpunkt". Welcher Mechanismus?
Optionen:
- (a) Operator stellt gRPC/HTTPS-Server bereit, Engine pollt/streamt
- (b) Operator schreibt ConfigMap/Secret, Engine mountet
- (c) Operator schreibt CR-Status, Engine watcht via Kube-API
- (d) Sidecar im Engine-Pod, der konfiguriert

Antwort: (a) — verifiziert im Repo: Operator betreibt einen gRPC-Server
([internal/grpcserver](internal/grpcserver)), Engines streamen Bundles über
`rpc Subscribe(SubscribeRequest) returns (stream RuleSetBundle)`
([proto/waf/v1](proto/waf/v1)).

### 6.2 Authentifizierung Engine ↔ Operator?
Optionen: mTLS mit ServiceAccount-CA | Bearer-Token (SA-Projected) | SPIFFE/SPIRE

Antwort: mTLS mit operator-eigener CA — verifiziert im Repo: `Subscribe` erzwingt
per Stream-Interceptor ein verifiziertes Client-Zertifikat, `Enroll` ist davon
ausgenommen und dient dem Zertifikatsbezug
([internal/grpcserver/server.go](internal/grpcserver/server.go)).

### 6.3 Push (Operator informiert) oder Pull (Engine fragt)?
Antwort: Push über den bestehenden `Subscribe`-Stream: die Engine abonniert einmal,
der Operator schiebt bei jeder Neukompilierung ein neues Bundle (verifiziert im
Repo, siehe 6.1).

### 6.4 Wie wird Konsistenz garantiert bei N Replicas einer Engine? Atomarer Switch oder eventually consistent?
Antwort: Atomar **pro Pod** (I4: kompletter WAF-Swap, nie partiell), über die
Replicas hinweg eventually consistent — jede Replica hat ihren eigenen Stream.
Sichtbarkeit über `status.appliedRuleSetHash`
([api/v1/engine_types.go](api/v1/engine_types.go)); Fleet-weite Gleichzeitigkeit
wird nicht versprochen und ist für Regelauswertung auch nicht nötig.

### 6.5 Bootstrap-Problem: Wie kommt die Engine beim ersten Start an Konfig, bevor sie Ready ist?
Antwort: Verifiziert im Repo: `Enroll`-RPC ist vom mTLS-Zwang ausgenommen — die
Engine holt sich damit ihr Zertifikat, subscribed anschließend per mTLS und wird
erst Ready, wenn das erste Bundle geladen ist.

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

Antwort: (b) — Entschieden 2026-08-19 (T1): SPOA ist der **einzige** Datenpfad,
der Reverse-Proxy-Modus wird ersatzlos gestrichen (`spec.upstream`/`spec.listener`
entfallen). Verifizierter SPOE-Vertrag: genau eine Message `coraza-req`, Event
`on-backend-http-request`, Args wörtlich aus `modsecurity-args`, Var-Prefix
`coraza` — Details in OPERATIONAL_TARGET.md §4.

### 7.2 Wird HAProxy vom selben Operator verwaltet oder existierend vorausgesetzt?
Antwort: Existierend vorausgesetzt (bestätigt 1.1). Die Global-Keys
(`modsecurity-endpoints`, `modsecurity-use-coraza: true`, `modsecurity-args` inkl.
`src` **append-only**, Timeouts) setzt das Plattform-Team pro Controller-Instanz;
der Operator validiert und meldet Abweichungen als Condition, setzt sie aber nie
selbst (T1, I2).

### 7.3 Soll der Operator HAProxy-Konfigurations-Snippets (Backend-Definition, SPOE-Config) generieren?
Antwort: Rendern ja, schreiben nie (I2). Team-seitige Annotationen (`waf`,
`waf-mode`, `auth-tls-*` → D1, `allowlist-source-range` → D2) werden als
Copy-Paste-Snippet in Doku/CR-Status ausgegeben; ihr Fehlen wird als Condition
gemeldet. Der Operator hat **kein** Schreibrecht auf team-eigene
Ingress-/Gateway-Objekte.

### 7.4 Gibt es ein bevorzugtes HAProxy-Deployment (HAProxy-Ingress, HAProxy-Kubernetes-Ingress, eigenes)?
Antwort: Entschieden (T1): [haproxy-ingress](https://haproxy-ingress.github.io/)
(jcmoraisjr), unverändertes Original-Chart. Alles was der Operator emittiert, muss
über dokumentierte Keys dieses Controllers konsumierbar sein. Mehrere Instanzen
werden über je eine eigene Engine pro `ingressClassName` unterstützt (T9).

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

Antwort (eingeschränkt durch Prometheus-only-Entscheidung, 2.7): MVP maximal
(a), (b), (d) — alles aggregat-basiert beantwortbar. (c), (e), (f) brauchen die
verschobene Event-Pipeline und sind bis dahin außer Scope; nicht versprechen.

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

Antwort: (a) — folgt aus der Prometheus-only-Entscheidung (2.7). Wechsel auf (d)
erst, wenn die TimescaleDB-Pipeline kommt.

### 8.5 Aufbewahrungsdauer für Stats (1h, 24h, 30d)? Wo gespeichert?
Antwort: 0.1.0: Retention des cluster-eigenen Prometheus, wir speichern nichts
selbst. Langzeit-/Event-Retention ist eine TimescaleDB-Frage und mit ihr
verschoben. Client-IPs sind personenbezogen und gehören in Events mit
Retention-Policy, nie in Prometheus-Labels (T6, 10.8).

### 8.6 Multi-Tenancy-Anforderungen im Frontend (User sieht nur eigene Namespaces)?
Antwort:

### 8.7 Soll Frontend embedded im Operator-Pod laufen oder separates Deployment?
Antwort:

---

## 9. Observability

### 9.1 Welche Operator-Metriken sind Pflicht (reconcile_total, reconcile_errors, engine_state, ruleset_hash)?
Antwort:

### 9.2 Welche Engine-Metriken sind Pflicht (requests_total, blocked_total, latency_buckets, rule_hits)?
Antwort (T6): Basis existiert ([internal/enginepkg/metrics.go](internal/enginepkg/metrics.go),
SPOA-Metriken). Ziel-Dimensionen: Ingress-Instanz, Namespace, Host, Path-Gruppe
(normalisiert auf die Ingress-Pfadregel, nie Roh-URI), Rule-ID/-Tag,
Anomaly-Score-Bucket, Action, Phase. Invariante I5: Kardinalität ist Budget —
jedes neue Label braucht eine Schätzung im Ticket.

### 9.3 OpenTelemetry-Tracing-Unterstützung Pflicht oder optional?
Antwort:

### 9.4 Strukturierte Logs (JSON) per Default?
Antwort:

### 9.5 Prometheus-ServiceMonitor und PodMonitor automatisch erzeugen?
Antwort: Per Chart-Toggle (analog T7: `monitoring.*.enabled`), nicht
unconditionally — die ServiceMonitor-CRD existiert nur mit installiertem
prometheus-operator. Noch nicht final entschieden.

### 9.6 Sollen Default-Grafana-Dashboards mitgeliefert werden?
Antwort: Ja — Entschieden (T7): Chart liefert PrometheusRule-Alarme (operational +
security) und Grafana-Dashboards, toggle- und label-konfigurierbar. Regel: kein
Dashboard erfindet eine Metrik, die der Operator nicht exportiert; Panels, die
D2-vorgefilterten Traffic nicht sehen, sagen das in der Legende.

---

## 10. Security & Compliance

### 10.1 RBAC-Minimalprinzip: Welche Permissions soll der Operator-ServiceAccount maximal haben dürfen?
Antwort (I2, entschieden): Ingresses/Gateways clusterweit **nur** `get/list/watch` —
niemals write auf team-eigene Objekte (kein field-level RBAC in Kubernetes ⇒
Ingress-Write hieße Routing-Hijack-Fähigkeit). Schreibrechte nur auf eigene CRDs
(+Status) und die selbst erzeugten Ressourcen (Deployments/DaemonSets, Services,
Secrets für die CA) mit OwnerReferences. Ein Ticket, das mehr will, muss erst I2
amendieren.

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
Antwort (Teilentscheidung, T6): Client-IPs erscheinen nie als Prometheus-Label.
Vollständige Antwort (Pseudonymisierung, Retention) wird mit der verschobenen
Event-Pipeline fällig — vor deren Design zu klären.

---

## 11. Lifecycle & API-Evolution

### 11.1 Sollen Conversion-Webhooks von Anfang an vorgesehen werden (v1 → v1beta1 etc.)?
Antwort:

### 11.2 Status-Subresource mit Conditions (Ready, Progressing, Degraded) standardisiert?
Antwort: Ja — bereits Projektregel ([CLAUDE.md](CLAUDE.md)): jedes Status-Update
setzt alle drei Condition-Typen. `Degraded` trägt zusätzlich die neuen Fälle:
verlorener Host-Claim (I1, mit Gewinner-Namespace), fehlende Global-Keys (T1),
fehlendes `src` in `modsecurity-args` (T3).

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
Antwort (Stand 2026-08-19): Nichts davon rückt ins MVP vor. Es fehlt in der Liste:
- **ClamAV-Scanning (T10)** — Ziel, aber nicht MVP; nur Request-Pfad. Verifiziert
  upstream: das SPOE-Template kennt ausschließlich `on-backend-http-request`,
  Response-/Egress-Scanning ist mit dem unveränderten Chart nicht lieferbar.
- **Gateway-API-Support (T2)** — gewollt, Key-Abdeckung upstream noch unverifiziert.
- Policy-as-Code (OPA/Kyverno) bleibt Roadmap; der Host-Claim-Ledger (I1) ist
  bewusst operator-intern gelöst und hängt nicht davon ab.

---

## 19. Offene Punkte / Sonstiges

Freitextfeld für alles, was hier noch nicht erfasst ist:
Antwort (offene Punkte, Stand 2026-08-19):
- 1.1 nennt `ClusterRuleSet` als MVP-CRD — existiert im Code nicht
  (api/v1 hat nur SecRules, ClusterSecRules, RuleSet, Engine). Klären: bauen oder
  aus 1.1 streichen.
- Team-Policy-CR (T2/T3: Ingress-Referenz, IP×Pfad×Methode, Exclusions) hat noch
  keinen CRD-Namen — neues Kind oder Erweiterung von SecRules?
- Stateful-Regeln (Rate-Limit, Brute-Force) zählen pro Pod, nicht fleet-weit —
  harte Grenze ohne Shared Store, muss in die Doku (T4).
- Fail-open→fail-closed-Fix ([internal/enginepkg/spoa.go](internal/enginepkg/spoa.go),
  I6) ist Vorbedingung für T10.
- Gateway-API-Verifikation (T2) steht aus.
- Ticket-Reihenfolge: siehe OPERATIONAL_TARGET.md §6 (Ticket-Checkliste) und die
  im Gespräch festgelegte Priorisierung: erst die drei offenen Löcher
  (Compiler-Filter, fail-closed, `src`), dann Engine-API-Umbau, dann Host-Claim,
  dann Inhalt (CRS, Metriken, Chart-Monitoring).
