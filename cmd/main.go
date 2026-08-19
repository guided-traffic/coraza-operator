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

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	wafv1 "github.com/guided-traffic/coraza-operator/api/v1"
	"github.com/guided-traffic/coraza-operator/internal/controller"
	"github.com/guided-traffic/coraza-operator/internal/grpcserver"
	"github.com/guided-traffic/coraza-operator/internal/pki"
	"github.com/guided-traffic/coraza-operator/internal/rulestore"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(wafv1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// grpcListenAddr returns the gRPC listen address from the GRPC_LISTEN_ADDR
// env var, defaulting to ":9443".
func grpcListenAddr() string {
	if v := os.Getenv("GRPC_LISTEN_ADDR"); v != "" {
		return v
	}
	return ":9443"
}

// operatorGRPCAddr returns the operator's gRPC Service address from
// OPERATOR_GRPC_ADDR, used to inject into engine pods.
func operatorGRPCAddr() string {
	return os.Getenv("OPERATOR_GRPC_ADDR")
}

// defaultEngineImage returns the override for the engine image from
// DEFAULT_ENGINE_IMAGE env var, or empty string to use the compiled-in constant.
func defaultEngineImage() string {
	return os.Getenv("DEFAULT_ENGINE_IMAGE")
}

// podNamespace returns the operator pod's namespace from POD_NAMESPACE env var.
func podNamespace() string {
	if v := os.Getenv("POD_NAMESPACE"); v != "" {
		return v
	}
	return "default"
}

// startGRPCServer starts the gRPC ConfigService on listenAddr with mTLS and
// returns the running *grpc.Server. The caller is responsible for graceful shutdown.
func startGRPCServer(
	listenAddr string,
	store *rulestore.Store,
	ca *pki.CertAuthority,
	kubeClient kubernetes.Interface,
	crClient client.Client,
	tlsCfg *tls.Config,
) (*grpc.Server, error) {
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	srv := grpcserver.NewServer(store, ca, kubeClient, crClient, tlsCfg, ctrl.Log.WithName("grpc-server"))
	go func() {
		if serveErr := srv.Serve(lis); serveErr != nil {
			ctrl.Log.WithName("grpc-server").Error(serveErr, "gRPC server exited")
		}
	}()
	return srv, nil
}

// nolint:gocyclo
// serverOptions holds the flag-derived configuration of the manager's metrics
// and webhook servers.
type serverOptions struct {
	metricsAddr          string
	probeAddr            string
	enableLeaderElection bool
	secureMetrics        bool
	enableHTTP2          bool

	metricsCertPath, metricsCertName, metricsCertKey string
	webhookCertPath, webhookCertName, webhookCertKey string
}

// parseFlags registers and parses the command line flags, including the zap
// logging flags.
func parseFlags() (serverOptions, zap.Options) {
	var o serverOptions

	flag.StringVar(&o.metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&o.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&o.enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&o.secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&o.webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&o.webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&o.webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&o.metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&o.metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&o.metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&o.enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")

	zapOpts := zap.Options{Development: true}
	zapOpts.BindFlags(flag.CommandLine)
	flag.Parse()

	return o, zapOpts
}

// buildManagerOptions turns the parsed flags into controller-runtime options.
func buildManagerOptions(o serverOptions) ctrl.Options {
	var tlsOpts []func(*tls.Config)

	// Disable HTTP/2 by default to avoid CVEs.
	if !o.enableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) {
			setupLog.Info("Disabling HTTP/2")
			c.NextProtos = []string{"http/1.1"}
		})
	}

	webhookServerOptions := webhook.Options{TLSOpts: tlsOpts}
	if len(o.webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", o.webhookCertPath, "webhook-cert-name", o.webhookCertName,
			"webhook-cert-key", o.webhookCertKey)

		webhookServerOptions.CertDir = o.webhookCertPath
		webhookServerOptions.CertName = o.webhookCertName
		webhookServerOptions.KeyName = o.webhookCertKey
	}

	metricsServerOptions := metricsserver.Options{
		BindAddress:   o.metricsAddr,
		SecureServing: o.secureMetrics,
		TLSOpts:       tlsOpts,
	}
	if o.secureMetrics {
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}
	if len(o.metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", o.metricsCertPath, "metrics-cert-name", o.metricsCertName,
			"metrics-cert-key", o.metricsCertKey)

		metricsServerOptions.CertDir = o.metricsCertPath
		metricsServerOptions.CertName = o.metricsCertName
		metricsServerOptions.KeyName = o.metricsCertKey
	}

	return ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhook.NewServer(webhookServerOptions),
		HealthProbeBindAddress: o.probeAddr,
		LeaderElection:         o.enableLeaderElection,
		LeaderElectionID:       "45cf04c4.gtrfc.com",
	}
}

// setupPKI loads or creates the operator CA and issues the gRPC server cert.
//
// It uses a direct (non-cached) client so the CA Secret can be read before the
// controller-runtime cache has started.
func setupPKI(ctx context.Context, mgr ctrl.Manager, ns string) (*pki.CertAuthority, *tls.Config, error) {
	directClient, err := client.New(mgr.GetConfig(), client.Options{Scheme: scheme})
	if err != nil {
		return nil, nil, fmt.Errorf("create direct client for PKI bootstrap: %w", err)
	}

	ca, err := pki.LoadOrCreate(ctx, directClient, ns, "coraza-operator-ca")
	if err != nil {
		return nil, nil, fmt.Errorf("initialise CA: %w", err)
	}
	setupLog.Info("CA initialised", "namespace", ns)

	grpcSvcName := fmt.Sprintf("coraza-operator-grpc.%s.svc", ns)
	serverCertPEM, serverKeyPEM, err := ca.IssueServerCert(
		[]string{grpcSvcName, grpcSvcName + ".cluster.local", "localhost"},
		nil,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("issue gRPC server cert: %w", err)
	}

	grpcTLS, err := ca.BuildTLSConfig(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("build gRPC TLS config: %w", err)
	}

	return ca, grpcTLS, nil
}

// registerControllers wires every reconciler into the manager.
func registerControllers(mgr ctrl.Manager, store *rulestore.Store) error {
	if err := (&controller.SecRulesReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("create secrules controller: %w", err)
	}
	if err := (&controller.ClusterSecRulesReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("create clustersecrules controller: %w", err)
	}
	if err := (&controller.RuleSetReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Store:  store,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("create ruleset controller: %w", err)
	}
	if err := (&controller.EngineReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		Store:              store,
		OperatorGRPCAddr:   operatorGRPCAddr(),
		DefaultEngineImage: defaultEngineImage(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("create engine controller: %w", err)
	}
	// +kubebuilder:scaffold:builder
	return nil
}

// addHealthChecks registers the liveness and readiness probes.
func addHealthChecks(mgr ctrl.Manager) error {
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("set up health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("set up ready check: %w", err)
	}
	return nil
}

// shutdownGRPC stops the gRPC server gracefully, falling back to a hard stop
// after gracefulGRPCStopTimeout so a stuck stream cannot block process exit.
func shutdownGRPC(srv *grpc.Server) {
	stopped := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(stopped)
	}()

	timer := time.NewTimer(gracefulGRPCStopTimeout)
	defer timer.Stop()

	select {
	case <-stopped:
	case <-timer.C:
		setupLog.Info("gRPC graceful stop timed out, forcing stop")
		srv.Stop()
	}
}

// fatal logs err and terminates the process. It never returns.
func fatal(err error, msg string, keysAndValues ...any) {
	setupLog.Error(err, msg, keysAndValues...)
	os.Exit(1)
}

// gracefulGRPCStopTimeout bounds how long a graceful gRPC stop may take before
// the server is stopped hard.
const gracefulGRPCStopTimeout = 5 * time.Second

func main() {
	opts, zapOpts := parseFlags()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), buildManagerOptions(opts))
	if err != nil {
		fatal(err, "Failed to start manager")
	}

	// POD_NAMESPACE is injected via the downward API.
	ns := podNamespace()
	ctx := ctrl.SetupSignalHandler()

	ca, grpcTLS, err := setupPKI(ctx, mgr, ns)
	if err != nil {
		fatal(err, "Failed to initialise PKI")
	}

	// Native kube clientset for TokenReview calls during engine enrollment.
	kubeClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		fatal(err, "Failed to create kube clientset")
	}

	store := rulestore.NewStore()
	grpcAddr := grpcListenAddr()

	grpcSrv, err := startGRPCServer(grpcAddr, store, ca, kubeClient, mgr.GetClient(), grpcTLS)
	if err != nil {
		fatal(err, "Failed to start gRPC server", "addr", grpcAddr)
	}
	setupLog.Info("gRPC server listening (mTLS)", "addr", grpcAddr)

	if err := registerControllers(mgr, store); err != nil {
		fatal(err, "Failed to register controllers")
	}

	if err := addHealthChecks(mgr); err != nil {
		fatal(err, "Failed to set up probes")
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctx); err != nil {
		fatal(err, "Failed to run manager")
	}

	shutdownGRPC(grpcSrv)
}
