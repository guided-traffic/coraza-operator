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
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Disable HTTP/2 by default to avoid CVEs.
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("Disabling HTTP/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
	}

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "45cf04c4.gtrfc.com",
	})
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	// --- PKI: load or create the operator CA ---
	// Uses POD_NAMESPACE (injected via downward API) as the secret namespace.
	ns := podNamespace()
	ctx := ctrl.SetupSignalHandler()

	// Build a direct (non-cached) client for PKI bootstrap so we can access the
	// Secret before the controller-runtime cache has started.
	directClient, err := client.New(mgr.GetConfig(), client.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "Failed to create direct client for PKI bootstrap")
		os.Exit(1)
	}

	ca, err := pki.LoadOrCreate(ctx, directClient, ns, "coraza-operator-ca")
	if err != nil {
		setupLog.Error(err, "Failed to initialise CA")
		os.Exit(1)
	}
	setupLog.Info("CA initialised", "namespace", ns)

	// Issue a server cert for the gRPC service SANs.
	grpcSvcName := fmt.Sprintf("coraza-operator-grpc.%s.svc", ns)
	serverCertPEM, serverKeyPEM, err := ca.IssueServerCert(
		[]string{grpcSvcName, grpcSvcName + ".cluster.local", "localhost"},
		nil,
	)
	if err != nil {
		setupLog.Error(err, "Failed to issue gRPC server cert")
		os.Exit(1)
	}

	grpcTLS, err := ca.BuildTLSConfig(serverCertPEM, serverKeyPEM)
	if err != nil {
		setupLog.Error(err, "Failed to build gRPC TLS config")
		os.Exit(1)
	}

	// --- Build the native kube clientset for TokenReview calls ---
	kubeClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "Failed to create kube clientset")
		os.Exit(1)
	}

	// --- Initialise the in-memory bundle store and start the gRPC server ---
	store := rulestore.NewStore()
	grpcAddr := grpcListenAddr()

	grpcSrv, err := startGRPCServer(grpcAddr, store, ca, kubeClient, mgr.GetClient(), grpcTLS)
	if err != nil {
		setupLog.Error(err, "Failed to start gRPC server", "addr", grpcAddr)
		os.Exit(1)
	}
	setupLog.Info("gRPC server listening (mTLS)", "addr", grpcAddr)

	if err := (&controller.SecRulesReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "secrules")
		os.Exit(1)
	}
	if err := (&controller.ClusterSecRulesReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "clustersecrules")
		os.Exit(1)
	}
	if err := (&controller.RuleSetReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Store:  store,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "ruleset")
		os.Exit(1)
	}
	if err := (&controller.EngineReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		Store:              store,
		OperatorGRPCAddr:   operatorGRPCAddr(),
		DefaultEngineImage: defaultEngineImage(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "engine")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}

	// Graceful gRPC shutdown with a 5-second fallback hard stop.
	stopped := make(chan struct{})
	go func() {
		grpcSrv.GracefulStop()
		close(stopped)
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-stopped:
	case <-timer.C:
		setupLog.Info("gRPC graceful stop timed out, forcing stop")
		grpcSrv.Stop()
	}
}
