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

package enginepkg_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	k8stesting "k8s.io/client-go/testing"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"

	wafv1 "github.com/guided-traffic/coraza-operator/api/v1"
	"github.com/guided-traffic/coraza-operator/internal/engineassets"
	"github.com/guided-traffic/coraza-operator/internal/grpcserver"
	"github.com/guided-traffic/coraza-operator/internal/pki"
	"github.com/guided-traffic/coraza-operator/internal/rulestore"
	wafv1pb "github.com/guided-traffic/coraza-operator/proto/waf/v1"
)

const e2eBufSize = 1 << 20

// TestEnrollThenSubscribe is the end-to-end integration test that exercises:
//  1. Engine calls Enroll (without a client cert) — bootstraps via SA token.
//  2. Engine calls Subscribe (with the enrolled client cert) — receives a bundle.
//
// The server runs in-process over a bufconn listener with real mTLS.
// The TokenReview is shimmed via a k8s fake client reactor.
func TestEnrollThenSubscribe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const (
		engineNS   = "testns"
		engineName = "testengine"
	)

	// --- Build the CA ---
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = wafv1.AddToScheme(scheme)

	caFakeClient := crfake.NewClientBuilder().WithScheme(scheme).Build()
	ca, err := pki.LoadOrCreate(ctx, caFakeClient, "operator-ns", "coraza-operator-ca")
	require.NoError(t, err)

	// Issue a server cert for the bufconn listener (SAN = "bufconn").
	serverCertPEM, serverKeyPEM, err := ca.IssueServerCert(
		[]string{"bufconn", "localhost"},
		[]net.IP{net.ParseIP("127.0.0.1")},
	)
	require.NoError(t, err)

	serverTLS, err := ca.BuildTLSConfig(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	// --- Build the CR client with an Engine CR ---
	crClient := crfake.NewClientBuilder().WithScheme(scheme).
		WithRuntimeObjects(&wafv1.Engine{
			ObjectMeta: metav1.ObjectMeta{
				Name:      engineName,
				Namespace: engineNS,
			},
			Spec: wafv1.EngineSpec{
				Upstream: wafv1.UpstreamConfig{URL: "http://backend.svc:80"},
			},
		}).Build()

	// --- Fake kube client with a TokenReview reactor ---
	saUsername := "system:serviceaccount:" + engineNS + ":" + engineName + "-engine"
	kubeClient := fake.NewClientset()
	kubeClient.PrependReactor("create", "tokenreviews",
		func(_ k8stesting.Action) (bool, runtime.Object, error) {
			return true, &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: true,
					User:          authv1.UserInfo{Username: saUsername},
				},
			}, nil
		},
	)

	// --- Build and start the gRPC server ---
	store := rulestore.NewStore()
	grpcSrv := grpcserver.NewServer(store, ca, kubeClient, crClient, serverTLS, logr.Discard())

	lis := bufconn.Listen(e2eBufSize)
	go func() {
		if serveErr := grpcSrv.Serve(lis); serveErr != nil && serveErr != grpc.ErrServerStopped {
			t.Logf("e2e grpc server error: %v", serveErr)
		}
	}()
	t.Cleanup(func() {
		grpcSrv.GracefulStop()
		_ = lis.Close()
	})

	dialBufconn := func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	}

	// CA pool for client-side cert verification in the Subscribe phase.
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(ca.CertPEM))

	certDir := t.TempDir()

	// --- Enroll phase ---
	t.Run("Enroll", func(t *testing.T) {
		// Generate key + CSR for the Enroll request.
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: engineNS + "/" + engineName},
		}, priv)
		require.NoError(t, err)

		// SECURITY: During bootstrap, the engine uses InsecureSkipVerify because
		// it does not yet have the CA cert. This matches the production flow.
		enrollTLS := &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // bootstrap-only
			MinVersion:         tls.VersionTLS13,
		}

		conn, err := grpc.NewClient(
			"passthrough://bufnet",
			grpc.WithContextDialer(dialBufconn),
			grpc.WithTransportCredentials(credentials.NewTLS(enrollTLS)),
		)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		resp, err := wafv1pb.NewConfigServiceClient(conn).Enroll(ctx, &wafv1pb.EnrollRequest{
			SaToken:         "fake-sa-token",
			EngineNamespace: engineNS,
			EngineName:      engineName,
			CsrDer:          csrDER,
		})
		require.NoError(t, err)
		require.NotEmpty(t, resp.ClientCertPem)
		require.NotEmpty(t, resp.CaCertPem)

		// Verify the issued cert chain against the returned CA cert.
		block, _ := pem.Decode(resp.ClientCertPem)
		require.NotNil(t, block)
		issuedCert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		assert.Equal(t, engineNS+"/"+engineName, issuedCert.Subject.CommonName)

		verifyPool := x509.NewCertPool()
		require.True(t, verifyPool.AppendCertsFromPEM(resp.CaCertPem))
		_, err = issuedCert.Verify(x509.VerifyOptions{
			Roots:     verifyPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		assert.NoError(t, err, "enrolled cert must verify against returned CA cert")

		// Persist cert, key, and CA cert to certDir for the Subscribe phase.
		keyDER, err := x509.MarshalECPrivateKey(priv)
		require.NoError(t, err)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

		require.NoError(t, os.WriteFile(certDir+"/client.crt", resp.ClientCertPem, 0o600))
		require.NoError(t, os.WriteFile(certDir+"/client.key", keyPEM, 0o600))
		require.NoError(t, os.WriteFile(certDir+"/ca.crt", resp.CaCertPem, 0o644))
	})

	// --- Subscribe phase ---
	t.Run("Subscribe_receives_bundle", func(t *testing.T) {
		clientCert, err := tls.LoadX509KeyPair(certDir+"/client.crt", certDir+"/client.key")
		require.NoError(t, err)

		subscribeTLS := &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caPool,
			// ServerName must match one of the server cert's SANs.
			ServerName: "bufconn",
			MinVersion: tls.VersionTLS13,
		}

		conn, err := grpc.NewClient(
			"passthrough://bufnet",
			grpc.WithContextDialer(dialBufconn),
			grpc.WithTransportCredentials(credentials.NewTLS(subscribeTLS)),
		)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		// Publish a bundle before subscribing.
		store.Publish(engineNS, engineName, rulestore.Bundle{
			RuleSetName: "rs",
			SHA256:      "sha-e2e-001",
			Compiled:    "# compiled rules",
			GeneratedAt: time.Now(),
		})

		stream, err := wafv1pb.NewConfigServiceClient(conn).Subscribe(ctx, &wafv1pb.SubscribeRequest{
			EngineNamespace: engineNS,
			EngineName:      engineName,
		})
		require.NoError(t, err)

		msg := recvWithTimeout(t, stream, 5*time.Second)
		require.NotNil(t, msg)
		assert.Equal(t, "sha-e2e-001", msg.Sha256)
		assert.Equal(t, "rs", msg.RulesetName)
	})

	// Publish a second bundle and verify it arrives on the still-open stream.
	t.Run("Subscribe_receives_second_bundle", func(t *testing.T) {
		clientCert, err := tls.LoadX509KeyPair(certDir+"/client.crt", certDir+"/client.key")
		require.NoError(t, err)

		subscribeTLS := &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caPool,
			ServerName:   "bufconn",
			MinVersion:   tls.VersionTLS13,
		}

		conn, err := grpc.NewClient(
			"passthrough://bufnet",
			grpc.WithContextDialer(dialBufconn),
			grpc.WithTransportCredentials(credentials.NewTLS(subscribeTLS)),
		)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		streamCtx, streamCancel := context.WithCancel(ctx)
		defer streamCancel()

		stream, err := wafv1pb.NewConfigServiceClient(conn).Subscribe(streamCtx, &wafv1pb.SubscribeRequest{
			EngineNamespace: engineNS,
			EngineName:      engineName,
		})
		require.NoError(t, err)

		// The store already has sha-e2e-001 from the previous sub-test; receive it.
		first := recvWithTimeout(t, stream, 5*time.Second)
		require.NotNil(t, first)

		// Now publish a new bundle and verify it arrives.
		store.Publish(engineNS, engineName, rulestore.Bundle{
			RuleSetName: "rs",
			SHA256:      "sha-e2e-002",
			Compiled:    "# updated rules",
			GeneratedAt: time.Now(),
		})

		var count atomic.Int32
		count.Add(1)
		second := recvWithTimeout(t, stream, 5*time.Second)
		require.NotNil(t, second)
		count.Add(1)
		assert.Equal(t, "sha-e2e-002", second.Sha256)
		assert.Equal(t, int32(2), count.Load())
	})

	// Verify Subscribe is rejected WITHOUT a client cert.
	t.Run("Subscribe_rejected_without_client_cert", func(t *testing.T) {
		// Connect with TLS but no client cert.
		noClientTLS := &tls.Config{
			RootCAs:    caPool,
			ServerName: "bufconn",
			MinVersion: tls.VersionTLS13,
		}

		conn, err := grpc.NewClient(
			"passthrough://bufnet",
			grpc.WithContextDialer(dialBufconn),
			grpc.WithTransportCredentials(credentials.NewTLS(noClientTLS)),
		)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		stream, err := wafv1pb.NewConfigServiceClient(conn).Subscribe(ctx, &wafv1pb.SubscribeRequest{
			EngineNamespace: engineNS,
			EngineName:      engineName,
		})
		require.NoError(t, err)

		_, recvErr := stream.Recv()
		require.Error(t, recvErr, "Subscribe without client cert must be rejected")
	})

	// Verify the SA name helper produces the expected format.
	t.Run("SAName_matches_enroll_expectation", func(t *testing.T) {
		engine := &wafv1.Engine{ObjectMeta: metav1.ObjectMeta{Name: engineName, Namespace: engineNS}}
		assert.Equal(t, engineName+"-engine", engineassets.ServiceAccountName(engine))
		assert.Equal(t, saUsername, "system:serviceaccount:"+engineNS+":"+engineassets.ServiceAccountName(engine))
	})
}

// recvWithTimeout receives one message from the stream or fails the test after timeout.
func recvWithTimeout(t *testing.T, stream wafv1pb.ConfigService_SubscribeClient, timeout time.Duration) *wafv1pb.RuleSetBundle {
	t.Helper()
	ch := make(chan *wafv1pb.RuleSetBundle, 1)
	go func() {
		msg, _ := stream.Recv()
		ch <- msg
	}()
	select {
	case msg := <-ch:
		return msg
	case <-time.After(timeout):
		t.Fatal("timed out waiting for Subscribe message")
		return nil
	}
}
