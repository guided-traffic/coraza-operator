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

package grpcserver_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1 "k8s.io/api/core/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	wafv1 "github.com/guided-traffic/coraza-operator/api/v1"
	"github.com/guided-traffic/coraza-operator/internal/grpcserver"
	"github.com/guided-traffic/coraza-operator/internal/pki"
	"github.com/guided-traffic/coraza-operator/internal/rulestore"
	wafv1pb "github.com/guided-traffic/coraza-operator/proto/waf/v1"
)

const enrollBufSize = 1 << 20

// tokenReviewReactor returns a reactor that always authenticates as the given username.
func tokenReviewReactor(authenticatedAs string) k8stesting.ReactionFunc {
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authv1.TokenReview{
			Status: authv1.TokenReviewStatus{
				Authenticated: true,
				User: authv1.UserInfo{
					Username: authenticatedAs,
				},
			},
		}, nil
	}
}

// unauthTokenReviewReactor returns a reactor that always rejects the token.
func unauthTokenReviewReactor() k8stesting.ReactionFunc {
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authv1.TokenReview{
			Status: authv1.TokenReviewStatus{
				Authenticated: false,
				Error:         "token not valid",
			},
		}, nil
	}
}

// buildFakeCRClient builds a controller-runtime fake client pre-seeded with the given objects.
func buildFakeCRClient(objs ...runtime.Object) *crfake.ClientBuilder {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = wafv1.AddToScheme(scheme)
	b := crfake.NewClientBuilder().WithScheme(scheme)
	for _, o := range objs {
		b = b.WithRuntimeObjects(o)
	}
	return b
}

// buildCA builds a fresh in-memory CA without a k8s Secret.
func buildCA(t *testing.T) *pki.CertAuthority {
	t.Helper()
	fc := buildFakeCRClient().Build()
	ca, err := pki.LoadOrCreate(context.Background(), fc, "test-ns", "ca")
	require.NoError(t, err)
	return ca
}

// buildCSR generates a fresh ECDSA P-256 key, builds a CSR, and returns (csrDER, privateKey).
func buildCSR(t *testing.T, cn string) (csrDER []byte, priv *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	csrDER, err = x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	require.NoError(t, err)
	return csrDER, priv
}

// engineCR builds a minimal Engine CR.
func engineCR(ns, name string) *wafv1.Engine {
	return &wafv1.Engine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: wafv1.EngineSpec{
			Upstream: wafv1.UpstreamConfig{URL: "http://backend.svc:80"},
		},
	}
}

// setupEnroll starts a grpc server with the given server + returns a connected client.
func setupEnrollServer(t *testing.T, srv *grpcserver.Server) (wafv1pb.ConfigServiceClient, context.CancelFunc) {
	t.Helper()

	lis := bufconn.Listen(enrollBufSize)
	grpcSrv := grpc.NewServer()
	wafv1pb.RegisterConfigServiceServer(grpcSrv, srv)

	go func() {
		if err := grpcSrv.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			t.Logf("enroll test grpc server error: %v", err)
		}
	}()

	conn, err := grpc.NewClient(
		"passthrough://bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	cancel := func() {
		conn.Close()
		grpcSrv.GracefulStop()
		lis.Close()
	}

	return wafv1pb.NewConfigServiceClient(conn), cancel
}

func TestEnroll_Success(t *testing.T) {
	ca := buildCA(t)
	csrDER, _ := buildCSR(t, "ignored-cn")

	kubeClient := fake.NewSimpleClientset()
	kubeClient.Fake.PrependReactor("create", "tokenreviews",
		tokenReviewReactor("system:serviceaccount:myns:myengine-engine"),
	)

	crClient := buildFakeCRClient(engineCR("myns", "myengine")).Build()

	srv := &grpcserver.Server{
		Store:      rulestore.NewStore(),
		Logger:     logr.Discard(),
		CA:         ca,
		KubeClient: kubeClient,
		CRClient:   crClient,
	}

	client, cancel := setupEnrollServer(t, srv)
	defer cancel()

	resp, err := client.Enroll(context.Background(), &wafv1pb.EnrollRequest{
		SaToken:         "valid-token",
		EngineNamespace: "myns",
		EngineName:      "myengine",
		CsrDer:          csrDER,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.ClientCertPem)
	require.NotEmpty(t, resp.CaCertPem)

	// Verify the issued cert chain against the CA.
	block, _ := pem.Decode(resp.ClientCertPem)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(resp.CaCertPem))

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	assert.NoError(t, err, "issued cert must verify against returned CA cert")

	// Verify CN.
	assert.Equal(t, "myns/myengine", cert.Subject.CommonName)
}

func TestEnroll_WrongToken_PermissionDenied(t *testing.T) {
	ca := buildCA(t)
	csrDER, _ := buildCSR(t, "ignored-cn")

	kubeClient := fake.NewSimpleClientset()
	kubeClient.Fake.PrependReactor("create", "tokenreviews",
		unauthTokenReviewReactor(),
	)

	crClient := buildFakeCRClient(engineCR("myns", "myengine")).Build()

	srv := &grpcserver.Server{
		Store:      rulestore.NewStore(),
		Logger:     logr.Discard(),
		CA:         ca,
		KubeClient: kubeClient,
		CRClient:   crClient,
	}

	client, cancel := setupEnrollServer(t, srv)
	defer cancel()

	_, err := client.Enroll(context.Background(), &wafv1pb.EnrollRequest{
		SaToken:         "bad-token",
		EngineNamespace: "myns",
		EngineName:      "myengine",
		CsrDer:          csrDER,
	})
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, s.Code())
}

func TestEnroll_WrongSAUsername_PermissionDenied(t *testing.T) {
	ca := buildCA(t)
	csrDER, _ := buildCSR(t, "ignored-cn")

	kubeClient := fake.NewSimpleClientset()
	// Authenticated as a different SA (different engine name).
	kubeClient.Fake.PrependReactor("create", "tokenreviews",
		tokenReviewReactor("system:serviceaccount:myns:other-engine"),
	)

	crClient := buildFakeCRClient(engineCR("myns", "myengine")).Build()

	srv := &grpcserver.Server{
		Store:      rulestore.NewStore(),
		Logger:     logr.Discard(),
		CA:         ca,
		KubeClient: kubeClient,
		CRClient:   crClient,
	}

	client, cancel := setupEnrollServer(t, srv)
	defer cancel()

	_, err := client.Enroll(context.Background(), &wafv1pb.EnrollRequest{
		SaToken:         "mismatched-token",
		EngineNamespace: "myns",
		EngineName:      "myengine",
		CsrDer:          csrDER,
	})
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, s.Code())
}

func TestEnroll_EngineCRNotFound_NotFound(t *testing.T) {
	ca := buildCA(t)
	csrDER, _ := buildCSR(t, "ignored-cn")

	kubeClient := fake.NewSimpleClientset()
	kubeClient.Fake.PrependReactor("create", "tokenreviews",
		tokenReviewReactor("system:serviceaccount:myns:myengine-engine"),
	)

	// No Engine CR in the fake client.
	crClient := buildFakeCRClient().Build()

	srv := &grpcserver.Server{
		Store:      rulestore.NewStore(),
		Logger:     logr.Discard(),
		CA:         ca,
		KubeClient: kubeClient,
		CRClient:   crClient,
	}

	client, cancel := setupEnrollServer(t, srv)
	defer cancel()

	_, err := client.Enroll(context.Background(), &wafv1pb.EnrollRequest{
		SaToken:         "valid-token",
		EngineNamespace: "myns",
		EngineName:      "myengine",
		CsrDer:          csrDER,
	})
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, s.Code())
}

func TestEnroll_MalformedCSR_InvalidArgument(t *testing.T) {
	ca := buildCA(t)

	kubeClient := fake.NewSimpleClientset()
	kubeClient.Fake.PrependReactor("create", "tokenreviews",
		tokenReviewReactor("system:serviceaccount:myns:myengine-engine"),
	)

	crClient := buildFakeCRClient(engineCR("myns", "myengine")).Build()

	srv := &grpcserver.Server{
		Store:      rulestore.NewStore(),
		Logger:     logr.Discard(),
		CA:         ca,
		KubeClient: kubeClient,
		CRClient:   crClient,
	}

	client, cancel := setupEnrollServer(t, srv)
	defer cancel()

	_, err := client.Enroll(context.Background(), &wafv1pb.EnrollRequest{
		SaToken:         "valid-token",
		EngineNamespace: "myns",
		EngineName:      "myengine",
		CsrDer:          []byte("not-a-valid-csr"),
	})
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, s.Code())
}
