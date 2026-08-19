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

package pki_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/guided-traffic/coraza-operator/internal/pki"
)

func newFakeClient() *fake.ClientBuilder {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme)
}

func TestLoadOrCreate_CreatesNewCA(t *testing.T) {
	fc := newFakeClient().Build()
	ctx := context.Background()

	ca, err := pki.LoadOrCreate(ctx, fc, "test-ns", "coraza-operator-ca")
	require.NoError(t, err)
	require.NotNil(t, ca)

	assert.NotNil(t, ca.Cert)
	assert.NotNil(t, ca.Key)
	assert.NotEmpty(t, ca.CertPEM)
	assert.NotEmpty(t, ca.KeyPEM)
	assert.Equal(t, "coraza-operator-ca", ca.Cert.Subject.CommonName)
	assert.True(t, ca.Cert.IsCA)
}

func TestLoadOrCreate_SecondCallReturnsSameCA(t *testing.T) {
	fc := newFakeClient().Build()
	ctx := context.Background()

	ca1, err := pki.LoadOrCreate(ctx, fc, "test-ns", "coraza-operator-ca")
	require.NoError(t, err)

	ca2, err := pki.LoadOrCreate(ctx, fc, "test-ns", "coraza-operator-ca")
	require.NoError(t, err)

	// Same cert bytes — no regeneration occurred.
	assert.Equal(t, ca1.CertPEM, ca2.CertPEM, "second LoadOrCreate must return the same CA cert")
	assert.Equal(t, ca1.Cert.SerialNumber.String(), ca2.Cert.SerialNumber.String())
}

func TestIssueServerCert_VerifiesAgainstCA(t *testing.T) {
	fc := newFakeClient().Build()
	ctx := context.Background()

	ca, err := pki.LoadOrCreate(ctx, fc, "test-ns", "coraza-operator-ca")
	require.NoError(t, err)

	dnsSANs := []string{"coraza-operator-grpc.test-ns.svc", "coraza-operator-grpc.test-ns.svc.cluster.local"}
	ipSANs := []net.IP{net.ParseIP("127.0.0.1")}

	certPEM, keyPEM, err := ca.IssueServerCert(dnsSANs, ipSANs)
	require.NoError(t, err)
	require.NotEmpty(t, certPEM)
	require.NotEmpty(t, keyPEM)

	// Parse and verify the cert against the CA.
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   dnsSANs[0],
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	assert.NoError(t, err, "server cert must verify against the CA")

	// Check SANs.
	assert.Equal(t, dnsSANs, cert.DNSNames)
	assert.Len(t, cert.IPAddresses, 1)

	// Verify it forms a valid TLS key pair.
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	assert.NoError(t, err, "server cert and key must form a valid TLS key pair")
}

func TestIssueClientCert_CNParsesBack(t *testing.T) {
	fc := newFakeClient().Build()
	ctx := context.Background()

	ca, err := pki.LoadOrCreate(ctx, fc, "test-ns", "coraza-operator-ca")
	require.NoError(t, err)

	certPEM, keyPEM, err := ca.IssueClientCert("myns", "myengine")
	require.NoError(t, err)
	require.NotEmpty(t, certPEM)
	require.NotEmpty(t, keyPEM)

	// Parse the cert and check CN.
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	assert.Equal(t, "myns/myengine", cert.Subject.CommonName)

	// Verify ParseClientCN round-trip.
	ns, name, err := pki.ParseClientCN(cert.Subject.CommonName)
	require.NoError(t, err)
	assert.Equal(t, "myns", ns)
	assert.Equal(t, "myengine", name)

	// Verify cert chain against CA.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	assert.NoError(t, err, "client cert must verify against the CA")

	// Verify it forms a valid TLS key pair.
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	assert.NoError(t, err, "client cert and key must form a valid TLS key pair")
}

func TestParseClientCN(t *testing.T) {
	tests := []struct {
		name    string
		cn      string
		wantNS  string
		wantN   string
		wantErr bool
	}{
		{
			name:   "valid",
			cn:     "mynamespace/myengine",
			wantNS: "mynamespace",
			wantN:  "myengine",
		},
		{
			name:    "missing slash",
			cn:      "mynamespace",
			wantErr: true,
		},
		{
			name:    "empty namespace",
			cn:      "/myengine",
			wantErr: true,
		},
		{
			name:    "empty name",
			cn:      "mynamespace/",
			wantErr: true,
		},
		{
			name:    "empty string",
			cn:      "",
			wantErr: true,
		},
		{
			name:   "name with slash preserved",
			cn:     "ns/engine/extra",
			wantNS: "ns",
			wantN:  "engine/extra",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, name, err := pki.ParseClientCN(tt.cn)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantNS, ns)
			assert.Equal(t, tt.wantN, name)
		})
	}
}
