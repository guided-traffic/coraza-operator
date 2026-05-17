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

// Package pki manages the operator's self-signed CA and issues mTLS certificates
// for the gRPC server and engine clients.
package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CertAuthority holds a loaded or freshly generated self-signed CA.
// Keys are kept in memory only; they are never logged.
type CertAuthority struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	// CertPEM and KeyPEM are PEM-encoded blobs cached for convenience.
	// KeyPEM must never be logged.
	CertPEM []byte
	KeyPEM  []byte
}

// LoadOrCreate fetches the CA key material from the named Secret in namespace,
// or generates a new self-signed ECDSA P-256 CA, persists it, and returns it.
// The Secret type is kubernetes.io/tls; tls.crt = cert PEM, tls.key = key PEM.
func LoadOrCreate(ctx context.Context, c client.Client, namespace, secretName string) (*CertAuthority, error) {
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: namespace, Name: secretName}

	if err := c.Get(ctx, key, &secret); err == nil {
		// Secret exists — load the CA from it.
		return loadFromSecret(&secret)
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("get CA secret %s/%s: %w", namespace, secretName, err)
	}

	// Secret does not exist — generate a new CA.
	ca, err := generateCA()
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}

	// Persist to a Secret. Keys are stored as Secret data (etcd at rest) and
	// must only be accessible to the operator service account (RBAC restricts this).
	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       ca.CertPEM,
			corev1.TLSPrivateKeyKey: ca.KeyPEM,
		},
	}

	if err := c.Create(ctx, newSecret); err != nil {
		return nil, fmt.Errorf("create CA secret %s/%s: %w", namespace, secretName, err)
	}

	return ca, nil
}

// IssueServerCert signs a TLS server certificate valid for the given DNS SANs
// and IP SANs. Validity is 1 year.
func (ca *CertAuthority) IssueServerCert(dnsSANs []string, ipSANs []net.IP) (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate server key: %w", err)
	}

	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "coraza-operator-grpc",
		},
		DNSNames:    dnsSANs,
		IPAddresses: ipSANs,
		NotBefore:   time.Now().Add(-10 * time.Second), // small clock skew tolerance
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certPEM, err = signCert(tmpl, &priv.PublicKey, ca.Cert, ca.Key)
	if err != nil {
		return nil, nil, err
	}

	keyPEM, err = marshalPrivKey(priv)
	if err != nil {
		return nil, nil, err
	}

	return certPEM, keyPEM, nil
}

// IssueClientCert signs a client certificate with CN = "<engineNS>/<engineName>"
// using a freshly generated key pair. Validity is 90 days.
func (ca *CertAuthority) IssueClientCert(engineNS, engineName string) (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate client key: %w", err)
	}

	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: engineNS + "/" + engineName,
		},
		NotBefore:   time.Now().Add(-10 * time.Second),
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certPEM, err = signCert(tmpl, &priv.PublicKey, ca.Cert, ca.Key)
	if err != nil {
		return nil, nil, err
	}

	keyPEM, err = marshalPrivKey(priv)
	if err != nil {
		return nil, nil, err
	}

	return certPEM, keyPEM, nil
}

// IssueClientCertFromCSR signs a client certificate using the public key from
// the provided CSR. The CN is always set to "<engineNS>/<engineName>" regardless
// of what the CSR claims. Validity is 90 days.
func (ca *CertAuthority) IssueClientCertFromCSR(csr *x509.CertificateRequest, engineNS, engineName string) (certPEM []byte, err error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			// Operator always sets the CN — CSR's claimed CN is ignored.
			CommonName: engineNS + "/" + engineName,
		},
		NotBefore:   time.Now().Add(-10 * time.Second),
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("sign client cert from CSR: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

// BuildTLSConfig builds a *tls.Config for the gRPC server that:
//   - Presents the server certificate issued by this CA.
//   - Requests (but does not require) a client cert — the Subscribe interceptor
//     enforces client cert presence per-method.
//   - Verifies any presented client cert against this CA.
func (ca *CertAuthority) BuildTLSConfig(serverCertPEM, serverKeyPEM []byte) (*tls.Config, error) {
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse server key pair: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM) {
		return nil, fmt.Errorf("append CA cert to pool: no PEM block found")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		// VerifyClientCertIfGiven: if the client presents a cert, verify it
		// against ClientCAs and populate tls.ConnectionState.VerifiedChains.
		// If no cert is presented, the handshake still succeeds.
		//
		// This allows the Enroll RPC (no cert) to complete the TLS handshake
		// while Subscribe (requires a verified cert) is gated by the stream
		// interceptor which checks VerifiedChains.
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS13,
	}, nil
}

// ParseClientCN parses a CN of the form "<namespace>/<name>" and returns the
// components. Returns an error if the format is not exactly two slash-separated
// non-empty parts.
func ParseClientCN(cn string) (engineNS, engineName string, err error) {
	parts := strings.SplitN(cn, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid client cert CN %q: expected <namespace>/<name>", cn)
	}
	return parts[0], parts[1], nil
}

// generateCA creates a new self-signed ECDSA P-256 root CA.
func generateCA() (*CertAuthority, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "coraza-operator-ca"},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("self-sign CA: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &CertAuthority{
		Cert:    cert,
		Key:     priv,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// loadFromSecret parses cert and key PEM from a kubernetes.io/tls Secret.
func loadFromSecret(secret *corev1.Secret) (*CertAuthority, error) {
	certPEM := secret.Data[corev1.TLSCertKey]
	keyPEM := secret.Data[corev1.TLSPrivateKeyKey]

	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, fmt.Errorf("CA secret %s/%s is missing tls.crt or tls.key", secret.Namespace, secret.Name)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("CA secret %s/%s: tls.crt is not valid PEM", secret.Namespace, secret.Name)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert from secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("CA secret %s/%s: tls.key is not valid PEM", secret.Namespace, secret.Name)
	}

	priv, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key from secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}

	return &CertAuthority{
		Cert:    cert,
		Key:     priv,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// signCert creates and signs a certificate from tmpl using signerCert and signerKey.
// Returns the PEM-encoded certificate.
func signCert(tmpl *x509.Certificate, pub any, signerCert *x509.Certificate, signerKey *ecdsa.PrivateKey) (certPEM []byte, err error) {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, pub, signerKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

// marshalPrivKey DER-encodes an ECDSA private key and returns the PEM block.
// The result must never be logged.
func marshalPrivKey(priv *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// newSerial generates a random 128-bit serial number for certificates.
func newSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}
