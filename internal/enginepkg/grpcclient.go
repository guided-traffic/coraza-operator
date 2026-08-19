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

package enginepkg

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
	"os"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	wafv1pb "github.com/guided-traffic/coraza-operator/proto/waf/v1"
)

// GRPCClientConfig holds the configuration for the engine-side gRPC client.
type GRPCClientConfig struct {
	// OperatorAddr is the operator gRPC service address, e.g.
	// "coraza-operator-grpc.coraza-system.svc:9443".
	OperatorAddr string
	// EngineNamespace is the Kubernetes namespace of this engine pod.
	EngineNamespace string
	// EngineName is the Kubernetes name of this engine pod.
	EngineName string
	// CertDir is the directory for persisting the enrolled client cert, key, and CA cert.
	CertDir string
	// SATokenPath is the path to the projected ServiceAccount token file.
	SATokenPath string
}

// Bundle is the engine-side view of a received config bundle.
type Bundle struct {
	RuleSetName string
	SHA256      string
	Compiled    string
}

const (
	clientCertFile = "client.crt"
	clientKeyFile  = "client.key"
	caCertFile     = "ca.crt"
)

// SubscribeConfig opens a Subscribe stream to the operator, performing mTLS
// enrollment first if no client cert is cached on disk.
//
// It runs until ctx is cancelled. On any stream error it reconnects with
// exponential backoff (initial 1s, max 30s).
func SubscribeConfig(ctx context.Context, cfg GRPCClientConfig, onBundle func(Bundle)) error {
	logger := logr.FromContextOrDiscard(ctx)

	const (
		initialBackoff = 1 * time.Second
		maxBackoff     = 30 * time.Second
	)

	backoff := initialBackoff

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		err := runSubscribeLoop(ctx, cfg, onBundle)
		if err == nil || ctx.Err() != nil {
			return nil
		}

		logger.Error(err, "gRPC stream error, reconnecting", "backoff", backoff)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// runSubscribeLoop ensures a client cert is enrolled, then subscribes once.
// Returns nil on clean context cancellation.
func runSubscribeLoop(ctx context.Context, cfg GRPCClientConfig, onBundle func(Bundle)) error {
	// Ensure we have a client cert + CA cert enrolled before subscribing.
	if err := ensureEnrolled(ctx, cfg); err != nil {
		return fmt.Errorf("enrollment: %w", err)
	}

	tlsCfg, err := buildClientTLS(cfg)
	if err != nil {
		return fmt.Errorf("build client TLS: %w", err)
	}

	return runStream(ctx, cfg, onBundle, tlsCfg)
}

// ensureEnrolled checks whether a valid client cert already exists on disk.
// If not, it performs the Enroll RPC and persists the received cert, key, and CA cert.
func ensureEnrolled(ctx context.Context, cfg GRPCClientConfig) error {
	logger := logr.FromContextOrDiscard(ctx)

	certPath := filepath.Join(cfg.CertDir, clientCertFile)
	keyPath := filepath.Join(cfg.CertDir, clientKeyFile)
	caPath := filepath.Join(cfg.CertDir, caCertFile)

	// If all three files exist, skip enrollment.
	if fileExists(certPath) && fileExists(keyPath) && fileExists(caPath) {
		return nil
	}

	logger.Info("no cached client cert; starting enrollment")

	if err := os.MkdirAll(cfg.CertDir, 0o700); err != nil {
		return fmt.Errorf("create cert dir %s: %w", cfg.CertDir, err)
	}

	// Generate a fresh ECDSA P-256 key pair for the CSR.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate enrollment key: %w", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			// CN is informational only — the operator overrides it with <ns>/<name>.
			CommonName: cfg.EngineNamespace + "/" + cfg.EngineName,
		},
	}, priv)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}

	// Read the projected SA token.
	// NOTE: the token content is never logged.
	tokenBytes, err := os.ReadFile(cfg.SATokenPath)
	if err != nil {
		return fmt.Errorf("read SA token from %s: %w", cfg.SATokenPath, err)
	}

	// Dial the operator for Enroll.
	// SECURITY NOTE: During bootstrap the engine does not yet have the CA cert,
	// so it cannot verify the operator's server cert. InsecureSkipVerify is used
	// ONLY for the Enroll RPC. After Enroll the CA cert is persisted and every
	// subsequent connection (Subscribe) verifies the server cert properly. This
	// mirrors the kubelet TLS bootstrap pattern.
	//
	// RESIDUAL RISK: the SA token is sent over this unverified channel. An
	// attacker able to MITM the engine->operator path during bootstrap reads the
	// token and can replay it to the real operator to enrol as this engine.
	// Server-side TokenReview authenticates the token, it does not protect the
	// token in transit. Closing this requires the CA bundle to be delivered to
	// the engine out of band (e.g. mounted from the operator's CA secret) so the
	// Enroll connection can be verified like any other.
	enrollTLS := &tls.Config{
		// #nosec G402 -- bootstrap-only, see the SECURITY NOTE above.
		InsecureSkipVerify: true, //nolint:gosec // bootstrap-only; see comment above
		MinVersion:         tls.VersionTLS13,
	}

	enrollConn, err := grpc.NewClient(
		cfg.OperatorAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(enrollTLS)),
	)
	if err != nil {
		return fmt.Errorf("dial operator for enroll %s: %w", cfg.OperatorAddr, err)
	}
	defer func() { _ = enrollConn.Close() }()

	enrollClient := wafv1pb.NewConfigServiceClient(enrollConn)
	resp, err := enrollClient.Enroll(ctx, &wafv1pb.EnrollRequest{
		SaToken:         string(tokenBytes),
		EngineNamespace: cfg.EngineNamespace,
		EngineName:      cfg.EngineName,
		CsrDer:          csrDER,
	})
	if err != nil {
		return fmt.Errorf("enroll RPC: %w", err)
	}

	// Marshal the private key for persistence.
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal enrollment key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Persist cert (0600), key (0600), CA cert (0644).
	// Keys must never be world-readable.
	if err := writeFile(certPath, resp.ClientCertPem, 0o600); err != nil {
		return fmt.Errorf("write client cert: %w", err)
	}
	if err := writeFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write client key: %w", err)
	}
	if err := writeFile(caPath, resp.CaCertPem, 0o644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}

	logger.Info("enrollment complete", "cert_dir", cfg.CertDir)
	return nil
}

// buildClientTLS reads the persisted cert/key/CA and builds a *tls.Config for
// the Subscribe mTLS connection. This is called only after ensureEnrolled succeeds.
func buildClientTLS(cfg GRPCClientConfig) (*tls.Config, error) {
	certPath := filepath.Join(cfg.CertDir, clientCertFile)
	keyPath := filepath.Join(cfg.CertDir, clientKeyFile)
	caPath := filepath.Join(cfg.CertDir, caCertFile)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client key pair: %w", err)
	}

	// #nosec G304 -- caPath is derived from cfg.CertDir, an operator-supplied path.
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %s: %w", caPath, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA cert from %s: no PEM block found", caPath)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// runStream dials the operator with mTLS, subscribes, and receives bundles until
// the stream ends or ctx is cancelled. Returns nil on clean context cancellation.
func runStream(ctx context.Context, cfg GRPCClientConfig, onBundle func(Bundle), tlsCfg *tls.Config) error {
	logger := logr.FromContextOrDiscard(ctx)

	var dialOpt grpc.DialOption
	if tlsCfg != nil {
		dialOpt = grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
	} else {
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	conn, err := grpc.NewClient(cfg.OperatorAddr, dialOpt)
	if err != nil {
		return fmt.Errorf("dial %s: %w", cfg.OperatorAddr, err)
	}
	defer func() { _ = conn.Close() }()

	client := wafv1pb.NewConfigServiceClient(conn)

	stream, err := client.Subscribe(ctx, &wafv1pb.SubscribeRequest{
		EngineNamespace: cfg.EngineNamespace,
		EngineName:      cfg.EngineName,
	})
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	logger.Info("connected to operator gRPC", "addr", cfg.OperatorAddr,
		"engine_namespace", cfg.EngineNamespace, "engine_name", cfg.EngineName)

	for {
		msg, recvErr := stream.Recv()
		if recvErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("recv: %w", recvErr)
		}

		onBundle(Bundle{
			RuleSetName: msg.RulesetName,
			SHA256:      msg.Sha256,
			Compiled:    msg.CompiledSeclang,
		})
	}
}

// fileExists returns true if the file at path exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// writeFile writes data to path with the given permission bits.
// It creates the file if it does not exist and truncates it if it does.
func writeFile(path string, data []byte, mode os.FileMode) error {
	// #nosec G304 -- path is derived from cfg.CertDir, an operator-supplied path.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	// The Close error is returned rather than dropped: these files hold the
	// client key and cert, and a failed flush would leave them truncated.
	return f.Close()
}
