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

// Package grpcserver implements the waf.v1.ConfigService gRPC server that
// streams compiled RuleSet bundles to engine pods and handles mTLS enrollment.
package grpcserver

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/guided-traffic/coraza-operator/internal/pki"
	"github.com/guided-traffic/coraza-operator/internal/rulestore"
	wafv1pb "github.com/guided-traffic/coraza-operator/proto/waf/v1"
)

// Server implements wafv1pb.ConfigServiceServer.
type Server struct {
	wafv1pb.UnimplementedConfigServiceServer

	Store      *rulestore.Store
	Logger     logr.Logger
	CA         *pki.CertAuthority // may be nil when running without mTLS (tests)
	KubeClient kubernetes.Interface
	CRClient   client.Client
}

// NewServer constructs a gRPC server with optional mTLS and returns it ready to Serve.
// tlsCfg may be nil to run without TLS (useful in unit tests via bufconn).
func NewServer(store *rulestore.Store, ca *pki.CertAuthority, kubeClient kubernetes.Interface, crClient client.Client, tlsCfg *tls.Config, logger logr.Logger) *grpc.Server {
	svc := &Server{
		Store:      store,
		Logger:     logger,
		CA:         ca,
		KubeClient: kubeClient,
		CRClient:   crClient,
	}

	opts := []grpc.ServerOption{
		// Unary interceptor: no extra enforcement needed for Enroll at this level.
		grpc.ChainUnaryInterceptor(unaryNoopInterceptor),
		// Stream interceptor: enforce verified client cert for Subscribe only.
		grpc.ChainStreamInterceptor(subscribeClientCertInterceptor),
	}

	if tlsCfg != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}

	srv := grpc.NewServer(opts...)
	wafv1pb.RegisterConfigServiceServer(srv, svc)
	return srv
}

// unaryNoopInterceptor is a passthrough unary interceptor.
// Enroll is deliberately allowed without a client cert; no gate is needed here.
func unaryNoopInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return handler(ctx, req)
}

// subscribeClientCertInterceptor is a stream interceptor that enforces a
// verified mTLS client cert for the Subscribe RPC. Enroll is exempt.
func subscribeClientCertInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if info.FullMethod == wafv1pb.ConfigService_Subscribe_FullMethodName {
		if err := requireVerifiedClientCert(ss.Context()); err != nil {
			return err
		}
	}
	return handler(srv, ss)
}

// requireVerifiedClientCert checks that the gRPC peer presented a verified
// TLS client certificate. Returns PermissionDenied if not.
func requireVerifiedClientCert(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.PermissionDenied, "no peer info in context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		// No TLS at all (e.g. insecure connection in tests without CA) — allow.
		// The subscribe handler's own CA check is the authoritative gate.
		return nil
	}
	if len(tlsInfo.State.VerifiedChains) == 0 {
		return status.Error(codes.PermissionDenied, "client certificate required for Subscribe")
	}
	return nil
}

// Subscribe streams RuleSetBundle updates for the requested engine.
// It sends the current bundle immediately if one exists, then streams
// subsequent updates until the client disconnects.
//
// The mTLS stream interceptor ensures a verified client cert is present.
// This handler additionally checks that the cert CN matches the engine identity.
func (s *Server) Subscribe(req *wafv1pb.SubscribeRequest, stream wafv1pb.ConfigService_SubscribeServer) error {
	if req.EngineNamespace == "" || req.EngineName == "" {
		return status.Error(codes.InvalidArgument, "engine_namespace and engine_name must be non-empty")
	}

	log := s.Logger.WithValues("engine_namespace", req.EngineNamespace, "engine_name", req.EngineName)

	// Verify the client cert CN matches the claimed engine identity.
	// Only enforced when CA is configured (skipped in plain-insecure test mode).
	if s.CA != nil {
		if err := s.verifyCertMatchesEngine(stream.Context(), req.EngineNamespace, req.EngineName); err != nil {
			return err
		}
	}

	log.Info("client subscribed")

	ch, unsub := s.Store.Subscribe(req.EngineNamespace, req.EngineName)
	defer unsub()

	for {
		select {
		case <-stream.Context().Done():
			log.Info("client disconnected")
			return nil

		case b := <-ch:
			pb := &wafv1pb.RuleSetBundle{
				RulesetName:     b.RuleSetName,
				Sha256:          b.SHA256,
				CompiledSeclang: b.Compiled,
				GeneratedAt:     timestamppb.New(b.GeneratedAt),
			}
			if err := stream.Send(pb); err != nil {
				return fmt.Errorf("send bundle: %w", err)
			}
			log.Info("sent bundle", "sha256", b.SHA256)
		}
	}
}

// verifyCertMatchesEngine checks that the peer's verified client cert has CN
// matching "<engineNamespace>/<engineName>".
func (s *Server) verifyCertMatchesEngine(ctx context.Context, engineNS, engineName string) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.PermissionDenied, "no peer info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		// Non-TLS connection; CA check is nil-guarded by caller.
		return nil
	}
	if len(tlsInfo.State.VerifiedChains) == 0 {
		return status.Error(codes.PermissionDenied, "no verified client certificate")
	}

	leaf := tlsInfo.State.VerifiedChains[0][0]
	ns, name, err := pki.ParseClientCN(leaf.Subject.CommonName)
	if err != nil {
		return status.Errorf(codes.PermissionDenied, "client cert CN invalid: %v", err)
	}
	if ns != engineNS || name != engineName {
		return status.Errorf(codes.PermissionDenied,
			"client cert CN %q does not match engine %s/%s",
			leaf.Subject.CommonName, engineNS, engineName,
		)
	}
	return nil
}
