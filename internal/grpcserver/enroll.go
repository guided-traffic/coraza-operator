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

package grpcserver

import (
	"context"
	"crypto/x509"
	"fmt"

	authv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	wafv1 "github.com/guided-traffic/coraza-operator/api/v1"
	wafv1pb "github.com/guided-traffic/coraza-operator/proto/waf/v1"
)

// enrollAudience is the expected SA token audience for enrollment.
const enrollAudience = "coraza-operator"

// Enroll implements the bootstrap token enrollment flow:
//  1. Validates the SA token via TokenReview (audiences: ["coraza-operator"]).
//  2. Verifies the authenticated SA username matches the claimed engine identity.
//  3. Confirms an Engine CR exists.
//  4. Parses and verifies the CSR signature.
//  5. Signs a client cert using the CA (CN = <ns>/<name>, EKU client auth).
//  6. Returns the signed cert + CA cert PEM.
func (s *Server) Enroll(ctx context.Context, req *wafv1pb.EnrollRequest) (*wafv1pb.EnrollResponse, error) {
	if req.EngineNamespace == "" || req.EngineName == "" {
		return nil, status.Error(codes.InvalidArgument, "engine_namespace and engine_name must be non-empty")
	}
	if req.SaToken == "" {
		return nil, status.Error(codes.InvalidArgument, "sa_token must be non-empty")
	}
	if len(req.CsrDer) == 0 {
		return nil, status.Error(codes.InvalidArgument, "csr_der must be non-empty")
	}

	log := s.Logger.WithValues(
		"engine_namespace", req.EngineNamespace,
		"engine_name", req.EngineName,
	)

	// Step 1: validate SA token via TokenReview.
	// NOTE: req.SaToken is never logged — it is a credential.
	tr := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     req.SaToken,
			Audiences: []string{enrollAudience},
		},
	}

	result, err := s.KubeClient.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		log.Error(err, "TokenReview call failed")
		return nil, status.Errorf(codes.Internal, "token review failed: %v", err)
	}
	if !result.Status.Authenticated {
		log.Info("token not authenticated", "error", result.Status.Error)
		return nil, status.Error(codes.PermissionDenied, "SA token not authenticated")
	}

	// Step 2: verify the authenticated SA matches the claimed identity.
	// Expected username format: system:serviceaccount:<ns>:<sa-name>
	wantUsername := fmt.Sprintf("system:serviceaccount:%s:%s-engine", req.EngineNamespace, req.EngineName)
	if result.Status.User.Username != wantUsername {
		log.Info("SA username mismatch",
			"got", result.Status.User.Username,
			"want", wantUsername,
		)
		return nil, status.Errorf(codes.PermissionDenied,
			"SA username %q does not match expected %q",
			result.Status.User.Username, wantUsername,
		)
	}

	// Step 3: confirm the Engine CR exists.
	var engine wafv1.Engine
	if err := s.CRClient.Get(ctx, client.ObjectKey{Namespace: req.EngineNamespace, Name: req.EngineName}, &engine); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Engine CR not found")
			return nil, status.Errorf(codes.NotFound, "Engine %s/%s not found", req.EngineNamespace, req.EngineName)
		}
		return nil, status.Errorf(codes.Internal, "get Engine CR: %v", err)
	}

	// Step 4: parse and verify CSR signature.
	csr, err := x509.ParseCertificateRequest(req.CsrDer)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "CSR signature invalid: %v", err)
	}

	// Step 5: issue a client cert using the public key from the CSR.
	// The operator always sets CN = <ns>/<name> — CSR's claimed CN is ignored.
	certPEM, err := s.CA.IssueClientCertFromCSR(csr, req.EngineNamespace, req.EngineName)
	if err != nil {
		log.Error(err, "issue client cert")
		return nil, status.Errorf(codes.Internal, "issue client cert: %v", err)
	}

	log.Info("issued client cert", "cn", req.EngineNamespace+"/"+req.EngineName)

	return &wafv1pb.EnrollResponse{
		ClientCertPem: certPEM,
		CaCertPem:     s.CA.CertPEM,
	}, nil
}
