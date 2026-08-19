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
	"net"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/guided-traffic/coraza-operator/internal/grpcserver"
	"github.com/guided-traffic/coraza-operator/internal/rulestore"
	wafv1pb "github.com/guided-traffic/coraza-operator/proto/waf/v1"
)

const bufSize = 1 << 20 // 1 MiB

// setup starts a gRPC server backed by a real rulestore over a bufconn listener.
// Returns a connected client and a cancel func that shuts the server down.
func setup(t *testing.T) (wafv1pb.ConfigServiceClient, *rulestore.Store, context.CancelFunc) {
	t.Helper()

	store := rulestore.NewStore()
	srv := &grpcserver.Server{
		Store:  store,
		Logger: logr.Discard(),
	}

	lis := bufconn.Listen(bufSize)
	grpcSrv := grpc.NewServer()
	wafv1pb.RegisterConfigServiceServer(grpcSrv, srv)

	go func() {
		if err := grpcSrv.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			t.Logf("grpc server error: %v", err)
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
		_ = conn.Close()
		grpcSrv.GracefulStop()
		_ = lis.Close()
	}

	return wafv1pb.NewConfigServiceClient(conn), store, cancel
}

func bundle(sha string) rulestore.Bundle {
	return rulestore.Bundle{
		RuleSetName: "rs",
		SHA256:      sha,
		Compiled:    "# compiled " + sha,
		GeneratedAt: time.Now(),
	}
}

func recv(t *testing.T, stream wafv1pb.ConfigService_SubscribeClient) *wafv1pb.RuleSetBundle {
	t.Helper()
	ch := make(chan *wafv1pb.RuleSetBundle, 1)
	go func() {
		msg, _ := stream.Recv()
		ch <- msg
	}()
	select {
	case msg := <-ch:
		return msg
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bundle from gRPC stream")
		return nil
	}
}

func TestSubscribe_InvalidArgument_EmptyNamespace(t *testing.T) {
	client, _, cancel := setup(t)
	defer cancel()

	ctx := context.Background()
	stream, err := client.Subscribe(ctx, &wafv1pb.SubscribeRequest{
		EngineNamespace: "",
		EngineName:      "e1",
	})
	require.NoError(t, err)

	_, err = stream.Recv()
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, s.Code())
}

func TestSubscribe_InvalidArgument_EmptyName(t *testing.T) {
	client, _, cancel := setup(t)
	defer cancel()

	ctx := context.Background()
	stream, err := client.Subscribe(ctx, &wafv1pb.SubscribeRequest{
		EngineNamespace: "ns1",
		EngineName:      "",
	})
	require.NoError(t, err)

	_, err = stream.Recv()
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, s.Code())
}

func TestSubscribe_ReceivesPublishedBundle(t *testing.T) {
	client, store, cancel := setup(t)
	defer cancel()

	ctx := t.Context()

	stream, err := client.Subscribe(ctx, &wafv1pb.SubscribeRequest{
		EngineNamespace: "ns1",
		EngineName:      "e1",
	})
	require.NoError(t, err)

	// Publish first bundle after subscribe.
	store.Publish("ns1", "e1", bundle("sha-001"))
	msg := recv(t, stream)
	require.NotNil(t, msg)
	assert.Equal(t, "sha-001", msg.Sha256)

	// Publish second bundle.
	store.Publish("ns1", "e1", bundle("sha-002"))
	msg = recv(t, stream)
	require.NotNil(t, msg)
	assert.Equal(t, "sha-002", msg.Sha256)
}

func TestSubscribe_ReceivesInitialBundleBeforeSubscribe(t *testing.T) {
	client, store, cancel := setup(t)
	defer cancel()

	// Publish before subscribing.
	store.Publish("ns1", "e1", bundle("pre-existing"))

	ctx := t.Context()

	stream, err := client.Subscribe(ctx, &wafv1pb.SubscribeRequest{
		EngineNamespace: "ns1",
		EngineName:      "e1",
	})
	require.NoError(t, err)

	msg := recv(t, stream)
	require.NotNil(t, msg)
	assert.Equal(t, "pre-existing", msg.Sha256)
}

func TestSubscribe_CancelContext_CleanDisconnect(t *testing.T) {
	client, _, cancel := setup(t)
	defer cancel()

	ctx, ctxCancel := context.WithCancel(context.Background())

	stream, err := client.Subscribe(ctx, &wafv1pb.SubscribeRequest{
		EngineNamespace: "ns1",
		EngineName:      "e1",
	})
	require.NoError(t, err)

	// Cancel the context — server should return nil (clean disconnect).
	ctxCancel()

	// The client-side Recv should return a non-nil error (context cancelled or EOF).
	done := make(chan error, 1)
	go func() {
		_, recvErr := stream.Recv()
		done <- recvErr
	}()
	select {
	case err := <-done:
		assert.Error(t, err, "Recv should error after context cancel")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stream close after context cancel")
	}
}
