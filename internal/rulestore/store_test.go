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

package rulestore_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/coraza-operator/internal/rulestore"
)

func bundle(sha string) rulestore.Bundle {
	return rulestore.Bundle{
		RuleSetName: "rs-" + sha,
		SHA256:      sha,
		Compiled:    "# compiled " + sha,
		GeneratedAt: time.Now(),
	}
}

func TestPublishWithoutSubscribers_GetReturnsBundle(t *testing.T) {
	s := rulestore.NewStore()
	b := bundle("abc")

	s.Publish("ns1", "e1", b)

	got, ok := s.Get("ns1", "e1")
	require.True(t, ok)
	assert.Equal(t, "abc", got.SHA256)
}

func TestPublishIfChanged_FirstPublishReturnsTrue(t *testing.T) {
	s := rulestore.NewStore()
	changed := s.PublishIfChanged("ns1", "e1", bundle("abc"))
	assert.True(t, changed)

	got, ok := s.Get("ns1", "e1")
	require.True(t, ok)
	assert.Equal(t, "abc", got.SHA256)
}

func TestPublishIfChanged_SameSHAReturnsFalse(t *testing.T) {
	s := rulestore.NewStore()
	s.PublishIfChanged("ns1", "e1", bundle("abc"))

	changed := s.PublishIfChanged("ns1", "e1", bundle("abc"))
	assert.False(t, changed)
}

func TestPublishIfChanged_NewSHAReturnsTrue(t *testing.T) {
	s := rulestore.NewStore()
	s.PublishIfChanged("ns1", "e1", bundle("abc"))

	changed := s.PublishIfChanged("ns1", "e1", bundle("def"))
	assert.True(t, changed)

	got, _ := s.Get("ns1", "e1")
	assert.Equal(t, "def", got.SHA256)
}

func TestPublishIfChanged_DuplicateDoesNotBroadcast(t *testing.T) {
	s := rulestore.NewStore()
	s.Publish("ns1", "e1", bundle("abc"))

	ch, unsub := s.Subscribe("ns1", "e1")
	defer unsub()

	// drain initial
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("did not receive initial bundle")
	}

	// duplicate publish: no broadcast expected
	changed := s.PublishIfChanged("ns1", "e1", bundle("abc"))
	assert.False(t, changed)

	select {
	case b := <-ch:
		t.Fatalf("did not expect a broadcast for duplicate SHA, got %q", b.SHA256)
	case <-time.After(150 * time.Millisecond):
		// good: no broadcast
	}

	// new SHA: broadcast expected
	changed = s.PublishIfChanged("ns1", "e1", bundle("def"))
	assert.True(t, changed)
	select {
	case b := <-ch:
		assert.Equal(t, "def", b.SHA256)
	case <-time.After(time.Second):
		t.Fatal("expected broadcast for new SHA")
	}
}

func TestGet_NoBundle_ReturnsFalse(t *testing.T) {
	s := rulestore.NewStore()
	_, ok := s.Get("ns1", "e1")
	assert.False(t, ok)
}

func TestSubscribe_ReceivesInitialBundle(t *testing.T) {
	s := rulestore.NewStore()
	s.Publish("ns1", "e1", bundle("v1"))

	ch, unsub := s.Subscribe("ns1", "e1")
	defer unsub()

	select {
	case got := <-ch:
		assert.Equal(t, "v1", got.SHA256)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for initial bundle")
	}
}

func TestSubscribe_ReceivesSubsequentPublish(t *testing.T) {
	s := rulestore.NewStore()

	ch, unsub := s.Subscribe("ns1", "e1")
	defer unsub()

	s.Publish("ns1", "e1", bundle("v2"))

	select {
	case got := <-ch:
		assert.Equal(t, "v2", got.SHA256)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for bundle")
	}
}

func TestSubscribe_UnsubscribeDropsConsumer(t *testing.T) {
	s := rulestore.NewStore()

	ch, unsub := s.Subscribe("ns1", "e1")
	unsub() // unsubscribe immediately

	s.Publish("ns1", "e1", bundle("v3"))

	select {
	case <-ch:
		t.Fatal("expected no message after unsubscribe")
	case <-time.After(50 * time.Millisecond):
		// correct: no message received
	}
}

func TestTwoSubscribers_BothReceiveUpdate(t *testing.T) {
	s := rulestore.NewStore()

	ch1, unsub1 := s.Subscribe("ns1", "e1")
	defer unsub1()
	ch2, unsub2 := s.Subscribe("ns1", "e1")
	defer unsub2()

	s.Publish("ns1", "e1", bundle("v4"))

	for i, ch := range []<-chan rulestore.Bundle{ch1, ch2} {
		select {
		case got := <-ch:
			assert.Equal(t, "v4", got.SHA256, "subscriber %d", i+1)
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d timed out", i+1)
		}
	}
}

func TestSubscribers_DifferentEngines_NoCrossReceive(t *testing.T) {
	s := rulestore.NewStore()

	ch1, unsub1 := s.Subscribe("ns1", "e1")
	defer unsub1()
	ch2, unsub2 := s.Subscribe("ns1", "e2")
	defer unsub2()

	s.Publish("ns1", "e1", bundle("only-e1"))

	// ch1 should receive the bundle.
	select {
	case got := <-ch1:
		assert.Equal(t, "only-e1", got.SHA256)
	case <-time.After(time.Second):
		t.Fatal("e1 subscriber timed out")
	}

	// ch2 must NOT receive anything.
	select {
	case unexpected := <-ch2:
		t.Fatalf("e2 subscriber got unexpected bundle: %+v", unexpected)
	case <-time.After(50 * time.Millisecond):
		// correct
	}
}

func TestSlowConsumer_GetsLatestBundle(t *testing.T) {
	s := rulestore.NewStore()

	ch, unsub := s.Subscribe("ns1", "e1")
	defer unsub()

	// Publish 5 times rapidly without draining the channel.
	for i := 1; i <= 5; i++ {
		s.Publish("ns1", "e1", bundle(fmt.Sprintf("v%d", i)))
	}

	// Drain all messages available on the channel; collect the last one seen.
	var last rulestore.Bundle
	timeout := time.After(200 * time.Millisecond)
	for {
		select {
		case got := <-ch:
			last = got
		case <-timeout:
			goto done
		}
	}
done:
	require.NotEmpty(t, last.SHA256, "expected at least one bundle")
	assert.Equal(t, "v5", last.SHA256, "slow consumer must see the latest bundle (v5)")
}
