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

// Package rulestore provides an in-memory atomic store of compiled rule
// bundles keyed by engine identity (namespace/name), with a publish/subscribe
// mechanism for streaming updates to gRPC clients.
package rulestore

import (
	"sync"
	"time"
)

// Bundle is the publishable artifact for an engine.
type Bundle struct {
	RuleSetName string
	SHA256      string
	Compiled    string
	GeneratedAt time.Time
}

// engineKey is the composite key for engine identity.
type engineKey struct {
	ns   string
	name string
}

// subscription holds a single subscriber's channel.
type subscription struct {
	ch chan Bundle
}

// Store is the in-memory atomic store of compiled bundles keyed by engine
// identity. It supports subscribers that receive new versions as they are
// published.
//
// Atomicity invariant: subscribers either see the old bundle or the new
// bundle, never a partial mix. This is enforced by holding the write lock
// for the duration of both the map update and the fan-out.
type Store struct {
	mu          sync.RWMutex
	bundles     map[engineKey]Bundle
	subscribers map[engineKey]map[*subscription]struct{}
}

// NewStore returns an initialised Store.
func NewStore() *Store {
	return &Store{
		bundles:     make(map[engineKey]Bundle),
		subscribers: make(map[engineKey]map[*subscription]struct{}),
	}
}

// Publish atomically replaces the bundle for an engine and broadcasts it to
// all current subscribers for that engine.
//
// Slow-consumer drop pattern: if a subscriber's channel buffer is full, the
// stale message is drained first and the new bundle is then sent. This
// guarantees the consumer sees the most recent bundle without blocking the
// publisher.
func (s *Store) Publish(engineNS, engineName string, b Bundle) {
	k := engineKey{ns: engineNS, name: engineName}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.bundles[k] = b

	for sub := range s.subscribers[k] {
		sendLatest(sub.ch, b)
	}
}

// PublishIfChanged stores and fans out b only when the current bundle's SHA256
// differs from b.SHA256. Returns true if the bundle was accepted (new or
// changed), false if it was a duplicate and no broadcast happened.
// Same atomicity guarantees as Publish.
func (s *Store) PublishIfChanged(engineNS, engineName string, b Bundle) bool {
	k := engineKey{ns: engineNS, name: engineName}

	s.mu.Lock()
	defer s.mu.Unlock()

	if current, ok := s.bundles[k]; ok && current.SHA256 == b.SHA256 {
		return false
	}

	s.bundles[k] = b
	for sub := range s.subscribers[k] {
		sendLatest(sub.ch, b)
	}
	return true
}

// sendLatest sends b to ch without blocking. If the channel is full, the
// stale value is drained first so the consumer always sees the latest bundle.
func sendLatest(ch chan Bundle, b Bundle) {
	select {
	case ch <- b:
	default:
		// Drain stale value then send the new one.
		select {
		case <-ch:
		default:
		}
		ch <- b
	}
}

// Get returns the current bundle (and true) for the engine, or zero value
// (and false) if none has been published yet.
func (s *Store) Get(engineNS, engineName string) (Bundle, bool) {
	k := engineKey{ns: engineNS, name: engineName}

	s.mu.RLock()
	defer s.mu.RUnlock()

	b, ok := s.bundles[k]
	return b, ok
}

// Subscribe returns a channel that receives the current bundle (if any) as
// the first message, then every subsequent Publish for this engine. The
// channel buffer is 1; slow consumers only ever see the latest bundle.
//
// The returned unsubscribe func must always be called (typically via defer)
// to release internal resources.
func (s *Store) Subscribe(engineNS, engineName string) (<-chan Bundle, func()) {
	k := engineKey{ns: engineNS, name: engineName}
	sub := &subscription{ch: make(chan Bundle, 1)}

	s.mu.Lock()
	if s.subscribers[k] == nil {
		s.subscribers[k] = make(map[*subscription]struct{})
	}
	s.subscribers[k][sub] = struct{}{}

	// Send the current bundle immediately if one exists.
	current, hasCurrent := s.bundles[k]
	s.mu.Unlock()

	if hasCurrent {
		// Non-blocking: channel is fresh (buffer=1), so this always succeeds.
		sub.ch <- current
	}

	unsub := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.subscribers[k], sub)
		if len(s.subscribers[k]) == 0 {
			delete(s.subscribers, k)
		}
	}

	return sub.ch, unsub
}
