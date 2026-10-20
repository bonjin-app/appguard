package appguard

import (
	"context"
	"reflect"
	"sync"
)

type ReplayScope struct {
	AppID string
	KeyID string
	Nonce string
}

// ReplayStore must atomically accept exactly one live claim for a scope. Errors
// and cancellation must never be treated as successful or retried with fallback.
type ReplayStore interface {
	Claim(context.Context, ReplayScope, int64, int64) (bool, error)
}

func nilInterface(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func claim(ctx context.Context, s ReplayStore, scope ReplayScope, expires, now int64) (accepted bool, err error) {
	defer func() {
		if recover() != nil {
			accepted = false
			err = failure("REPLAY_STORE_UNAVAILABLE")
		}
	}()
	return s.Claim(ctx, scope, expires, now)
}

// LocalReplayStore is bounded, volatile and process-local. It is intended only
// for development/test use; multiple workers/instances need an explicit shared store.
type LocalReplayStore struct {
	mu       sync.Mutex
	claims   map[ReplayScope]int64
	capacity int
}

func NewLocalReplayStore(capacity int) (*LocalReplayStore, error) {
	if capacity < 1 {
		return nil, failure("REPLAY_STORE_UNAVAILABLE")
	}
	return &LocalReplayStore{claims: make(map[ReplayScope]int64), capacity: capacity}, nil
}
func (s *LocalReplayStore) Claim(ctx context.Context, scope ReplayScope, expires, now int64) (bool, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !identifierRE.MatchString(scope.AppID) || !identifierRE.MatchString(scope.KeyID) || !validNonce(scope.Nonce) || !validTime(now) || !validTime(expires) || now >= expires {
		return false, failure("REPLAY_STORE_UNAVAILABLE")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || s.claims == nil || s.capacity < 1 {
		return false, failure("REPLAY_STORE_UNAVAILABLE")
	}
	for key, end := range s.claims {
		if end <= now {
			delete(s.claims, key)
		}
	}
	if _, ok := s.claims[scope]; ok {
		return false, nil
	}
	if len(s.claims) >= s.capacity {
		return false, failure("REPLAY_STORE_UNAVAILABLE")
	}
	s.claims[scope] = expires
	return true, nil
}
