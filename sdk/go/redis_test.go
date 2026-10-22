package appguard

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/redis/go-redis/v9"
)

type redisCommandFunc func(context.Context, ...interface{}) *redis.Cmd

func (f redisCommandFunc) Do(ctx context.Context, args ...interface{}) *redis.Cmd {
	return f(ctx, args...)
}

var redisScope = ReplayScope{"app-a", "key-a", "AAECAwQFBgcICQoLDA0ODw"}

func assertRedisUnavailable(t *testing.T, accepted bool, err error) {
	t.Helper()
	if accepted || err == nil || err.Error() != "REPLAY_STORE_UNAVAILABLE" || errors.Unwrap(err) != nil {
		t.Fatalf("expected fixed unwrapped failure: %v %v", accepted, err)
	}
}
func TestRedisReplayKeyParity(t *testing.T) {
	key, err := RedisReplayKey(redisScope)
	if err != nil || key != "appguard:v0:replay:a01961ac0aa5b09fb924d3f4c066691b0d968cd3a041e6d76cb83c7b1c49ebf0" {
		t.Fatalf("canonical scope hash mismatch: %q %v", key, err)
	}
}
func TestRedisReplayCommandAndResponses(t *testing.T) {
	for _, tc := range []struct {
		name             string
		value            interface{}
		err              error
		accepted, failed bool
	}{
		{"new", "OK", nil, true, false}, {"duplicate", nil, redis.Nil, false, false},
		{"nil without sentinel", nil, nil, false, true}, {"wrong string", "ok", nil, false, true}, {"boolean", true, nil, false, true},
		{"bytes", []byte("OK"), nil, false, true}, {"wrapped sentinel", nil, fmt.Errorf("secret: %w", redis.Nil), false, true},
		{"backend", nil, fmt.Errorf("credential-secret: %w", context.DeadlineExceeded), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			store, err := NewRedisReplayStore(redisCommandFunc(func(ctx context.Context, args ...interface{}) *redis.Cmd {
				calls++
				key, _ := RedisReplayKey(redisScope)
				if !reflect.DeepEqual(args, []interface{}{"SET", key, "1", "NX", "EX", int64(150)}) {
					t.Fatalf("wrong atomic command %v", args)
				}
				return redis.NewCmdResult(tc.value, tc.err)
			}))
			if err != nil || calls != 0 {
				t.Fatal("constructor performed work")
			}
			accepted, err := store.Claim(context.Background(), redisScope, 250, 100)
			if tc.failed {
				assertRedisUnavailable(t, accepted, err)
			} else if accepted != tc.accepted || err != nil {
				t.Fatalf("unexpected result %v %v", accepted, err)
			}
			if calls != 1 {
				t.Fatal("claim retried")
			}
		})
	}
}
func TestRedisReplayInvalidNeverDispatches(t *testing.T) {
	calls := 0
	store, _ := NewRedisReplayStore(redisCommandFunc(func(context.Context, ...interface{}) *redis.Cmd { calls++; panic("private") }))
	for _, scope := range []ReplayScope{{}, {"bad app", "key-a", redisScope.Nonce}, {"app-a", "bad/key", redisScope.Nonce}, {"app-a", "key-a", "AAECAwQFBgcICQoLDA0ODx"}} {
		_, err := RedisReplayKey(scope)
		if err == nil {
			t.Fatal("invalid key accepted")
		}
		ok, err := store.Claim(context.Background(), scope, 101, 100)
		assertRedisUnavailable(t, ok, err)
	}
	for _, times := range [][2]int64{{100, 100}, {99, 100}, {251, 100}, {1, -1}, {maxTime + 1, maxTime}, {maxTime, maxTime - 151}} {
		ok, err := store.Claim(context.Background(), redisScope, times[0], times[1])
		assertRedisUnavailable(t, ok, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		ok, err := store.Claim(ctx, redisScope, 101, 100)
		assertRedisUnavailable(t, ok, err)
	}
	if calls != 0 {
		t.Fatal("invalid input dispatched")
	}
	for _, client := range []RedisCommandClient{nil, (*redis.Client)(nil)} {
		if _, err := NewRedisReplayStore(client); err == nil {
			t.Fatal("nil client accepted")
		}
	}
	var zero RedisReplayStore
	ok, err := zero.Claim(context.Background(), redisScope, 101, 100)
	assertRedisUnavailable(t, ok, err)
}
func TestRedisReplayCancellationAndPanicRedacted(t *testing.T) {
	for _, mode := range []string{"cancel", "panic", "nil command"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			store, _ := NewRedisReplayStore(redisCommandFunc(func(got context.Context, _ ...interface{}) *redis.Cmd {
				if got != ctx {
					t.Fatal("context replaced")
				}
				switch mode {
				case "panic":
					panic("secret")
				case "nil command":
					return nil
				default:
					cancel()
					return redis.NewCmdResult("OK", nil)
				}
			}))
			ok, err := store.Claim(ctx, redisScope, 101, 100)
			assertRedisUnavailable(t, ok, err)
		})
	}
}
