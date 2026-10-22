package appguard

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func ownedRedisClient(t *testing.T) *redis.Client {
	t.Helper()
	raw := os.Getenv("APPGUARD_TEST_REDIS_URL")
	if raw == "" {
		t.Skip("APPGUARD_TEST_REDIS_URL unset; requires explicitly owned disposable loopback Redis")
	}
	options, err := redis.ParseURL(raw)
	if err != nil {
		t.Fatal("invalid disposable Redis URL")
	}
	host, _, err := net.SplitHostPort(options.Addr)
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		t.Fatal("disposable Redis tests require numeric loopback")
	}
	options.MaxRetries = -1
	options.ContextTimeoutEnabled = true
	options.DialTimeout = time.Second
	options.ReadTimeout = time.Second
	options.WriteTimeout = time.Second
	options.PoolTimeout = time.Second
	client := redis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatal("owned Redis unavailable")
	}
	return client
}
func uniqueRedisScope(t *testing.T) ReplayScope {
	t.Helper()
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		t.Fatal(err)
	}
	return ReplayScope{"go-sdk-test", "isolated", base64.RawURLEncoding.EncodeToString(bytes[:])}
}
func TestRedisLiveIndependentClientsAtomicityAndOwnership(t *testing.T) {
	first, second := ownedRedisClient(t), ownedRedisClient(t)
	scope := uniqueRedisScope(t)
	key, _ := RedisReplayKey(scope)
	t.Cleanup(func() { _ = first.Del(context.Background(), key).Err() })
	stores := make([]*RedisReplayStore, 2)
	stores[0], _ = NewRedisReplayStore(first)
	stores[1], _ = NewRedisReplayStore(second)
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ok, err := stores[i%2].Claim(context.Background(), scope, 250, 100)
			if err != nil {
				t.Error("atomic claim unavailable")
			} else if ok {
				wins.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("expected exactly one winner; got %d", wins.Load())
	}
	if value, err := second.Get(context.Background(), key).Result(); err != nil || value != "1" {
		t.Fatal("claim value mismatch")
	}
	if ttl, err := second.TTL(context.Background(), key).Result(); err != nil || ttl <= 0 || ttl > 150*time.Second {
		t.Fatal("claim TTL missing/outside contract")
	}
	// The adapter cannot close the host's client. Both remain usable after claims.
	for _, client := range []*redis.Client{first, second} {
		if err := client.Ping(context.Background()).Err(); err != nil {
			t.Fatal("host connection lost")
		}
	}
	if err := second.Close(); err != nil {
		t.Fatal("host close failed")
	}
	ok, err := stores[1].Claim(context.Background(), scope, 101, 100)
	assertRedisUnavailable(t, ok, err)
	if err := first.Ping(context.Background()).Err(); err != nil {
		t.Fatal("independent host client affected")
	}
}
func TestRedisLiveRelativeExpiry(t *testing.T) {
	client := ownedRedisClient(t)
	store, _ := NewRedisReplayStore(client)
	scope := uniqueRedisScope(t)
	key, _ := RedisReplayKey(scope)
	t.Cleanup(func() { _ = client.Del(context.Background(), key).Err() })
	if ok, err := store.Claim(context.Background(), scope, 101, 100); !ok || err != nil {
		t.Fatal("initial claim failed")
	}
	if ok, err := store.Claim(context.Background(), scope, 101, 100); ok || err != nil {
		t.Fatal("duplicate accepted")
	}
	// Synthetic now=100 demonstrates relative EX rather than absolute EXAT expiry.
	deadline := time.Now().Add(3 * time.Second)
	for client.Exists(context.Background(), key).Val() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if ok, err := store.Claim(context.Background(), scope, 101, 100); !ok || err != nil {
		t.Fatal("expired claim not reclaimed")
	}
}

func TestRedisBackendTimeoutNoPrivateCause(t *testing.T) {
	// Owned in-memory transport stalls during the maintained client's handshake.
	// No production RESP implementation, external host or Redis config mutation.
	a, b := net.Pipe()
	defer b.Close()
	client := redis.NewClient(&redis.Options{
		Dialer:     func(context.Context, string, string) (net.Conn, error) { return a, nil },
		MaxRetries: -1, ContextTimeoutEnabled: true, DialTimeout: 50 * time.Millisecond,
		ReadTimeout: 50 * time.Millisecond, WriteTimeout: 50 * time.Millisecond,
	})
	defer client.Close()
	store, _ := NewRedisReplayStore(client)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	ok, err := store.Claim(ctx, redisScope, 101, 100)
	assertRedisUnavailable(t, ok, err)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("backend timeout not bounded: %v", elapsed)
	}
}
