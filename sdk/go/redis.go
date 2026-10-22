package appguard

import (
	"context"
	"crypto/sha256"
	hexencoding "encoding/hex"
	"encoding/json"

	"github.com/redis/go-redis/v9"
)

// RedisCommandClient is implemented by configured go-redis clients. The host owns
// connection lifecycle, credentials, retry policy and finite network timeouts.
// Enable ContextTimeoutEnabled to honor request deadlines. Do must not be a
// pipeline: Claim requires the completed response of one atomic command.
type RedisCommandClient interface {
	Do(context.Context, ...interface{}) *redis.Cmd
}

// RedisReplayStore shares replay claims through a caller-owned Redis client.
// Construction does no I/O. The store never closes, reconfigures or replaces the
// client, retries a claim, or falls back to local state.
type RedisReplayStore struct{ client RedisCommandClient }

func NewRedisReplayStore(client RedisCommandClient) (*RedisReplayStore, error) {
	if nilInterface(client) {
		return nil, failure("REPLAY_STORE_UNAVAILABLE")
	}
	return &RedisReplayStore{client: client}, nil
}

// RedisReplayKey returns the protocol's compact JSON scope SHA-256 namespace.
// It contains no raw scope values; hashing does not provide secrecy for guesses.
func RedisReplayKey(scope ReplayScope) (string, error) {
	if !identifierRE.MatchString(scope.AppID) || !identifierRE.MatchString(scope.KeyID) || !validNonce(scope.Nonce) {
		return "", failure("REPLAY_STORE_UNAVAILABLE")
	}
	encoded, _ := json.Marshal([3]string{scope.AppID, scope.KeyID, scope.Nonce})
	sum := sha256.Sum256(encoded)
	return "appguard:v0:replay:" + hexencoding.EncodeToString(sum[:]), nil
}

// Claim uses SET key 1 NX EX ttl with ttl in 1..150 seconds. Only Redis's exact
// OK or nil response means a new or duplicate claim. Ambiguous outcomes fail
// closed and may already have consumed the nonce; they are never undone.
func (s *RedisReplayStore) Claim(ctx context.Context, scope ReplayScope, expires, now int64) (accepted bool, err error) {
	defer func() {
		if recover() != nil {
			accepted = false
			err = failure("REPLAY_STORE_UNAVAILABLE")
		}
	}()
	if s == nil || nilInterface(s.client) || ctx == nil || ctx.Err() != nil || !validTime(now) || !validTime(expires) || now >= expires || expires-now > 150 {
		return false, failure("REPLAY_STORE_UNAVAILABLE")
	}
	key, err := RedisReplayKey(scope)
	if err != nil {
		return false, err
	}
	cmd := s.client.Do(ctx, "SET", key, "1", "NX", "EX", expires-now)
	if cmd == nil {
		return false, failure("REPLAY_STORE_UNAVAILABLE")
	}
	value, backendErr := cmd.Result()
	if ctx.Err() != nil {
		return false, failure("REPLAY_STORE_UNAVAILABLE")
	}
	if backendErr == redis.Nil && value == nil {
		return false, nil
	}
	if response, ok := value.(string); backendErr == nil && ok && response == "OK" {
		return true, nil
	}
	return false, failure("REPLAY_STORE_UNAVAILABLE")
}
