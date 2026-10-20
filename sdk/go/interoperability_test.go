package appguard

import (
	"context"
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestEquivalentECDSASignatureCannotBypassNonce(t *testing.T) {
	r, p, s, o := baseline(t)
	if _, err := VerifyRequest(context.Background(), r, p, s, o); err != nil {
		t.Fatal(err)
	}
	alternate := append([]byte(nil), s...)
	high := new(big.Int).Sub(elliptic.P256().Params().N, new(big.Int).SetBytes(s[32:]))
	high.FillBytes(alternate[32:])
	if _, err := VerifyRequest(context.Background(), r, p, alternate, o); code(err) != "REPLAY_DETECTED" {
		t.Fatalf("equivalent signature bypassed nonce: %v", err)
	}
}
func TestFailuresNeverClaimAndReplayScopeSeparatesKeys(t *testing.T) {
	for _, change := range []func(*Request, *Parameters, []byte, *VerifyOptions){
		func(r *Request, _ *Parameters, _ []byte, _ *VerifyOptions) { r.Body = []byte("tampered") },
		func(_ *Request, _ *Parameters, s []byte, _ *VerifyOptions) { s[0] ^= 1 },
		func(_ *Request, p *Parameters, _ []byte, _ *VerifyOptions) { p.Expires = p.Created },
		func(_ *Request, _ *Parameters, _ []byte, o *VerifyOptions) { o.Key.Revoked = true },
	} {
		r, p, s, o := baseline(t)
		calls := 0
		o.Replay = storeFunc(func(context.Context, ReplayScope, int64, int64) (bool, error) { calls++; return true, nil })
		change(&r, &p, s, &o)
		if _, err := VerifyRequest(context.Background(), r, p, s, o); err == nil || calls != 0 {
			t.Fatal("failed request claimed/verified", err, calls)
		}
	}
	store, err := NewLocalReplayStore(3)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []ReplayScope{{"app-a", "key-a", "AAECAwQFBgcICQoLDA0ODw"}, {"app-a", "key-b", "AAECAwQFBgcICQoLDA0ODw"}, {"app-b", "key-a", "AAECAwQFBgcICQoLDA0ODw"}} {
		if ok, err := store.Claim(context.Background(), scope, 120, 100); err != nil || !ok {
			t.Fatal(ok, err)
		}
	}
}
